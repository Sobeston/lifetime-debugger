use anyhow::anyhow;
use aya::{
    maps::{MapData, RingBuf, StackTraceMap},
    programs::UProbe,
};
use clap::Parser;
use std::sync::Arc;
use tokio::sync::Mutex;

#[rustfmt::skip]
use log::{debug, warn};
use myapp_common::Trace;
use tokio::signal;

#[derive(Debug, Parser)]
#[command(arg_required_else_help = true)]
struct Opt {
    #[clap(short, long)]
    pid: Option<i32>,
    #[clap(long)]
    binary_path: String,
    #[clap(long)]
    lifetime_probe_symbol: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();
    let Opt {
        pid,
        binary_path,
        lifetime_probe_symbol,
    } = opt;

    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/myapp"
    )))?;
    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    let program: &mut UProbe = ebpf.program_mut("myapp").unwrap().try_into()?;
    program.load()?;

    program.attach(Some(&lifetime_probe_symbol), 0, &binary_path, pid)?;

    let stack_traces = StackTraceMap::try_from(
        ebpf.take_map("stack_traces")
            .ok_or(anyhow!("stack_traces not found"))?,
    )?;

    let ebpf = Arc::new(Mutex::new(ebpf));

    let binary_path = binary_path.clone();
    tokio::task::spawn(async move {
        let mut ebpf = ebpf.lock().await;

        let loader = addr2line::Loader::new(binary_path).unwrap();

        let ring_buf = RingBuf::try_from(ebpf.map_mut("RING_BUF_TRACES").unwrap()).unwrap();
        use tokio::io::unix::AsyncFd;
        let mut fd = AsyncFd::new(ring_buf).unwrap();

        while let Ok(mut guard) = fd.readable_mut().await {
            match guard.try_io(|inner| {
                let ring_buf = inner.get_mut();
                while let Some(item) = ring_buf.next() {
                    let trace: Trace = unsafe { *item.as_ptr().cast() };
                    println!("{trace:?}");
                    print_trace(trace, &stack_traces, &loader);
                }
                Ok(())
            }) {
                Ok(_) => {
                    guard.clear_ready();
                    continue;
                }
                Err(_would_block) => continue,
            }
        }
    });

    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    println!("Exiting...");

    Ok(())
}

fn print_trace(trace: Trace, stack_traces: &StackTraceMap<MapData>, loader: &addr2line::Loader) {
    let stack_trace = stack_traces.get(&(trace.stackid as u32), 0).ok();

    if let Some(stack_trace) = stack_trace {
        for (i, frame) in stack_trace.frames().iter().enumerate() {
            let location = loader.find_location(frame.ip).unwrap();

            let middle = if let Some(location) = location {
                let file = location.file.unwrap_or("unknown");
                let line = location
                    .line
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "unknown".to_string());

                format!("{file}:{line}")
            } else {
                format!("(unknown) 0x{:X}", frame.ip)
            };

            let mut frames = loader.find_frames(frame.ip).unwrap();

            let fn_name = {
                let fn_name = frames
                    .next()
                    .unwrap()
                    .and_then(|frame| frame.function.map(|func| func.name));

                if let Some(fn_name) = fn_name {
                    fn_name.to_string().unwrap()
                } else {
                    "unknown"
                }
            };

            println!("{i:>2}:    {middle: <80} {fn_name: <50}");
        }
    }
}
