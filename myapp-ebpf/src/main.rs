#![no_std]
#![no_main]

use aya_ebpf::{bindings::BPF_F_USER_STACK, macros::uprobe, maps::RingBuf, programs::ProbeContext};
use aya_log_ebpf::info;

use aya_ebpf::{macros::map, maps::HashMap, maps::StackTrace};

use myapp_common::{Kind, ProbeKind, Trace};

/// Set of alive indices and their stack trace ids.
/// ( RESET_COUNT, idx ) -> stack_id
#[map(name = "ALIVE_FRAMES")]
static ALIVE_FRAMES: HashMap<(u32, u32), i64> =
    HashMap::<(u32, u32), i64>::with_max_entries(1024 * 1024 * 20, 0);

/// for sending back to our process
#[map(name = "RING_BUF_TRACES")]
static RING_BUF_TRACES: RingBuf = RingBuf::with_byte_size(1024 * 1024, 0);

/// needed so that we can use the actual stack traces
#[map(name = "stack_traces")]
static mut STACK_TRACE: StackTrace = StackTrace::with_max_entries(1024 * 1024, 0);

#[uprobe]
pub fn myapp(ctx: ProbeContext) -> u32 {
    match try_myapp(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

static mut RESET_COUNT: u32 = 0;

fn try_myapp(ctx: ProbeContext) -> Result<u32, u32> {
    let frame_index: u32 = if let Some(value) = ctx.arg(0) {
        value
    } else {
        return Err(0);
    };

    let kind: u8 = if let Some(value) = ctx.arg(1) {
        value
    } else {
        return Err(0);
    };
    let kind: ProbeKind = kind.try_into().map_err(|_| 0_u32)?;

    let prev_stack_id = unsafe { ALIVE_FRAMES.get(&(RESET_COUNT, frame_index)) };
    let current_stack_id =
        unsafe { STACK_TRACE.get_stackid(&ctx, BPF_F_USER_STACK.into()) }.map_err(|_| 0_u32)?;

    match kind {
        ProbeKind::Init => {
            if let Some(prev_stack_id) = prev_stack_id {
                // trying to allocate id already used (!)
                collect_bad_trace(ctx, *prev_stack_id, frame_index, Kind::DoubleAlloc);
                return Err(0);
            } else {
                // normal alloc
                _ = ALIVE_FRAMES.insert(
                    &(unsafe { RESET_COUNT }, frame_index),
                    &current_stack_id,
                    0,
                );
            }
        }
        ProbeKind::Deinit => {
            if let Some(_) = prev_stack_id {
                // normal free
                _ = ALIVE_FRAMES.remove(&(unsafe { RESET_COUNT }, frame_index));
                return Err(0);
            } else {
                // freeing nothing (!)
                collect_bad_trace(ctx, current_stack_id, frame_index, Kind::DoubleFree);
            }
        }
        ProbeKind::ResetAll => {
            info!(&ctx, "reset");
            unsafe { RESET_COUNT += 1 };
        }
    }

    Ok(0)
}

fn collect_bad_trace(ctx: ProbeContext, stackid: i64, frame_id: u32, kind: Kind) {
    _ = ctx;

    if let Some(mut v) = RING_BUF_TRACES.reserve::<Trace>(0) {
        let t = Trace {
            frame_id,
            stackid,
            kind,
        };
        v.write(t);
        v.submit(0);
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
