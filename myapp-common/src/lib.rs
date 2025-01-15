#![no_std]

#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct Trace {
    pub frame_id: u32,
    pub stackid: i64,
    pub kind: Kind,
}

#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub enum Kind {
    DoubleAlloc,
    DoubleFree,
}

#[derive(Debug, Copy, Clone)]
#[repr(u8)]
pub enum ProbeKind {
    Init = 0,
    Deinit = 1,
    ResetAll = 2,
}

impl TryFrom<u8> for ProbeKind {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(ProbeKind::Init),
            1 => Ok(ProbeKind::Deinit),
            2 => Ok(ProbeKind::ResetAll),
            _ => Err(()),
        }
    }
}
