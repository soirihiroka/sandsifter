#[repr(C, packed)]
#[derive(Debug, Default, Copy, Clone)]
pub struct InjectorResults {
    pub disas_length: i32,
    pub disas_known: i32,
    pub raw_insn: [u8; 16],
    pub valid: u32,
    pub length: u32,
    pub signum: u32,
    pub sicode: u32,
    pub siaddr: u32,
}

impl InjectorResults {
    pub const BYTE_LEN: usize = core::mem::size_of::<Self>();
}
