pub fn arch_mode() -> capstone::arch::x86::ArchMode {
    if cfg!(target_arch = "x86_64") {
        capstone::arch::x86::ArchMode::Mode64
    } else {
        capstone::arch::x86::ArchMode::Mode32
    }
}
