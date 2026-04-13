#![allow(unsafe_op_in_unsafe_fn, static_mut_refs)]

#[cfg(not(target_arch = "x86_64"))]
compile_error!("injector_rs currently supports x86_64 only");

use std::ffi::c_void;
use std::fmt::Write as _;
use std::mem::{MaybeUninit, size_of};
use std::ptr;
use std::sync::OnceLock;

use capstone_sys as cs_sys;
use getopts::Options;

use crate::injector_abi::InjectorResults;

mod asm {
    use std::arch::global_asm;

    global_asm!(
        r#"
        .global inject_exec
        .global preamble_start
        .global preamble_end

        preamble_start:
            pushfq
            orq $0x100, (%rsp)
            popfq
        preamble_end:

        inject_exec:
            mov {inject_state}+0(%rip), %rax
            mov {inject_state}+8(%rip), %rbx
            mov {inject_state}+16(%rip), %rcx
            mov {inject_state}+24(%rip), %rdx
            mov {inject_state}+32(%rip), %rsi
            mov {inject_state}+40(%rip), %rdi
            mov {inject_state}+48(%rip), %r8
            mov {inject_state}+56(%rip), %r9
            mov {inject_state}+64(%rip), %r10
            mov {inject_state}+72(%rip), %r11
            mov {inject_state}+80(%rip), %r12
            mov {inject_state}+88(%rip), %r13
            mov {inject_state}+96(%rip), %r14
            mov {inject_state}+104(%rip), %r15
            mov {inject_state}+112(%rip), %rbp
            lea {dummy_stack}+2048(%rip), %rsp
            jmp *{packet}(%rip)
        "#,
        inject_state = sym super::INJECT_STATE,
        dummy_stack = sym super::DUMMY_STACK,
        packet = sym super::PACKET,
        options(att_syntax)
    );

    unsafe extern "C" {
        pub fn inject_exec();
        pub static preamble_start: u8;
        pub static preamble_end: u8;
    }
}

const USE_CAPSTONE: bool = true;
const UD2_SIZE: i32 = 2;
const PAGE_SIZE: usize = 4096;
const TF: i64 = 0x100;
const USE_TF: bool = true;
const MAX_INSN_LENGTH: usize = 15;
const JMP_LENGTH: i32 = 16;
const RAW_REPORT_INSN_BYTES: usize = 16;
const TICK_MASK: u64 = 0xffff;
const SIG_STACK_SIZE: usize = 65536;

#[derive(Copy, Clone, Eq, PartialEq)]
enum SearchMode {
    Brute,
    Rand,
    Tunnel,
    Driven,
}

#[derive(Copy, Clone, Eq, PartialEq)]
enum OutputMode {
    Text,
    Raw,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct Config {
    allow_dup_prefix: bool,
    max_prefix: i32,
    brute_depth: i32,
    seed: libc::c_long,
    range_bytes: i32,
    show_tick: bool,
    jobs: i32,
    force_core: bool,
    core: i32,
    enable_null_access: bool,
    nx_support: bool,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct State64 {
    rax: u64,
    rbx: u64,
    rcx: u64,
    rdx: u64,
    rsi: u64,
    rdi: u64,
    r8: u64,
    r9: u64,
    r10: u64,
    r11: u64,
    r12: u64,
    r13: u64,
    r14: u64,
    r15: u64,
    rbp: u64,
    rsp: u64,
}

#[repr(C, align(4096))]
struct DummyStack {
    dummy_stack_hi: [u64; 256],
    dummy_stack_lo: [u64; 256],
}

#[repr(C)]
#[derive(Copy, Clone)]
struct Insn {
    bytes: [u8; MAX_INSN_LENGTH],
    len: i32,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct Inj {
    i: Insn,
    index: i32,
    last_len: i32,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct Range {
    start: Insn,
    end: Insn,
    started: bool,
}

#[derive(Copy, Clone)]
struct IgnoreOpcode {
    opcode: &'static [u8],
    reason: &'static str,
}

#[derive(Copy, Clone)]
struct IgnorePrefix {
    prefix: &'static [u8],
    reason: &'static str,
}

const DEFAULT_CONFIG: Config = Config {
    allow_dup_prefix: false,
    max_prefix: 0,
    brute_depth: 4,
    seed: 0,
    range_bytes: 0,
    show_tick: false,
    jobs: 1,
    force_core: false,
    core: 0,
    enable_null_access: false,
    nx_support: true,
};

const ZERO_INSN: Insn = Insn {
    bytes: [0; MAX_INSN_LENGTH],
    len: 0,
};

const TOTAL_RANGE_DEFAULT: Range = Range {
    start: Insn {
        bytes: [0x00; MAX_INSN_LENGTH],
        len: 0,
    },
    end: Insn {
        bytes: [0xff; MAX_INSN_LENGTH],
        len: 0,
    },
    started: false,
};

const OPCODE_BLACKLIST: &[IgnoreOpcode] = &[
    IgnoreOpcode {
        opcode: b"\x0f\x34",
        reason: "sysenter",
    },
    IgnoreOpcode {
        opcode: b"\x0f\xa1",
        reason: "pop fs",
    },
    IgnoreOpcode {
        opcode: b"\x0f\xa9",
        reason: "pop gs",
    },
    IgnoreOpcode {
        opcode: b"\x8e",
        reason: "mov seg",
    },
    IgnoreOpcode {
        opcode: b"\xc8",
        reason: "enter",
    },
    IgnoreOpcode {
        opcode: b"\x0f\xb2",
        reason: "lss",
    },
    IgnoreOpcode {
        opcode: b"\x0f\xb4",
        reason: "lfs",
    },
    IgnoreOpcode {
        opcode: b"\x0f\xb5",
        reason: "lgs",
    },
    IgnoreOpcode {
        opcode: b"\x63",
        reason: "movsxd",
    },
    IgnoreOpcode {
        opcode: b"\xbc",
        reason: "mov sp",
    },
    IgnoreOpcode {
        opcode: b"\xd1\xec",
        reason: "shr sp, 1",
    },
    IgnoreOpcode {
        opcode: b"\xd1\xe4",
        reason: "shl sp, 1",
    },
    IgnoreOpcode {
        opcode: b"\xd1\xfc",
        reason: "sar sp, 1",
    },
    IgnoreOpcode {
        opcode: b"\xd1\xdc",
        reason: "rcr sp, 1",
    },
    IgnoreOpcode {
        opcode: b"\xd1\xd4",
        reason: "rcl sp, 1",
    },
    IgnoreOpcode {
        opcode: b"\xd1\xcc",
        reason: "ror sp, 1",
    },
    IgnoreOpcode {
        opcode: b"\xd1\xc4",
        reason: "rol sp, 1",
    },
    IgnoreOpcode {
        opcode: b"\x8d\xa2",
        reason: "lea sp",
    },
    IgnoreOpcode {
        opcode: b"\xc7\xf8",
        reason: "xbegin",
    },
    IgnoreOpcode {
        opcode: b"\xcd\x80",
        reason: "int 0x80",
    },
    IgnoreOpcode {
        opcode: b"\x0f\x05",
        reason: "syscall",
    },
    IgnoreOpcode {
        opcode: b"\x0f\xb9",
        reason: "ud2",
    },
    IgnoreOpcode {
        opcode: b"\xc2",
        reason: "ret 0x0000",
    },
];

const PREFIX_BLACKLIST: &[IgnorePrefix] = &[IgnorePrefix {
    prefix: b"\x64",
    reason: "fs",
}];

static mut CONFIG: Config = DEFAULT_CONFIG;
static mut MODE: SearchMode = SearchMode::Tunnel;
static mut OUTPUT: OutputMode = OutputMode::Text;
static mut PACKET_BUFFER: *mut u8 = ptr::null_mut();
static mut PACKET: *mut u8 = ptr::null_mut();
static mut DUMMY_STACK: DummyStack = DummyStack {
    dummy_stack_hi: [0; 256],
    dummy_stack_lo: [0; 256],
};
static mut INJECT_STATE: State64 = State64 {
    rax: 0,
    rbx: 0,
    rcx: 0,
    rdx: 0,
    rsi: 0,
    rdi: 0,
    r8: 0,
    r9: 0,
    r10: 0,
    r11: 0,
    r12: 0,
    r13: 0,
    r14: 0,
    r15: 0,
    rbp: 0,
    rsp: 0,
};
static mut INJ: Inj = Inj {
    i: ZERO_INSN,
    index: -1,
    last_len: -1,
};
static mut RESULT: InjectorResults = InjectorResults {
    disas_length: 0,
    disas_known: 0,
    raw_insn: [0; RAW_REPORT_INSN_BYTES],
    valid: 0,
    length: 0,
    signum: 0,
    sicode: 0,
    siaddr: 0,
};
static mut FAULT_CONTEXT: MaybeUninit<libc::mcontext_t> = MaybeUninit::uninit();
static mut RESUME_IP: usize = 0;
static mut EXPECTED_LENGTH: i32 = 0;
static mut RANGE_MARKER: *mut Insn = ptr::null_mut();
static mut SEARCH_RANGE: Range = Range {
    start: ZERO_INSN,
    end: ZERO_INSN,
    started: false,
};
static mut TOTAL_RANGE: Range = TOTAL_RANGE_DEFAULT;
static mut POOL_MUTEX: *mut libc::pthread_mutex_t = ptr::null_mut();
static mut OUTPUT_MUTEX: *mut libc::pthread_mutex_t = ptr::null_mut();
static mut ALT_STACK: [u8; SIG_STACK_SIZE] = [0; SIG_STACK_SIZE];
static mut USER_BLACKLISTS: Vec<Vec<u8>> = Vec::new();
static mut SYSTEM_CAPSTONE_HANDLE: cs_sys::csh = 0;
static mut SYSTEM_CAPSTONE_INSN: *mut cs_sys::cs_insn = ptr::null_mut();
static mut HAVE_STATE: bool = false;
static mut TICK_COUNTER: u64 = 0;

struct SystemCapstoneApi {
    _handle: *mut c_void,
    cs_open: unsafe extern "C" fn(
        cs_sys::cs_arch,
        cs_sys::cs_mode,
        *mut cs_sys::csh,
    ) -> cs_sys::cs_err::Type,
    cs_close: unsafe extern "C" fn(*mut cs_sys::csh) -> cs_sys::cs_err::Type,
    cs_malloc: unsafe extern "C" fn(cs_sys::csh) -> *mut cs_sys::cs_insn,
    cs_free: unsafe extern "C" fn(*mut cs_sys::cs_insn, usize),
    cs_disasm_iter: unsafe extern "C" fn(
        cs_sys::csh,
        *mut *const u8,
        *mut usize,
        *mut u64,
        *mut cs_sys::cs_insn,
    ) -> bool,
}

unsafe impl Send for SystemCapstoneApi {}
unsafe impl Sync for SystemCapstoneApi {}

static SYSTEM_CAPSTONE_API: OnceLock<SystemCapstoneApi> = OnceLock::new();

pub fn run() -> Result<(), Box<dyn std::error::Error>> {
    unsafe { run_impl() }.map_err(|e| e.into())
}

unsafe fn load_system_capstone_api() -> Result<&'static SystemCapstoneApi, String> {
    fn symbol_name(name: &str) -> Vec<u8> {
        let mut bytes = name.as_bytes().to_vec();
        bytes.push(0);
        bytes
    }

    unsafe fn load_symbol<T: Copy>(handle: *mut c_void, name: &str) -> Result<T, String> {
        let name = symbol_name(name);
        let ptr = libc::dlsym(handle, name.as_ptr().cast());
        if ptr.is_null() {
            return Err(format!("dlsym failed for {name:?}"));
        }
        Ok(std::mem::transmute_copy(&ptr))
    }

    if let Some(api) = SYSTEM_CAPSTONE_API.get() {
        return Ok(api);
    }

    let api: SystemCapstoneApi = unsafe {
        let lib_name = b"/lib/x86_64-linux-gnu/libcapstone.so.4\0";
        let handle = libc::dlopen(lib_name.as_ptr().cast(), libc::RTLD_NOW);
        if handle.is_null() {
            return Err("dlopen(libcapstone.so.4) failed".to_string());
        }
        SystemCapstoneApi {
            _handle: handle,
            cs_open: load_symbol(handle, "cs_open")?,
            cs_close: load_symbol(handle, "cs_close")?,
            cs_malloc: load_symbol(handle, "cs_malloc")?,
            cs_free: load_symbol(handle, "cs_free")?,
            cs_disasm_iter: load_symbol(handle, "cs_disasm_iter")?,
        }
    };

    let _ = SYSTEM_CAPSTONE_API.set(api);
    SYSTEM_CAPSTONE_API
        .get()
        .ok_or_else(|| "failed to initialize system capstone api".to_string())
}

unsafe fn init_system_capstone() -> Result<(), String> {
    let api = load_system_capstone_api()?;
    let err = (api.cs_open)(
        cs_sys::cs_arch::CS_ARCH_X86,
        cs_sys::cs_mode::CS_MODE_64,
        ptr::addr_of_mut!(SYSTEM_CAPSTONE_HANDLE),
    );
    if err != cs_sys::cs_err::CS_ERR_OK {
        return Err(format!("system cs_open failed: {err}"));
    }
    SYSTEM_CAPSTONE_INSN = (api.cs_malloc)(SYSTEM_CAPSTONE_HANDLE);
    if SYSTEM_CAPSTONE_INSN.is_null() {
        return Err("system cs_malloc failed".to_string());
    }
    Ok(())
}

unsafe fn shutdown_system_capstone() {
    if let Some(api) = SYSTEM_CAPSTONE_API.get() {
        if !SYSTEM_CAPSTONE_INSN.is_null() {
            (api.cs_free)(SYSTEM_CAPSTONE_INSN, 1);
            SYSTEM_CAPSTONE_INSN = ptr::null_mut();
        }
        if SYSTEM_CAPSTONE_HANDLE != 0 {
            let mut handle = SYSTEM_CAPSTONE_HANDLE;
            (api.cs_close)(ptr::addr_of_mut!(handle));
            SYSTEM_CAPSTONE_HANDLE = 0;
        }
    }
}

unsafe fn run_impl() -> Result<(), String> {
    init_shared_mutexes()?;
    init_config()?;
    pin_core()?;

    libc::srand(CONFIG.seed as u32);

    let packet_buffer_unaligned = libc::malloc(PAGE_SIZE * 3) as *mut u8;
    if packet_buffer_unaligned.is_null() {
        return Err("malloc failed".to_string());
    }

    PACKET_BUFFER =
        (((packet_buffer_unaligned as usize) + (PAGE_SIZE - 1)) & !(PAGE_SIZE - 1)) as *mut u8;

    if libc::mprotect(
        PACKET_BUFFER.cast(),
        PAGE_SIZE,
        libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
    ) != 0
    {
        return Err("mprotect(packet_buffer) failed".to_string());
    }

    if CONFIG.nx_support {
        if libc::mprotect(
            PACKET_BUFFER.add(PAGE_SIZE).cast(),
            PAGE_SIZE,
            libc::PROT_READ | libc::PROT_WRITE,
        ) != 0
        {
            return Err("mprotect(next page RW) failed".to_string());
        }
    } else if libc::mprotect(
        PACKET_BUFFER.add(PAGE_SIZE).cast(),
        PAGE_SIZE,
        libc::PROT_NONE,
    ) != 0
    {
        return Err("mprotect(next page NONE) failed".to_string());
    }

    if USE_CAPSTONE {
        init_system_capstone()?;
    }

    let mut null_p: *mut c_void = ptr::null_mut();
    if CONFIG.enable_null_access {
        null_p = libc::mmap(
            ptr::null_mut(),
            PAGE_SIZE,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_FIXED | libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        );
        if null_p == libc::MAP_FAILED {
            return Err("null access requires running as root".to_string());
        }
    }

    let ss = libc::stack_t {
        ss_sp: ALT_STACK.as_mut_ptr().cast(),
        ss_flags: 0,
        ss_size: SIG_STACK_SIZE,
    };
    if libc::sigaltstack(&ss, ptr::null_mut()) != 0 {
        return Err("sigaltstack failed".to_string());
    }

    initialize_ranges()?;

    let mut pid = 1;
    for _ in 0..CONFIG.jobs.saturating_sub(1) {
        pid = libc::fork();
        if pid < 0 {
            return Err("fork failed".to_string());
        }
        if pid == 0 {
            break;
        }
    }

    while move_next_range() {
        while move_next_instruction()? {
            pretext();
            let mut i = 1;
            while i <= MAX_INSN_LENGTH {
                inject(i as i32);
                if RESULT.siaddr != PACKET_BUFFER.add(PAGE_SIZE) as usize as u32 {
                    break;
                }
                i += 1;
            }
            RESULT.length = i as u32;
            give_result_stdout()?;
            tick();
        }
    }

    if USE_CAPSTONE {
        shutdown_system_capstone();
    }

    if CONFIG.enable_null_access {
        libc::munmap(null_p, PAGE_SIZE);
    }

    libc::free(packet_buffer_unaligned.cast());

    if pid != 0 {
        for _ in 0..CONFIG.jobs.saturating_sub(1) {
            libc::wait(ptr::null_mut());
        }
        free_ranges();
        libc::pthread_mutex_destroy(POOL_MUTEX);
        libc::pthread_mutex_destroy(OUTPUT_MUTEX);
    }

    Ok(())
}

unsafe fn init_shared_mutexes() -> Result<(), String> {
    let mut mutex_attr = MaybeUninit::<libc::pthread_mutexattr_t>::uninit();
    if libc::pthread_mutexattr_init(mutex_attr.as_mut_ptr()) != 0 {
        return Err("pthread_mutexattr_init failed".to_string());
    }
    let mut mutex_attr = mutex_attr.assume_init();
    if libc::pthread_mutexattr_setpshared(&mut mutex_attr, libc::PTHREAD_PROCESS_SHARED) != 0 {
        return Err("pthread_mutexattr_setpshared failed".to_string());
    }

    POOL_MUTEX = libc::mmap(
        ptr::null_mut(),
        size_of::<libc::pthread_mutex_t>(),
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_SHARED | libc::MAP_ANONYMOUS,
        -1,
        0,
    ) as *mut libc::pthread_mutex_t;
    OUTPUT_MUTEX = libc::mmap(
        ptr::null_mut(),
        size_of::<libc::pthread_mutex_t>(),
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_SHARED | libc::MAP_ANONYMOUS,
        -1,
        0,
    ) as *mut libc::pthread_mutex_t;

    if POOL_MUTEX.cast::<c_void>() == libc::MAP_FAILED
        || OUTPUT_MUTEX.cast::<c_void>() == libc::MAP_FAILED
    {
        return Err("mmap mutex failed".to_string());
    }

    if libc::pthread_mutex_init(POOL_MUTEX, &mutex_attr) != 0 {
        return Err("pthread_mutex_init(pool) failed".to_string());
    }
    if libc::pthread_mutex_init(OUTPUT_MUTEX, &mutex_attr) != 0 {
        return Err("pthread_mutex_init(output) failed".to_string());
    }

    Ok(())
}

unsafe fn init_config() -> Result<(), String> {
    let args: Vec<String> = std::env::args().collect();
    let mut opts = Options::new();
    opts.optflag("b", "", "");
    opts.optflag("r", "", "");
    opts.optflag("t", "", "");
    opts.optflag("d", "", "");
    opts.optflag("R", "", "");
    opts.optflag("T", "", "");
    opts.optflag("x", "", "");
    opts.optflag("0", "", "");
    opts.optflag("D", "", "");
    opts.optflag("N", "", "");
    opts.optflag("?", "", "");
    opts.optopt("s", "", "", "");
    opts.optopt("B", "", "", "");
    opts.optopt("P", "", "", "");
    opts.optopt("i", "", "", "");
    opts.optopt("e", "", "", "");
    opts.optopt("c", "", "", "");
    opts.optopt("X", "", "", "");
    opts.optopt("j", "", "", "");
    opts.optopt("l", "", "", "");

    let matches = opts.parse(&args[1..]).map_err(|e| e.to_string())?;
    if !matches.free.is_empty() {
        usage();
        return Err("unexpected free arguments".to_string());
    }
    if matches.opt_present("?") {
        help();
        return Err(String::new());
    }

    if matches.opt_present("b") {
        MODE = SearchMode::Brute;
    }
    if matches.opt_present("r") {
        MODE = SearchMode::Rand;
    }
    if matches.opt_present("t") {
        MODE = SearchMode::Tunnel;
    }
    if matches.opt_present("d") {
        MODE = SearchMode::Driven;
    }
    if matches.opt_present("R") {
        OUTPUT = OutputMode::Raw;
    }
    if matches.opt_present("T") {
        OUTPUT = OutputMode::Text;
    }
    if matches.opt_present("x") {
        CONFIG.show_tick = true;
    }
    if matches.opt_present("0") {
        CONFIG.enable_null_access = true;
    }
    if matches.opt_present("D") {
        CONFIG.allow_dup_prefix = true;
    }
    if matches.opt_present("N") {
        CONFIG.nx_support = false;
    }
    if let Some(seed) = matches.opt_str("s") {
        CONFIG.seed = seed
            .parse::<libc::c_long>()
            .map_err(|_| "bad seed".to_string())?;
    } else {
        CONFIG.seed = libc::time(ptr::null_mut()) as libc::c_long;
    }
    if let Some(max_prefix) = matches.opt_str("P") {
        CONFIG.max_prefix = max_prefix
            .parse::<i32>()
            .map_err(|_| "bad max_prefix".to_string())?;
    }
    if let Some(brute_depth) = matches.opt_str("B") {
        CONFIG.brute_depth = brute_depth
            .parse::<i32>()
            .map_err(|_| "bad brute_depth".to_string())?;
    }
    if let Some(start) = matches.opt_str("i") {
        parse_insn_hex(&start, &mut TOTAL_RANGE.start);
    }
    if let Some(end) = matches.opt_str("e") {
        parse_insn_hex(&end, &mut TOTAL_RANGE.end);
    }
    if let Some(core) = matches.opt_str("c") {
        CONFIG.force_core = true;
        CONFIG.core = core.parse::<i32>().map_err(|_| "bad core".to_string())?;
    }
    for entry in matches.opt_strs("X") {
        USER_BLACKLISTS.push(parse_opcode_hex(&entry));
    }
    if let Some(jobs) = matches.opt_str("j") {
        CONFIG.jobs = jobs.parse::<i32>().map_err(|_| "bad jobs".to_string())?;
    }
    if let Some(range_bytes) = matches.opt_str("l") {
        CONFIG.range_bytes = range_bytes
            .parse::<i32>()
            .map_err(|_| "bad range_bytes".to_string())?;
    }

    Ok(())
}

unsafe fn parse_insn_hex(hex: &str, insn: &mut Insn) {
    let bytes = hex.as_bytes();
    let mut i = 0usize;
    while i < MAX_INSN_LENGTH && i * 2 + 1 < bytes.len() {
        if let Ok(s) = std::str::from_utf8(&bytes[i * 2..i * 2 + 2]) {
            if let Ok(v) = u8::from_str_radix(s, 16) {
                insn.bytes[i] = v;
            }
        }
        i += 1;
    }
    insn.len = i as i32;
    while i < MAX_INSN_LENGTH {
        insn.bytes[i] = 0;
        i += 1;
    }
}

unsafe fn parse_opcode_hex(hex: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(hex.len() / 2);
    let bytes = hex.as_bytes();
    let mut i = 0usize;
    while i * 2 + 1 < bytes.len() {
        let s = std::str::from_utf8(&bytes[i * 2..i * 2 + 2]).unwrap_or("00");
        let v = u8::from_str_radix(s, 16).unwrap_or(0);
        out.push(v);
        i += 1;
    }
    out
}

unsafe fn pin_core() -> Result<(), String> {
    if !CONFIG.force_core {
        return Ok(());
    }

    let mut mask = [0u8; 128];
    let core = CONFIG.core.max(0) as usize;
    if core / 8 < mask.len() {
        mask[core / 8] |= 1 << (core % 8);
    }
    if libc::sched_setaffinity(0, mask.len(), mask.as_ptr().cast()) != 0 {
        return Err("error: failed to set cpu".to_string());
    }
    Ok(())
}

unsafe fn initialize_ranges() -> Result<(), String> {
    if RANGE_MARKER.is_null() {
        RANGE_MARKER = libc::mmap(
            ptr::null_mut(),
            size_of::<Insn>(),
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED | libc::MAP_ANONYMOUS,
            -1,
            0,
        ) as *mut Insn;
        if RANGE_MARKER.cast::<c_void>() == libc::MAP_FAILED {
            return Err("range marker mmap failed".to_string());
        }
        *RANGE_MARKER = TOTAL_RANGE.start;
    }
    Ok(())
}

unsafe fn free_ranges() {
    if !RANGE_MARKER.is_null() {
        libc::munmap(RANGE_MARKER.cast(), size_of::<Insn>());
    }
}

unsafe fn zero_insn_end(insn: &mut Insn, marker: usize) {
    let mut i = marker;
    while i < MAX_INSN_LENGTH {
        insn.bytes[i] = 0;
        i += 1;
    }
}

unsafe fn increment_range(insn: &mut Insn, marker: usize) -> bool {
    let mut i = marker as isize - 1;
    zero_insn_end(insn, marker);

    if i >= 0 {
        insn.bytes[i as usize] = insn.bytes[i as usize].wrapping_add(1);
        while insn.bytes[i as usize] == 0 {
            i -= 1;
            if i < 0 {
                break;
            }
            insn.bytes[i as usize] = insn.bytes[i as usize].wrapping_add(1);
        }
    }

    insn.len = marker as i32;
    i >= 0
}

unsafe fn move_next_range() -> bool {
    let mut result = true;
    match MODE {
        SearchMode::Rand | SearchMode::Driven => {
            if SEARCH_RANGE.started {
                result = false;
            } else {
                SEARCH_RANGE = TOTAL_RANGE;
            }
        }
        SearchMode::Brute | SearchMode::Tunnel => {
            libc::pthread_mutex_lock(POOL_MUTEX);
            SEARCH_RANGE.started = false;
            if ptr::addr_of!((*RANGE_MARKER).bytes).read()
                == ptr::addr_of!(TOTAL_RANGE.end.bytes).read()
            {
                result = false;
            } else {
                SEARCH_RANGE.start = *RANGE_MARKER;
                SEARCH_RANGE.end = *RANGE_MARKER;
                if !increment_range(&mut SEARCH_RANGE.end, CONFIG.range_bytes as usize) {
                    SEARCH_RANGE.end = TOTAL_RANGE.end;
                } else if SEARCH_RANGE.end.bytes > TOTAL_RANGE.end.bytes {
                    SEARCH_RANGE.end = TOTAL_RANGE.end;
                }
                *RANGE_MARKER = SEARCH_RANGE.end;
            }
            libc::pthread_mutex_unlock(POOL_MUTEX);
        }
    }
    result
}

unsafe fn init_inj(new_insn: &Insn) {
    INJ.i = *new_insn;
    INJ.index = -1;
    INJ.last_len = -1;
}

unsafe fn get_rand_insn_in_range(r: &Range) {
    let mut inclusive_end = r.end.bytes;
    let mut i = MAX_INSN_LENGTH as isize - 1;
    while i >= 0 {
        inclusive_end[i as usize] = inclusive_end[i as usize].wrapping_sub(1);
        if inclusive_end[i as usize] != 0xff {
            break;
        }
        i -= 1;
    }

    let mut all_max = true;
    let mut all_min = true;
    let mut j = 0usize;
    while j < MAX_INSN_LENGTH {
        let rand_byte = if all_max && all_min {
            (libc::rand() % (inclusive_end[j] as i32 - r.start.bytes[j] as i32 + 1)
                + r.start.bytes[j] as i32) as u8
        } else if all_max {
            (libc::rand() % (inclusive_end[j] as i32 + 1)) as u8
        } else if all_min {
            (libc::rand() % (256 - r.start.bytes[j] as i32) + r.start.bytes[j] as i32) as u8
        } else {
            (libc::rand() % 256) as u8
        };
        INJ.i.bytes[j] = rand_byte;
        all_max = all_max && (INJ.i.bytes[j] == inclusive_end[j]);
        all_min = all_min && (INJ.i.bytes[j] == r.start.bytes[j]);
        j += 1;
    }
}

unsafe fn move_next_instruction() -> Result<bool, String> {
    loop {
        match MODE {
            SearchMode::Rand => {
                if !SEARCH_RANGE.started {
                    init_inj(&ZERO_INSN);
                }
                get_rand_insn_in_range(&SEARCH_RANGE);
            }
            SearchMode::Brute => {
                if !SEARCH_RANGE.started {
                    init_inj(&SEARCH_RANGE.start);
                    INJ.index = CONFIG.brute_depth - 1;
                } else {
                    INJ.index = CONFIG.brute_depth - 1;
                    while INJ.index >= 0 {
                        let idx = INJ.index as usize;
                        INJ.i.bytes[idx] = INJ.i.bytes[idx].wrapping_add(1);
                        if INJ.i.bytes[idx] != 0 {
                            break;
                        }
                        INJ.index -= 1;
                    }
                }
            }
            SearchMode::Tunnel => {
                if !SEARCH_RANGE.started {
                    init_inj(&SEARCH_RANGE.start);
                    INJ.index = SEARCH_RANGE.start.len;
                } else {
                    if RESULT.length as i32 != INJ.last_len && INJ.index < RESULT.length as i32 - 1
                    {
                        INJ.index += 1;
                    }
                    INJ.last_len = RESULT.length as i32;
                    let idx = INJ.index as usize;
                    INJ.i.bytes[idx] = INJ.i.bytes[idx].wrapping_add(1);
                    while INJ.index >= 0 && INJ.i.bytes[INJ.index as usize] == 0 {
                        INJ.index -= 1;
                        if INJ.index >= 0 {
                            let idx = INJ.index as usize;
                            INJ.i.bytes[idx] = INJ.i.bytes[idx].wrapping_add(1);
                        }
                        INJ.last_len = -1;
                    }
                }
            }
            SearchMode::Driven => {
                let mut remaining = MAX_INSN_LENGTH;
                let mut offset = 0usize;
                while remaining > 0 {
                    let rc = libc::read(
                        libc::STDIN_FILENO,
                        INJ.i.bytes[offset..].as_mut_ptr().cast(),
                        remaining,
                    );
                    if rc > 0 {
                        remaining -= rc as usize;
                        offset += rc as usize;
                    }
                }
            }
        }

        SEARCH_RANGE.started = true;

        if is_blacklisted_opcode() {
            emit_skipped("opcode blacklist")?;
            continue;
        }
        if is_blacklisted_prefix() {
            emit_skipped("prefix blacklist")?;
            continue;
        }
        if prefix_count() > CONFIG.max_prefix || (!CONFIG.allow_dup_prefix && has_dup_prefix()) {
            emit_skipped("prefix violation")?;
            continue;
        }
        if INJ.i.bytes >= SEARCH_RANGE.end.bytes {
            return Ok(false);
        }

        return Ok(match MODE {
            SearchMode::Rand | SearchMode::Driven => true,
            SearchMode::Brute | SearchMode::Tunnel => INJ.index >= 0,
        });
    }
}

unsafe fn is_prefix(x: u8) -> bool {
    matches!(
        x,
        0xf0 | 0xf2 | 0xf3 | 0x2e | 0x36 | 0x3e | 0x26 | 0x64 | 0x65 | 0x66 | 0x67
    ) || (0x40..=0x4f).contains(&x)
}

unsafe fn prefix_count() -> i32 {
    let mut i = 0usize;
    while i < MAX_INSN_LENGTH {
        if !is_prefix(INJ.i.bytes[i]) {
            return i as i32;
        }
        i += 1;
    }
    i as i32
}

unsafe fn has_dup_prefix() -> bool {
    let mut byte_count = [0i32; 256];
    let mut i = 0usize;
    while i < MAX_INSN_LENGTH {
        if is_prefix(INJ.i.bytes[i]) {
            byte_count[INJ.i.bytes[i] as usize] += 1;
        } else {
            break;
        }
        i += 1;
    }
    byte_count.iter().any(|count| *count > 1)
}

unsafe fn has_opcode(op: &[u8]) -> bool {
    let mut i = 0usize;
    while i < MAX_INSN_LENGTH {
        if !is_prefix(INJ.i.bytes[i]) {
            let mut j = 0usize;
            while j < op.len() {
                if i + j >= MAX_INSN_LENGTH || op[j] != INJ.i.bytes[i + j] {
                    return false;
                }
                j += 1;
            }
            return true;
        }
        i += 1;
    }
    false
}

unsafe fn has_prefix(pre: &[u8]) -> bool {
    let mut i = 0usize;
    while i < MAX_INSN_LENGTH {
        if is_prefix(INJ.i.bytes[i]) {
            if pre.contains(&INJ.i.bytes[i]) {
                return true;
            }
        } else {
            return false;
        }
        i += 1;
    }
    false
}

unsafe fn is_blacklisted_opcode() -> bool {
    if OPCODE_BLACKLIST
        .iter()
        .any(|entry| has_opcode(entry.opcode))
    {
        return true;
    }
    USER_BLACKLISTS.iter().any(|entry| has_opcode(entry))
}

unsafe fn is_blacklisted_prefix() -> bool {
    PREFIX_BLACKLIST
        .iter()
        .any(|entry| has_prefix(entry.prefix))
}

unsafe fn emit_skipped(reason: &str) -> Result<(), String> {
    match OUTPUT {
        OutputMode::Text => {
            let mut line = String::from("x: ");
            line.push_str(&print_mc(16));
            let _ = writeln!(&mut line, "... ({reason})");
            write_locked(libc::STDOUT_FILENO, line.as_bytes());
        }
        OutputMode::Raw => {
            RESULT = InjectorResults::default();
            give_result_stdout()?;
        }
    }
    Ok(())
}

unsafe fn print_asm() -> String {
    if OUTPUT != OutputMode::Text || !USE_CAPSTONE {
        return String::new();
    }

    match decode_capstone() {
        Some(decoded) => {
            EXPECTED_LENGTH = decoded.len;
            format!(
                "{:>10} {:<45} ({:2})",
                decoded.mnemonic,
                decoded.op_str,
                decoded.len
            )
        }
        None => {
            EXPECTED_LENGTH = 0;
            format!("{:>10} {:<45} ({:2})", "(unk)", " ", 0)
        }
    }
}

struct DecodedInsn {
    mnemonic: String,
    op_str: String,
    len: i32,
}

unsafe fn decode_capstone() -> Option<DecodedInsn> {
    let api = SYSTEM_CAPSTONE_API.get()?;
    if SYSTEM_CAPSTONE_HANDLE == 0 || SYSTEM_CAPSTONE_INSN.is_null() {
        return None;
    }
    let mut code = INJ.i.bytes.as_ptr();
    let mut size = MAX_INSN_LENGTH;
    let mut addr = PACKET_BUFFER as u64;
    let ok = (api.cs_disasm_iter)(
        SYSTEM_CAPSTONE_HANDLE,
        ptr::addr_of_mut!(code),
        ptr::addr_of_mut!(size),
        ptr::addr_of_mut!(addr),
        SYSTEM_CAPSTONE_INSN,
    );
    if !ok {
        return None;
    }
    let insn = &*SYSTEM_CAPSTONE_INSN;
    let mnemonic = std::ffi::CStr::from_ptr(insn.mnemonic.as_ptr())
        .to_string_lossy()
        .into_owned();
    let op_str = std::ffi::CStr::from_ptr(insn.op_str.as_ptr())
        .to_string_lossy()
        .into_owned();
    let len = (addr - PACKET_BUFFER as u64) as i32;
    Some(DecodedInsn {
        mnemonic,
        op_str,
        len,
    })
}

unsafe fn print_mc(length: usize) -> String {
    let mut out = String::new();
    let mut p = false;
    if !is_prefix(INJ.i.bytes[0]) {
        out.push(' ');
        p = true;
    }
    let mut i = 0usize;
    while i < length && i < MAX_INSN_LENGTH {
        let _ = write!(&mut out, "{:02x}", INJ.i.bytes[i]);
        if !p
            && i < MAX_INSN_LENGTH - 1
            && is_prefix(INJ.i.bytes[i])
            && !is_prefix(INJ.i.bytes[i + 1])
        {
            out.push(' ');
            p = true;
        }
        i += 1;
    }
    out
}

unsafe fn preamble_length() -> isize {
    if USE_TF {
        ptr::addr_of!(asm::preamble_end) as isize - ptr::addr_of!(asm::preamble_start) as isize
    } else {
        0
    }
}

#[inline(never)]
unsafe fn inject(insn_size: i32) {
    let preamble_length = preamble_length();
    PACKET = PACKET_BUFFER
        .add(PAGE_SIZE - insn_size as usize - preamble_length as usize)
        .cast();

    if preamble_length > 0 {
        libc::memcpy(
            PACKET.cast(),
            ptr::addr_of!(asm::preamble_start).cast(),
            preamble_length as usize,
        );
    }

    let copy_len = if insn_size < 0 {
        0
    } else if insn_size > MAX_INSN_LENGTH as i32 {
        MAX_INSN_LENGTH
    } else {
        insn_size as usize
    };
    libc::memcpy(
        PACKET.add(preamble_length as usize).cast(),
        INJ.i.bytes.as_ptr().cast(),
        copy_len,
    );

    if CONFIG.enable_null_access {
        libc::memset(ptr::null_mut(), 0, PAGE_SIZE);
    }

    DUMMY_STACK.dummy_stack_lo[0] = 0;

    if !HAVE_STATE {
        HAVE_STATE = true;
        configure_sig_handler(state_handler);
        core::arch::asm!("ud2", options(nomem, nostack));
    }

    configure_sig_handler(fault_handler);
    core::arch::asm!(
        "lea 2f(%rip), %r11",
        "mov %r11, {resume_slot}(%rip)",
        "jmp {inject_exec}",
        "2:",
        inject_exec = sym asm::inject_exec,
        resume_slot = sym RESUME_IP,
        options(att_syntax)
    );
}

unsafe extern "C" fn state_handler(
    _signum: libc::c_int,
    _si: *mut libc::siginfo_t,
    p: *mut c_void,
) {
    let uc = p as *mut libc::ucontext_t;
    FAULT_CONTEXT.write((*uc).uc_mcontext);
    (*uc).uc_mcontext.gregs[libc::REG_RIP as usize] += UD2_SIZE as i64;
}

unsafe extern "C" fn fault_handler(signum: libc::c_int, si: *mut libc::siginfo_t, p: *mut c_void) {
    let uc = p as *mut libc::ucontext_t;
    let mut insn_length = (*uc).uc_mcontext.gregs[libc::REG_RIP as usize]
        - PACKET as isize as i64
        - preamble_length() as i64;

    if insn_length < 0 || insn_length > MAX_INSN_LENGTH as i64 {
        insn_length = JMP_LENGTH as i64;
    }

    RESULT.valid = 1;
    RESULT.length = insn_length as u32;
    RESULT.signum = signum as u32;
    RESULT.sicode = (*si).si_code as u32;
    RESULT.siaddr = if signum == libc::SIGSEGV || signum == libc::SIGBUS {
        (*si).si_addr() as usize as u32
    } else {
        u32::MAX
    };

    let saved = FAULT_CONTEXT.assume_init_ref();
    (*uc).uc_mcontext.gregs = saved.gregs;
    (*uc).uc_mcontext.gregs[libc::REG_RIP as usize] = RESUME_IP as i64;
    (*uc).uc_mcontext.gregs[libc::REG_EFL as usize] &= !TF;
}

unsafe fn configure_sig_handler(
    handler: unsafe extern "C" fn(libc::c_int, *mut libc::siginfo_t, *mut c_void),
) {
    let mut s: libc::sigaction = std::mem::zeroed();
    s.sa_flags = libc::SA_SIGINFO | libc::SA_ONSTACK;
    s.sa_sigaction = handler as usize;
    libc::sigfillset(&mut s.sa_mask);

    for sig in [
        libc::SIGILL,
        libc::SIGSEGV,
        libc::SIGFPE,
        libc::SIGBUS,
        libc::SIGTRAP,
    ] {
        if libc::sigaction(sig, &s, ptr::null_mut()) != 0 {
            libc::abort();
        }
    }
}

unsafe fn raw_insn_bytes() -> [u8; RAW_REPORT_INSN_BYTES] {
    let mut bytes = [0u8; RAW_REPORT_INSN_BYTES];
    ptr::copy_nonoverlapping(
        ptr::addr_of!(INJ.i).cast::<u8>(),
        bytes.as_mut_ptr(),
        RAW_REPORT_INSN_BYTES,
    );
    bytes
}

unsafe fn give_result_stdout() -> Result<(), String> {
    match OUTPUT {
        OutputMode::Text => {
            let signum = RESULT.signum;
            let length = RESULT.length;
            let sicode = RESULT.sicode;
            let siaddr = RESULT.siaddr;
            let sig = match signum as i32 {
                libc::SIGILL => "sigill ",
                libc::SIGSEGV => "sigsegv",
                libc::SIGFPE => "sigfpe ",
                libc::SIGBUS => "sigbus ",
                libc::SIGTRAP => "sigtrap",
                _ => "       ",
            };
            let mut line = String::new();
            let _ = write!(
                &mut line,
                " {}r: ({:2}) {} {:3} {:08x} {}",
                if EXPECTED_LENGTH == length as i32 {
                    " "
                } else {
                    "."
                },
                length,
                sig,
                sicode,
                siaddr,
                print_mc(length as usize)
            );
            line.push('\n');
            write_locked(libc::STDOUT_FILENO, line.as_bytes());
        }
        OutputMode::Raw => {
            if USE_CAPSTONE {
                match decode_capstone() {
                    Some(decoded) => {
                        RESULT.disas_length = decoded.len;
                        RESULT.disas_known = 1;
                    }
                    None => {
                        RESULT.disas_length = 0;
                        RESULT.disas_known = 0;
                    }
                }
            }

            RESULT.raw_insn = raw_insn_bytes();
            let bytes = std::slice::from_raw_parts(
                ptr::addr_of!(RESULT).cast::<u8>(),
                InjectorResults::BYTE_LEN,
            );
            write_locked(libc::STDOUT_FILENO, bytes);
        }
    }
    Ok(())
}

unsafe fn tick() {
    if CONFIG.show_tick {
        TICK_COUNTER = TICK_COUNTER.wrapping_add(1);
        if (TICK_COUNTER & TICK_MASK) == 0 {
            let mut line = String::from("t: ");
            line.push_str(&print_mc(8));
            line.push_str("... ");
            if USE_CAPSTONE {
                line.push_str(&print_asm());
                line.push('\t');
            }
            let saved_output = OUTPUT;
            OUTPUT = OutputMode::Text;
            let signum = RESULT.signum;
            let length = RESULT.length;
            let sicode = RESULT.sicode;
            let siaddr = RESULT.siaddr;
            let sig = match signum as i32 {
                libc::SIGILL => "sigill ",
                libc::SIGSEGV => "sigsegv",
                libc::SIGFPE => "sigfpe ",
                libc::SIGBUS => "sigbus ",
                libc::SIGTRAP => "sigtrap",
                _ => "       ",
            };
            let _ = write!(
                &mut line,
                " {}r: ({:2}) {} {:3} {:08x} {}",
                if EXPECTED_LENGTH == length as i32 {
                    " "
                } else {
                    "."
                },
                length,
                sig,
                sicode,
                siaddr,
                print_mc(length as usize)
            );
            line.push('\n');
            OUTPUT = saved_output;
            write_locked(libc::STDERR_FILENO, line.as_bytes());
        }
    }
}

unsafe fn pretext() {
    if OUTPUT == OutputMode::Text {
        let mut line = String::from("r: ");
        line.push_str(&print_mc(8));
        line.push_str("... ");
        if USE_CAPSTONE {
            line.push_str(&print_asm());
            line.push(' ');
        }
        write_locked(libc::STDOUT_FILENO, line.as_bytes());
    }
}

unsafe fn write_locked(fd: libc::c_int, bytes: &[u8]) {
    libc::pthread_mutex_lock(OUTPUT_MUTEX);
    let _ = libc::write(fd, bytes.as_ptr().cast(), bytes.len());
    libc::pthread_mutex_unlock(OUTPUT_MUTEX);
}

unsafe fn usage() {
    let _ = libc::write(
        libc::STDOUT_FILENO,
        b"injector [-b|-r|-t|-d] [-R|-T] [-x] [-0] [-D] [-N]\n\t[-s seed] [-B brute_depth] [-P max_prefix]\n\t[-i instruction] [-e instruction]\n\t[-c core] [-X blacklist]\n\t[-j jobs] [-l range_bytes]\n"
            .as_ptr()
            .cast(),
        198,
    );
}

unsafe fn help() {
    let help = concat!(
        "injector [OPTIONS...]\n",
        "\t[-b|-r|-t|-d] ....... mode: brute, random, tunnel, directed (default: tunnel)\n",
        "\t[-R|-T] ............. output: raw, text (default: text)\n",
        "\t[-x] ................ show tick\n",
        "\t[-0] ................ allow null dereference (requires sudo)\n",
        "\t[-D] ................ allow duplicate prefixes\n",
        "\t[-N] ................ no nx bit support\n",
        "\t[-s seed] ........... in random search, seed\n",
        "\t[-B brute_depth] .... in brute search, maximum search depth\n",
        "\t[-P max_prefix] ..... maximum number of prefixes to search\n",
        "\t[-i instruction] .... instruction at which to start search, inclusive\n",
        "\t[-e instruction] .... instruction at which to end search, exclusive\n",
        "\t[-c core] ........... core on which to perform search\n",
        "\t[-X blacklist] ...... blacklist the specified instruction\n",
        "\t[-j jobs] ........... number of simultaneous jobs\n",
        "\t[-l range_bytes] .... number of base instruction bytes in each sub range\n",
    );
    let _ = libc::write(libc::STDOUT_FILENO, help.as_ptr().cast(), help.len());
}
