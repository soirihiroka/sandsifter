use capstone::prelude::*;
use chrono::Local;
use clap::Parser;
use crossterm::{
    event::{
        self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, MouseButton, MouseEventKind,
    },
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::widgets::{Scrollbar, ScrollbarOrientation, ScrollbarState};
use ratatui::{
    Terminal,
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph},
};
use std::collections::{HashMap, VecDeque};
use std::fs::{File, OpenOptions};
use std::io::{self, BufReader, Read, Write};
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use sandsifter::{injector_abi::InjectorResults, utils};

use utils::arch::arch_mode;
use utils::eslinux::SeLinuxGuard;

fn py_encode_insn(raw_insn: &[u8], len: usize) -> Vec<u8> {
    let mut out = Vec::new();
    for &b in raw_insn {
        let mut b_buf = [0; 4];
        let ch_str = (b as char).encode_utf8(&mut b_buf);
        out.extend_from_slice(ch_str.as_bytes());
    }
    out.into_iter().take(len).collect()
}

fn py_encode_full(raw_insn: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for &b in raw_insn {
        let mut b_buf = [0; 4];
        let ch_str = (b as char).encode_utf8(&mut b_buf);
        out.extend_from_slice(ch_str.as_bytes());
    }
    out
}

fn disas_ndisasm(b: &[u8]) -> (String, String) {
    let mut b_hex = String::new();
    for byte in b {
        b_hex.push_str(&format!("\\x{:02x}", byte));
    }
    let arch_flag = if cfg!(target_arch = "x86_64") {
        "-b64"
    } else {
        "-b32"
    };
    let cmd = format!("echo -ne '{}' | ndisasm {} - | head -2", b_hex, arch_flag);
    let output = std::process::Command::new("sh")
        .arg("-c")
        .arg(&cmd)
        .output();
    if let Ok(out) = output {
        let stdout = String::from_utf8_lossy(&out.stdout);
        let mut lines = stdout.lines();
        let first_line = lines.next().unwrap_or("");
        let extra_line = lines.next().unwrap_or("");

        let parts: Vec<&str> = first_line.split_whitespace().collect();
        if parts.len() >= 3 {
            let mut mnemonic = parts[2].to_string();
            let mut op_str = if parts.len() > 3 {
                parts[3..].join(" ")
            } else {
                "".to_string()
            };
            if extra_line.trim().starts_with('-') {
                op_str.push_str(&extra_line.trim()[1..]);
            }
            if mnemonic == "db" {
                mnemonic = "(unk)".to_string();
                op_str = "".to_string();
            }
            return (mnemonic, op_str);
        }
    }
    ("(unk)".to_string(), "".to_string())
}

fn disas_objdump(b: &[u8]) -> (String, String) {
    if let Ok(mut f) = std::fs::File::create("/dev/shm/shifter") {
        let _ = f.write_all(b);
    }
    let arch_arg = if cfg!(target_arch = "x86_64") {
        "-mi386 -Mx86-64"
    } else {
        "-mi386"
    };
    let cmd = format!(
        "objdump -D --insn-width=256 -b binary {} /dev/shm/shifter | head -8 | tail -1",
        arch_arg
    );
    let output = std::process::Command::new("sh")
        .arg("-c")
        .arg(&cmd)
        .output();
    if let Ok(out) = output {
        let stdout = String::from_utf8_lossy(&out.stdout);
        if stdout.len() >= 6 {
            let dis = &stdout[6..];
            if dis.len() >= 256 * 3 {
                let dis_str = &dis[256 * 3..].trim();
                let parts: Vec<&str> = dis_str.splitn(3, ' ').filter(|s| !s.is_empty()).collect();
                if !parts.is_empty() {
                    let mut mnemonic = parts[0].to_string();
                    let op_str = if parts.len() > 1 {
                        parts[1..].join(" ")
                    } else {
                        "".to_string()
                    };
                    if mnemonic == "(bad)" {
                        mnemonic = "(unk)".to_string();
                        return (mnemonic, "".to_string());
                    }
                    return (mnemonic, op_str);
                }
            }
        }
    }
    ("(unk)".to_string(), "".to_string())
}

fn format_commas(mut n: u64) -> String {
    if n == 0 {
        return "0".to_string();
    }
    let mut s = String::new();
    while n > 0 {
        let rem = n % 1000;
        n /= 1000;
        if n > 0 {
            s = format!(",{:03}{}", rem, s);
        } else {
            s = format!("{}{}", rem, s);
        }
    }
    s
}

#[derive(Parser, Debug, Clone)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(long, default_value_t = false)]
    len: bool,
    #[arg(long, default_value_t = false)]
    dis: bool,
    #[arg(long, default_value_t = false)]
    unk: bool,
    #[arg(long, default_value_t = false)]
    ill: bool,
    #[arg(long, default_value_t = false)]
    tick: bool,
    #[arg(long, default_value_t = false)]
    save: bool,
    #[arg(long, default_value_t = false)]
    resume: bool,
    #[arg(long, default_value_t = false)]
    sync: bool,
    #[arg(long, default_value_t = false)]
    low_mem: bool,

    // String args
    // Arg for the data directory
    #[arg(long, default_value = "./data_rs")]
    data_dir: String,
    // Disassembler option
    #[arg(long, default_value = "capstone")]
    disasm: String,
    // Injector path
    #[arg(long, default_value = "./injector")]
    injector: String,
    #[arg(allow_hyphen_values = true, trailing_var_arg = true)]
    injector_args: Vec<String>,
}

struct AppState {
    results: InjectorResults,
    insn_count: u64,
    artifact_count: u64,
    insn_log: VecDeque<ResultEntry>,
    artifact_log: VecDeque<InjectorResults>,
    artifacts: HashMap<Vec<u8>, InjectorResults>,
    start_time: Instant,
    insn_log_scroll_x: usize,
    insn_log_max_scroll_x: usize,
    pause: bool,
    run: bool,

    // Rate Calculation
    last_insn_count: u64,
    last_rate_time: Instant,
    delta_log: VecDeque<u64>,
    time_log: VecDeque<f64>,
    current_rate: u64,

    // Injector Management
    full_command_line: String, // The "sifter" command
    injector_flags: String,    // The flags passed to the injector
    seed: u32,
    synth_mode: char,
    child_id: u32,
    stdout: Option<BufReader<std::process::ChildStdout>>,
    intentional_restart: bool,
}

#[derive(Clone)]
struct ResultEntry {
    mnemonic: String,
    op_str: String,
    raw_full: [u8; 16], // Store full 16 bytes
    insn_len: usize,    // Store the actual length
}

impl AppState {
    fn new(synth_mode: char, seed: u32, injector_flags: String, full_command_line: String) -> Self {
        Self {
            results: InjectorResults::default(),
            insn_count: 0,
            artifact_count: 0,
            insn_log: VecDeque::with_capacity(20),
            artifact_log: VecDeque::with_capacity(10),
            artifacts: HashMap::new(),
            start_time: Instant::now(),
            insn_log_scroll_x: 0,
            insn_log_max_scroll_x: 0,
            pause: false,
            run: true,

            last_insn_count: 0,
            last_rate_time: Instant::now(),
            delta_log: VecDeque::with_capacity(100),
            time_log: VecDeque::with_capacity(100),
            current_rate: 0,

            synth_mode,
            full_command_line,
            seed,
            injector_flags,
            child_id: 0,
            stdout: None,
            intentional_restart: false,
        }
    }

    fn elapsed(&self) -> String {
        let elapsed = self.start_time.elapsed();
        let secs = elapsed.as_secs();
        let millis = elapsed.subsec_millis() / 10;
        let (h, rem) = (secs / 3600, secs % 3600);
        let (m, s) = (rem / 60, rem % 60);
        format!("{:02}:{:02}:{:02}.{:02}", h, m, s, millis)
    }
}

fn make_insn_log_line(entry: &ResultEntry, is_last: bool) -> Line<'static> {
    let style = if is_last {
        Style::default().fg(Color::White)
    } else {
        Style::default().fg(Color::DarkGray)
    };
    let op_style = if is_last {
        Style::default().fg(Color::Blue)
    } else {
        Style::default().fg(Color::DarkGray)
    };

    let hex_full = hex::encode(py_encode_full(&entry.raw_full));
    let valid_hex = hex::encode(py_encode_insn(&entry.raw_full, entry.insn_len.min(16)));
    let valid_hex_len = valid_hex.len();
    let trailing_hex = &hex_full[valid_hex_len..];

    let trailing_style = if is_last {
        Style::default().fg(Color::DarkGray)
    } else {
        Style::default().fg(Color::Rgb(50, 50, 50))
    };

    Line::from(vec![
        Span::styled(format!("{:>10} ", entry.mnemonic), style),
        Span::styled(format!("{:<55} ", entry.op_str), op_style),
        Span::styled(valid_hex.to_string(), style),
        Span::styled(trailing_hex.to_string(), trailing_style),
    ])
}

fn insn_log_scrollbar_area(
    size: ratatui::layout::Rect,
    show_scrollbar: bool,
) -> Option<ratatui::layout::Rect> {
    if !show_scrollbar {
        return None;
    }

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(22),
            Constraint::Length(6),
            Constraint::Min(0),
        ])
        .split(size);

    if chunks[0].width < 3 || chunks[0].height < 4 {
        return None;
    }

    let inner = ratatui::layout::Rect {
        x: chunks[0].x + 1,
        y: chunks[0].y + 1,
        width: chunks[0].width.saturating_sub(2),
        height: chunks[0].height.saturating_sub(2),
    };

    if inner.height == 0 {
        return None;
    }

    Some(ratatui::layout::Rect {
        x: inner.x,
        y: inner.y + inner.height - 1,
        width: inner.width,
        height: 1,
    })
}

fn spawn_injector(flags: &str, mode: char, seed: u32, args: &Args) -> std::process::Child {
    let root_flag = if unsafe { libc::geteuid() } == 0 {
        "-0"
    } else {
        ""
    };
    let cmd_str = format!(
        "exec {} {} -{} -R {} -s {}",
        args.injector, flags, mode, root_flag, seed
    );
    let stderr_file = File::create(format!("{}/injector_stderr.log", args.data_dir)).unwrap();
    let mut cmd = Command::new("sh");
    cmd.arg("-c").arg(&cmd_str);

    unsafe {
        cmd.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }

    cmd.stdout(Stdio::piped())
        .stdin(Stdio::piped())
        .stderr(Stdio::from(stderr_file))
        .spawn()
        .expect(
            format!(
                "Failed to spawn injector. Ensure '{}' exists.",
                args.injector
            )
            .as_str(),
        )
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let command_line = std::env::args().collect::<Vec<_>>().join(" ");

    if !args.len && !args.unk && !args.dis && !args.ill {
        println!(
            "warning: no search type (--len, --unk, --dis, --ill) specified, results will not be recorded."
        );
    }
    utils::privilege::get_privilege()?;

    let _selinux_guard = SeLinuxGuard::init();

    if !std::path::Path::new(&args.data_dir).exists() {
        std::fs::create_dir_all(&args.data_dir)?;
    }

    let sync_file = format!("{}/sync", args.data_dir);
    let tick_file = format!("{}/tick", args.data_dir);
    let last_file = format!("{}/last", args.data_dir);

    let synth_mode = if args.injector_args.contains(&"-r".to_string()) {
        'r'
    } else if args.injector_args.contains(&"-b".to_string()) {
        'b'
    } else {
        't'
    };
    let seed: u32 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .subsec_nanos();

    let mut clean_args = args.injector_args.clone();
    clean_args.retain(|a| a != "--");
    if args.resume {
        if let Ok(last) = std::fs::read_to_string(&last_file) {
            clean_args.push("-i".to_string());
            clean_args.push(last.trim().to_string());
        } else {
            println!("no resume file found");
            std::process::exit(1);
        }
    }
    let joined_args = clean_args.join(" ");

    if args.sync {
        if let Ok(mut f) = File::create(&sync_file) {
            let root_flag = if unsafe { libc::geteuid() } == 0 {
                "-0"
            } else {
                ""
            };
            let inj_cmd = format!(
                "exec {} {} -{} -R {} -s {}",
                args.injector, joined_args, synth_mode, root_flag, seed
            );
            writeln!(f, "#").ok();
            writeln!(f, "# {}", command_line).ok();
            writeln!(f, "# {}", inj_cmd).ok();
            writeln!(f, "#").ok();
            writeln!(f, "# cpu:").ok();
            if let Ok(file) = File::open("/proc/cpuinfo") {
                let reader = io::BufReader::new(file);
                for line in std::io::BufRead::lines(reader)
                    .filter_map(|l| l.ok())
                    .take(7)
                {
                    writeln!(f, "# {}", line).ok();
                }
            }
            writeln!(f, "# {:28}  v  l  s  c", "").ok();
        }
    }

    let state = Arc::new(Mutex::new(AppState::new(
        synth_mode,
        seed,
        joined_args.clone(),
        command_line.clone(),
    )));
    let mut child = spawn_injector(&joined_args, synth_mode, seed, &args);
    {
        let mut s = state.lock().unwrap();
        s.child_id = child.id();
        // Wrap the raw stdout in a 64KB BufReader
        s.stdout = Some(io::BufReader::with_capacity(
            65536,
            child.stdout.take().unwrap(),
        ));
    }

    let state_clone = Arc::clone(&state);
    let args_clone = args.clone();
    thread::spawn(move || {
        let cs = Capstone::new()
            .x86()
            .mode(arch_mode())
            .build()
            .expect("Failed to create Capstone object");

        let mut last_tick_write = Instant::now();

        loop {
            let mut stdout_opt = None;
            {
                let mut s = state_clone.lock().unwrap();
                if !s.run {
                    break;
                }
                if s.pause {
                    drop(s);
                    thread::sleep(Duration::from_millis(50));
                    continue;
                }
                stdout_opt = s.stdout.take();
            }

            if let Some(mut stdout) = stdout_opt {
                let mut process_aborted = false;

                // --- CONTINUOUS LOOP (NO BATCHING) ---
                {
                    let mut buffer = [0u8; InjectorResults::BYTE_LEN];
                    match stdout.read_exact(&mut buffer) {
                        Ok(_) => {
                            let res: InjectorResults = unsafe {
                                std::ptr::read_unaligned(buffer.as_ptr() as *const InjectorResults)
                            };

                            let insn_len = res.length as usize;
                            let py_encoded_bytes = py_encode_insn(&res.raw_insn, insn_len.min(16));
                            let insn_bytes = &py_encoded_bytes;

                            let (mnemonic, op_str) = if args_clone.disasm == "ndisasm" {
                                disas_ndisasm(insn_bytes)
                            } else if args_clone.disasm == "objdump" {
                                disas_objdump(insn_bytes)
                            } else {
                                match cs.disasm_all(insn_bytes, 0) {
                                    Ok(insns) => {
                                        if let Some(i) = insns.as_ref().first() {
                                            (
                                                i.mnemonic().unwrap_or("").to_string(),
                                                i.op_str().unwrap_or("").to_string(),
                                            )
                                        } else {
                                            ("(unk)".to_string(), "".to_string())
                                        }
                                    }
                                    Err(_) => ("(unk)".to_string(), "".to_string()),
                                }
                            };

                            let entry = ResultEntry {
                                mnemonic,
                                op_str: op_str.chars().take(60).collect(),
                                raw_full: res.raw_insn,
                                insn_len,
                            };


                            let mut error = false;
                            if res.valid != 0 {
                                if args_clone.unk && res.disas_known == 0 && res.signum != 4 {
                                    error = true;
                                }
                                if args_clone.len
                                    && res.disas_known != 0
                                    && res.disas_length != res.length.try_into().unwrap()
                                {
                                    error = true;
                                }
                                if args_clone.dis
                                    && res.disas_known != 0
                                    && res.disas_length != res.length.try_into().unwrap()
                                    && res.signum != 4
                                {
                                    error = true;
                                }
                                if args_clone.ill && res.disas_known != 0 && res.signum == 4 {
                                    error = true;
                                }
                            }

                            if error {
                                let mut s = state_clone.lock().unwrap();
                                s.artifact_log.push_front(res);
                                if s.artifact_log.len() >= 10 {
                                    s.artifact_log.pop_back();
                                }
                                if !s.artifacts.contains_key(insn_bytes) {
                                    if !args_clone.low_mem {
                                        s.artifacts.insert(insn_bytes.to_vec(), res);
                                    }
                                    s.artifact_count += 1;

                                    if args_clone.sync {
                                        if let Ok(mut f) = OpenOptions::new().append(true).open(&sync_file)
                                        {
                                            let v_val = res.valid;
                                            let v_len = res.length;
                                            let v_sig = res.signum;
                                            let v_cod = res.sicode;
                                            writeln!(
                                                f,
                                                "{:>30} {:2} {:2} {:2} {:2} ({})",
                                                hex::encode(insn_bytes),
                                                v_val,
                                                v_len,
                                                v_sig,
                                                v_cod,
                                                hex::encode(py_encode_full(&res.raw_insn))
                                            )
                                            .ok();
                                        }
                                    }
                                }
                            }

                            let mut s = state_clone.lock().unwrap();
                            s.insn_count += 1;
                            s.results = res;
                            s.insn_log.push_back(entry);
                            if s.insn_log.len() > 20 {
                                s.insn_log.pop_front();
                            }
                            drop(s);

                            if args_clone.tick
                                && last_tick_write.elapsed() >= Duration::from_secs_f32(2.5)
                            {
                                if let Ok(mut f) = File::create(&tick_file) {
                                    write!(f, "{}", hex::encode(insn_bytes)).ok();
                                }
                                last_tick_write = Instant::now();
                            }
                        }
                        Err(_) => {
                            process_aborted = true;
                        }
                    }
                }

                if !process_aborted {
                    let mut s = state_clone.lock().unwrap();
                    s.stdout = Some(stdout); // Return the pipe to the global state
                } else {
                    let mut s = state_clone.lock().unwrap();
                    if s.intentional_restart {
                        s.intentional_restart = false;
                    } else {
                        s.run = false;
                        break;
                    }
                }
            } else {
                thread::sleep(Duration::from_millis(10));
            }
        }
    });

    enable_raw_mode()?;
    let mut terminal_stdout = io::stdout();
    execute!(terminal_stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(terminal_stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut last_tick = Instant::now();
    let tick_rate = Duration::from_millis(1000 / 60);

    loop {
        {
            let mut s = state.lock().unwrap();
            let now = Instant::now();
            let elapsed = now.duration_since(s.last_rate_time).as_secs_f64();

            if elapsed >= 0.01 {
                let delta = s.insn_count.saturating_sub(s.last_insn_count);

                if s.delta_log.len() >= 100 {
                    s.delta_log.pop_front();
                }
                if s.time_log.len() >= 100 {
                    s.time_log.pop_front();
                }

                s.delta_log.push_back(delta);
                s.time_log.push_back(elapsed);

                s.last_insn_count = s.insn_count;
                s.last_rate_time = now;

                let total_time: f64 = s.time_log.iter().sum();
                let total_delta: u64 = s.delta_log.iter().sum();

                if total_time > 0.0 {
                    s.current_rate = (total_delta as f64 / total_time) as u64;
                }
            }
        }

        terminal.draw(|f| ui(f, &state))?;

        let timeout = tick_rate
            .checked_sub(last_tick.elapsed())
            .unwrap_or_else(|| Duration::from_secs(0));

        if event::poll(timeout)? {
            match event::read()? {
                Event::Key(key) => match key.code {
                    KeyCode::Left => {
                        let mut s = state.lock().unwrap();
                        s.insn_log_scroll_x = s.insn_log_scroll_x.saturating_sub(4);
                    }
                    KeyCode::Right => {
                        let mut s = state.lock().unwrap();
                        s.insn_log_scroll_x =
                            (s.insn_log_scroll_x + 4).min(s.insn_log_max_scroll_x);
                    }
                    KeyCode::Home => {
                        let mut s = state.lock().unwrap();
                        s.insn_log_scroll_x = 0;
                    }
                    KeyCode::End => {
                        let mut s = state.lock().unwrap();
                        s.insn_log_scroll_x = s.insn_log_max_scroll_x;
                    }
                    KeyCode::Char('q') => {
                        let mut s = state.lock().unwrap();
                        s.run = false;
                        unsafe {
                            libc::kill(-(s.child_id as i32), libc::SIGTERM);
                        }
                        break;
                    }
                    KeyCode::Char('p') => {
                        let mut s = state.lock().unwrap();
                        s.pause = !s.pause;
                    }
                    KeyCode::Char('m') => {
                        let mut s = state.lock().unwrap();
                        s.pause = true;
                        s.intentional_restart = true;
                        unsafe {
                            libc::kill(-(s.child_id as i32), libc::SIGTERM);
                        }

                        s.synth_mode = match s.synth_mode {
                            'b' => 'r',
                            'r' => 't',
                            _ => 'b',
                        };

                        let mut new_child =
                            spawn_injector(&s.injector_flags, s.synth_mode, s.seed, &args);
                        s.child_id = new_child.id();
                        // Wrap the new process's stdout
                        s.stdout = Some(io::BufReader::with_capacity(
                            65536,
                            new_child.stdout.take().unwrap(),
                        ));
                        s.pause = false;
                    }
                    _ => {}
                },
                Event::Mouse(mouse) => match mouse.kind {
                    MouseEventKind::Down(MouseButton::Left) => {
                        let show_scrollbar = {
                            let s = state.lock().unwrap();
                            s.insn_log_max_scroll_x > 0
                        };
                        if let Some(sb) =
                            insn_log_scrollbar_area(terminal.size()?.into(), show_scrollbar)
                        {
                            let mx = mouse.column;
                            let my = mouse.row;
                            if my == sb.y && mx >= sb.x && mx < sb.x + sb.width {
                                let mut s = state.lock().unwrap();
                                let width = sb.width.saturating_sub(1).max(1) as usize;
                                let rel = (mx - sb.x) as usize;
                                let ratio = rel as f64 / width as f64;
                                s.insn_log_scroll_x =
                                    ((s.insn_log_max_scroll_x as f64 * ratio).round() as usize)
                                        .min(s.insn_log_max_scroll_x);
                            }
                        }
                    }
                    MouseEventKind::ScrollLeft => {
                        let mut s = state.lock().unwrap();
                        s.insn_log_scroll_x = s.insn_log_scroll_x.saturating_sub(4);
                    }
                    MouseEventKind::ScrollRight => {
                        let mut s = state.lock().unwrap();
                        s.insn_log_scroll_x =
                            (s.insn_log_scroll_x + 4).min(s.insn_log_max_scroll_x);
                    }
                    _ => {}
                },
                _ => {}
            }
            if !state.lock().unwrap().run {
                break;
            }
        }

        if last_tick.elapsed() >= tick_rate {
            last_tick = Instant::now();
        }
        if !state.lock().unwrap().run {
            break;
        }
    }

    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    let final_state = state.lock().unwrap();
    dump_artifacts(&final_state, &args);

    Ok(())
}

fn ui(f: &mut ratatui::Frame, state: &Arc<Mutex<AppState>>) {
    let mut s = state.lock().unwrap();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(22), // Insn Log
            Constraint::Length(6),  // Stats (Perfect size for 4 lines of text + borders)
            Constraint::Min(0),     // Artifacts
        ])
        .split(f.area());

    // Instruction Log (horizontal scroll only)
    let insn_block = Block::default()
        .borders(Borders::ALL)
        .title(" Sandsifter Insn Log ");
    let insn_inner = insn_block.inner(chunks[0]);
    f.render_widget(insn_block, chunks[0]);

    let preview_max_width = s
        .insn_log
        .iter()
        .enumerate()
        .map(|(i, entry)| {
            let is_last = i == s.insn_log.len() - 1;
            make_insn_log_line(entry, is_last).width()
        })
        .max()
        .unwrap_or(0);
    let show_scrollbar = preview_max_width > insn_inner.width as usize;
    let insn_sections = if show_scrollbar {
        Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(0), Constraint::Length(1)])
            .split(insn_inner)
    } else {
        Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(0), Constraint::Length(0)])
            .split(insn_inner)
    };

    let insn_lines: Vec<Line> = s
        .insn_log
        .iter()
        .enumerate()
        .map(|(i, entry)| {
            let is_last = i == s.insn_log.len() - 1;
            make_insn_log_line(entry, is_last)
        })
        .collect();

    let content_width = insn_lines.iter().map(Line::width).max().unwrap_or(0);
    let viewport_width = insn_sections[0].width as usize;
    s.insn_log_max_scroll_x = content_width.saturating_sub(viewport_width);
    s.insn_log_scroll_x = s.insn_log_scroll_x.min(s.insn_log_max_scroll_x);

    let insn_par = Paragraph::new(insn_lines).scroll((0, s.insn_log_scroll_x as u16));
    f.render_widget(insn_par, insn_sections[0]);

    if s.insn_log_max_scroll_x > 0 {
        let mut scroll_state = ScrollbarState::new(s.insn_log_max_scroll_x.saturating_add(1))
            .position(s.insn_log_scroll_x)
            .viewport_content_length(viewport_width.max(1));
        let h_scroll = Scrollbar::new(ScrollbarOrientation::HorizontalBottom)
            .begin_symbol(None)
            .end_symbol(None);
        f.render_stateful_widget(h_scroll, insn_sections[1], &mut scroll_state);
    }

    // --- FIX: Dynamic Rate Bar Calculation ---
    // Matches Python's: "  %d/s%s" % (rate, " " * min(rate // 1000, 100))
    let rate_spaces = (s.current_rate / 1000).min(100) as usize;
    let rate_str = format!("  {}/s{}  ", s.current_rate, " ".repeat(rate_spaces));
    // -----------------------------------------

    // Stats
    let res = s.results;
    let v_val = res.valid;
    let v_len = res.length;
    let v_sig = res.signum;
    let v_cod = res.sicode;

    let stats_text = vec![
        Line::from(vec![
            Span::raw("Elapsed: "),
            Span::styled(s.elapsed(), Style::default().fg(Color::Cyan)),
            Span::raw(" | Mode: "),
            Span::styled(
                format!("{}", s.synth_mode),
                Style::default().fg(Color::Yellow),
            ),
            Span::raw(" | Status: "),
            Span::styled(
                if s.pause { "PAUSED" } else { "RUNNING" },
                Style::default().fg(if s.pause { Color::Red } else { Color::Green }),
            ),
        ]),
        Line::from(vec![
            Span::raw("Instructions: "),
            Span::styled(
                format_commas(s.insn_count),
                Style::default().fg(Color::White),
            ),
            Span::raw(" | Artifacts: "),
            Span::styled(
                format_commas(s.artifact_count),
                Style::default().fg(Color::Red),
            ),
        ]),
        // The rate gets its own line with the dynamic white background
        Line::from(vec![Span::styled(
            rate_str,
            Style::default().bg(Color::White).fg(Color::Black),
        )]),
        Line::from(vec![
            Span::raw("v: "),
            Span::styled(format!("{:02x}", v_val), Style::default()),
            Span::raw(" l: "),
            Span::styled(format!("{:02x}", v_len), Style::default()),
            Span::raw(" s: "),
            Span::styled(format!("{:02x}", v_sig), Style::default()),
            Span::raw(" c: "),
            Span::styled(format!("{:02x}", v_cod), Style::default()),
        ]),
    ];
    let stats_par = Paragraph::new(stats_text)
        .block(Block::default().borders(Borders::ALL).title(" Statistics "));
    f.render_widget(stats_par, chunks[1]);

    // Artifacts
    let artifact_items: Vec<ListItem> = s
        .artifact_log
        .iter()
        .map(|ares| {
            let a_len = ares.length as usize;
            let hex_insn = hex::encode(py_encode_insn(&ares.raw_insn, a_len.min(16)));
            let hex_full = hex::encode(py_encode_full(&ares.raw_insn));
            let hex_insn_len = hex_insn.len();
            ListItem::new(Line::from(vec![
                Span::styled(hex_insn, Style::default().fg(Color::Red)),
                Span::styled(
                    hex_full[hex_insn_len..].to_string(),
                    Style::default().fg(Color::DarkGray),
                ),
            ]))
        })
        .collect();

    let artifact_list = List::new(artifact_items).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Artifact Log "),
    );
    f.render_widget(artifact_list, chunks[2]);
}

fn dump_artifacts(s: &AppState, args: &Args) {
    let log_file = format!("{}/log", args.data_dir);
    if let Ok(mut f) = File::create(&log_file) {
        let root_flag = if unsafe { libc::geteuid() } == 0 {
            "-0"
        } else {
            ""
        };
        let injector_cmd = format!(
            "{} {} -{} -R {} -s {}",
            args.injector, s.injector_flags, s.synth_mode, root_flag, s.seed
        );

        writeln!(f, "#").ok();
        writeln!(f, "# {}", s.full_command_line).ok();
        writeln!(f, "# {}", injector_cmd).ok();
        writeln!(f, "#").ok();

        // 2. Use 13-character padding for the labels to align the values
        writeln!(f, "# {:<13}{}", "insn tested:", s.insn_count).ok();
        writeln!(f, "# {:<13}{}", "artf found: ", s.artifact_count).ok();
        writeln!(f, "# {:<13}{}", "runtime:    ", s.elapsed()).ok();
        writeln!(f, "# {:<13}{}", "seed:       ", s.seed).ok();

        let arch = if cfg!(target_arch = "x86_64") {
            "64"
        } else {
            "32"
        };
        writeln!(f, "# {:<13}{}", "arch:       ", arch).ok();
        writeln!(
            f,
            "# {:<13}{}",
            "date:       ",
            Local::now().format("%Y-%m-%d %H:%M:%S")
        )
        .ok();
        writeln!(f, "#").ok();

        // CPU info: Python takes the first 7 lines
        writeln!(f, "# cpu:").ok();
        if let Ok(cpu_file) = File::open("/proc/cpuinfo") {
            let reader = io::BufReader::new(cpu_file);
            for line in io::BufRead::lines(reader).filter_map(|l| l.ok()).take(7) {
                writeln!(f, "# {}", line).ok();
            }
        }

        // Column header padding matches Python's 28 spaces
        writeln!(f, "# {:28}  v  l  s  c", "").ok();

        let mut keys: Vec<_> = s.artifacts.keys().collect();
        keys.sort();
        for k in keys {
            let v = s.artifacts.get(k).unwrap();
            let v_val = v.valid;
            let v_len = v.length;
            let v_sig = v.signum;
            let v_cod = v.sicode;
            // Matching: "%30s %2d %2d %2d %2d (%s)\n"
            writeln!(
                f,
                "{:>30} {:2} {:2} {:2} {:2} ({})",
                hex::encode(k),
                v_val,
                v_len,
                v_sig,
                v_cod,
                hex::encode(py_encode_full(&v.raw_insn))
            )
            .ok();
        }
    }

    if args.save {
        let last_file = format!("{}/last", args.data_dir);
        if let Ok(mut f) = File::create(&last_file) {
            let encoded_insn = hex::encode(py_encode_full(&s.results.raw_insn));
            write!(f, "{}", encoded_insn).ok();
        }
    }
}
