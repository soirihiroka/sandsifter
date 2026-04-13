use capstone::prelude::*;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use indicatif::{ProgressBar, ProgressStyle};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap},
    Terminal,
};
use std::{
    cell::RefCell,
    collections::{BTreeMap, HashSet},
    env,
    fs::{self, File},
    io::{self, BufRead, BufReader},
    process::Command,
    rc::Rc,
    time::Duration,
};

const PREFIXES_32: &[u8] = &[
    0xF0, 0xF2, 0xF3, 0x2E, 0x36, 0x3E, 0x26, 0x64, 0x65, 0x66, 0x67,
];
const PREFIXES_64: &[u8] = &[
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
];

fn get_signal_name(sig: u32) -> &'static str {
    match sig {
        1 => "sighup", 2 => "sigint", 3 => "sigquit", 4 => "sigill", 5 => "sigtrap",
        6 => "sigiot", 7 => "sigbus", 8 => "sigfpe", 9 => "sigkill", 10 => "sigusr1",
        11 => "sigsegv", 12 => "sigusr2", 13 => "sigpipe", 14 => "sigalrm", 15 => "sigterm",
        16 => "sigstkflt", 17 => "sigchld", 18 => "sigcont", 19 => "sigstop", 20 => "sigtstp",
        21 => "sigttin", 22 => "sigttou", 23 => "sigurg", 24 => "sigxcpu", 25 => "sigxfsz",
        26 => "sigvtalrm", 27 => "sigprof", 28 => "sigwinch", 29 => "sigio", 30 => "sigpwr",
        _ => "unknown",
    }
}

fn format_signals(signums: &HashSet<u32>) -> String {
    let mut names: Vec<String> = signums
        .iter()
        .map(|&s| get_signal_name(s).to_string())
        .collect();
    
    // This is the key: sort them alphabetically or by ID 
    // so they never "jump" positions in the UI.
    names.sort(); 
    
    format!("({})", names.join(","))
}

#[derive(Debug, Clone, Default)]
struct Processor {
    processor: String,
    vendor_id: String,
    cpu_family: String,
    model: String,
    model_name: String,
    stepping: String,
    microcode: String,
    architecture: u32,
}

#[derive(Debug, Clone)]
struct SifterResult {
    raw: Vec<u8>,
    _long_raw: Vec<u8>,
    valid: u32,
    _length: usize,
    signum: u32,
    sicode: u32,
}

#[derive(Debug, Clone)]
struct CondensedResult {
    raw: Vec<u8>,
    valids: HashSet<u32>,
    lengths: HashSet<usize>,
    signums: HashSet<u32>,
    sicodes: HashSet<u32>,
    prefixes: HashSet<u8>,
}

#[derive(Debug, Clone)]
struct Catalog {
    d: BTreeMap<u8, Rc<RefCell<Catalog>>>,
    v: Vec<CondensedResult>,
    base: Vec<u8>,
    count: usize,
    collapsed: bool,
    example: Vec<u8>,
    valids: HashSet<u32>,
    lengths: HashSet<usize>,
    signums: HashSet<u32>,
    sicodes: HashSet<u32>,
    prefixes: HashSet<u8>,
}

impl Catalog {
    fn collapse_all(&mut self) {
        self.collapsed = true;
        for child in self.d.values() {
            child.borrow_mut().collapse_all();
        }
    }

    fn expand_all(&mut self) {
        self.collapsed = false;
        for child in self.d.values() {
            child.borrow_mut().expand_all();
        }
    }
}

fn strip_prefixes(i: &[u8], prefixes: &[u8]) -> Vec<u8> {
    let mut idx = 0;
    while idx < i.len() && prefixes.contains(&i[idx]) {
        idx += 1;
    }
    i[idx..].to_vec()
}

fn get_prefixes(i: &[u8], prefixes: &[u8]) -> HashSet<u8> {
    let mut p = HashSet::new();
    for &b in i {
        if prefixes.contains(&b) {
            p.insert(b);
        } else {
            break;
        }
    }
    p
}

fn summarize_set<T: Ord + std::fmt::Display + Copy + std::fmt::LowerHex>(s: &HashSet<T>, fmt_hex: bool) -> String {
    if s.is_empty() {
        return String::new();
    }
    let mut vec: Vec<&T> = s.iter().collect();
    vec.sort();

    let mut l = Vec::new();

    for i in 0..vec.len() {
        let formatted = if fmt_hex {
            format!("{:02x}", vec[i])
        } else {
            format!("{}", vec[i])
        };
        l.push(formatted);
    }
    l.join(",")
}

fn summarize_prefixes(c: &CondensedResult) -> String {
    let mut p = c.prefixes.clone();
    let has_zero = p.remove(&0);
    let summary = summarize_set(&p, true);
    if has_zero {
        if !summary.is_empty() {
            format!("(__,{})", summary)
        } else {
            "(__)".to_string()
        }
    } else {
        format!("({})", summary)
    }
}

fn merge_sets<T: Clone + Eq + std::hash::Hash>(items: &[CondensedResult], extractor: fn(&CondensedResult) -> &HashSet<T>) -> HashSet<T> {
    let mut s = HashSet::new();
    for i in items {
        s.extend(extractor(i).clone());
    }
    s
}
fn bin(
    instructions: Vec<CondensedResult>, 
    index: usize, 
    base: Vec<u8>, 
    pb: &ProgressBar // Add this
) -> Rc<RefCell<Catalog>> {
    let valids = merge_sets(&instructions, |i| &i.valids);
    let lengths = merge_sets(&instructions, |i| &i.lengths);
    let signums = merge_sets(&instructions, |i| &i.signums);
    let sicodes = merge_sets(&instructions, |i| &i.sicodes);
    let prefixes = merge_sets(&instructions, |i| &i.prefixes);

    let example = instructions.first().map(|i| i.raw.clone()).unwrap_or_default();
    let count = instructions.len();

    let mut c = Catalog {
        d: BTreeMap::new(),
        v: Vec::new(),
        base,
        count,
        collapsed: true,
        example,
        valids,
        lengths,
        signums,
        sicodes,
        prefixes,
    };

    let mut binned: BTreeMap<u8, Vec<CondensedResult>> = BTreeMap::new();

    for i in instructions {
        if i.raw.len() > index {
            let b = i.raw[index];
            binned.entry(b).or_default().push(i);
        } else {
            c.v.push(i);
            pb.inc(1); // Increment for every instruction binned into a leaf
        }
    }

    for (b, subset) in binned {
        let mut new_base = c.base.clone();
        new_base.push(b);
        // Pass the progress bar down the recursion
        c.d.insert(b, bin(subset, index + 1, new_base, pb));
    }

    Rc::new(RefCell::new(c))
}

#[derive(Clone)]
enum ItemRef {
    Node(Rc<RefCell<Catalog>>),
    Leaf(CondensedResult),
}

#[derive(Clone)]
struct ListItemData {
    text: String,
    item: ItemRef,
}

fn build_summary(c: Rc<RefCell<Catalog>>, depth: usize, list: &mut Vec<ListItemData>) {
    let cat = c.borrow();
    if cat.count > 1 {
        let min_len = cat.lengths.iter().min().copied().unwrap_or(0);
        let max_len = cat.lengths.iter().max().copied().unwrap_or(0);
        
        let mut suffix = String::new();
        if min_len > cat.base.len() {
            suffix.push_str(&"..".repeat(min_len - cat.base.len()));
            suffix.push(' ');
        }
        if max_len > min_len {
            suffix.push_str(&"..".repeat(max_len - min_len));
        }

        let prefix = "  ".repeat(depth);
        let text = format!("{}> {}{}", prefix, hex::encode(&cat.base), suffix);
        list.push(ListItemData { text, item: ItemRef::Node(c.clone()) });

        if !cat.collapsed {
            for child in cat.d.values() {
                build_summary(child.clone(), depth + 1, list);
            }
            for leaf in &cat.v {
                let leaf_text = format!("{}  {}", "  ".repeat(depth), hex::encode(&leaf.raw));
                list.push(ListItemData { text: leaf_text, item: ItemRef::Leaf(leaf.clone()) });
            }
        }
    } else {
        // Solo leaf
        let mut current = c.clone();
        loop {
            let b = current.borrow();
            if b.v.is_empty() {
                if let Some(first_child) = b.d.values().next() {
                    let next_child = first_child.clone();
                    drop(b);
                    current = next_child;
                } else {
                    break;
                }
            } else {
                let leaf = b.v[0].clone();
                let leaf_text = format!("{}  {}", "  ".repeat(depth), hex::encode(&leaf.raw));
                list.push(ListItemData { text: leaf_text, item: ItemRef::Leaf(leaf) });
                break;
            }
        }
    }
}

fn disassemble_capstone(arch: u32, data: &[u8]) -> (String, String) {
    let mode = if arch == 32 { arch::x86::ArchMode::Mode32 } else { arch::x86::ArchMode::Mode64 };
    let cs = Capstone::new()
        .x86()
        .mode(mode)
        .build()
        .unwrap_or_else(|_| Capstone::new().x86().mode(arch::x86::ArchMode::Mode32).build().unwrap());

    if let Ok(insns) = cs.disasm_count(data, 0, 1) {
        if let Some(i) = insns.iter().next() {
            let mnemonic = i.mnemonic().unwrap_or("(unk)");
            let op_str = i.op_str().unwrap_or("");
            return (format!("{} {}", mnemonic, op_str), hex::encode(i.bytes()));
        }
    }
    ("(unknown)".to_string(), "n/a".to_string())
}

fn disassemble_shell(cmd_template: &str, data: &[u8]) -> String {
    let temp_dir = env::temp_dir();
    let temp_path = temp_dir.join(format!("sifter_disas_{}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
    fs::write(&temp_path, data).unwrap_or_default();

    let cmd = cmd_template.replace("{0}", temp_path.to_str().unwrap());
    let output = Command::new("sh").arg("-c").arg(cmd).output();
    
    let _ = fs::remove_file(temp_path);
    
    if let Ok(out) = output {
        let mut s = String::from_utf8_lossy(&out.stdout).to_string();
        s = s.replace('\n', " ");
        s = s.trim().to_string();
        s
    } else {
        "".to_string()
    }
}

fn run_app(terminal: &mut Terminal<CrosstermBackend<std::io::Stdout>>, root: Rc<RefCell<Catalog>>, processor: Processor) -> io::Result<Vec<String>> {
    let mut list_state = ListState::default();
    list_state.select(Some(0));

    let mut list_items = Vec::new();
    build_summary(root.clone(), 0, &mut list_items);

    loop {
        terminal.draw(|f| {
            let size = f.area(); // using .area() instead of deprecated .size()
            if size.width < 80 || size.height < 40 {
                let msg = Paragraph::new("Please resize your terminal window to at least 80x40.")
                    .style(Style::default().fg(Color::Red));
                f.render_widget(msg, size);
                return;
            }

            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .margin(1)
                .constraints([Constraint::Length(3), Constraint::Min(10), Constraint::Length(7)].as_ref())
                .split(size);

            let header_text = vec![
                Line::from(vec![Span::styled(processor.model_name.clone(), Style::default().fg(Color::White))]),
                Line::from(vec![Span::styled(
                    format!("arch: {} / processor: {} / vendor: {} / family: {} / model: {} / stepping: {} / ucode: {}",
                        processor.architecture, processor.processor, processor.vendor_id, processor.cpu_family,
                        processor.model, processor.stepping, processor.microcode
                    ),
                    Style::default().fg(Color::DarkGray)
                )]),
            ];
            let header = Paragraph::new(header_text);
            f.render_widget(header, chunks[0]);

            let main_chunks = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Percentage(35), Constraint::Percentage(65)].as_ref())
                .split(chunks[1]);

            let items: Vec<ListItem> = list_items.iter().map(|i| {
                ListItem::new(i.text.clone()).style(Style::default().fg(Color::Gray))
            }).collect();

            let list = List::new(items)
                .block(Block::default().borders(Borders::ALL))
                .highlight_style(Style::default().fg(Color::Red).add_modifier(Modifier::BOLD))
                .highlight_symbol(">> ");
            
            f.render_stateful_widget(list, main_chunks[0], &mut list_state);

            // Detail view
            let selected_idx = list_state.selected().unwrap_or(0);
            if selected_idx < list_items.len() {
                let item = &list_items[selected_idx].item;
                let mut detail_lines = Vec::new();

                match item {
                    ItemRef::Node(node_rc) => {
                        let node = node_rc.borrow();
                        detail_lines.push(Line::from(Span::styled("instruction group:", Style::default().fg(Color::Red))));
                        let g = if node.base.is_empty() { "(all)".to_string() } else { hex::encode(&node.base) };
                        detail_lines.push(Line::from(Span::raw(g)));
                        detail_lines.push(Line::raw(""));
                        detail_lines.push(Line::from(Span::styled("instructions found in this group:", Style::default().fg(Color::DarkGray))));
                        detail_lines.push(Line::from(Span::raw(node.count.to_string())));
                        detail_lines.push(Line::raw(""));
                        detail_lines.push(Line::from(Span::styled("example instruction from this group:", Style::default().fg(Color::DarkGray))));
                        detail_lines.push(Line::from(Span::raw(hex::encode(&node.example))));
                        detail_lines.push(Line::raw(""));
                        detail_lines.push(Line::from(Span::styled("group attribute summary:", Style::default().fg(Color::DarkGray))));
                        
                        detail_lines.push(Line::from(format!("valid:           {}", summarize_set(&node.valids, false))));
                        detail_lines.push(Line::from(format!("length:          {}", summarize_set(&node.lengths, false))));
                        detail_lines.push(Line::from(format!("signum:          {}", summarize_set(&node.signums, false))));
                        
                        let sig_names: HashSet<String> = node.signums.iter().map(|&s| get_signal_name(s).to_string()).collect();
                        let sig_names_vec: Vec<String> = sig_names.into_iter().collect();
                        detail_lines.push(Line::from(format!("signal:          {}", format_signals(&node.signums))));
                        detail_lines.push(Line::from(format!("sicode:          {}", summarize_set(&node.sicodes, false))));
                        
                        let mut p = node.prefixes.clone();
                        p.remove(&0);
                        detail_lines.push(Line::from(format!("prefixes:        ({})", summarize_set(&p, true))));
                    },
                    ItemRef::Leaf(leaf) => {
                        detail_lines.push(Line::from(Span::styled("instruction:", Style::default().fg(Color::Red))));
                        detail_lines.push(Line::from(Span::raw(hex::encode(&leaf.raw))));
                        detail_lines.push(Line::raw(""));
                        detail_lines.push(Line::from(format!("prefixes:        {}", summarize_prefixes(leaf))));
                        detail_lines.push(Line::from(format!("valids:          {}", summarize_set(&leaf.valids, false))));
                        detail_lines.push(Line::from(format!("lengths:         {}", summarize_set(&leaf.lengths, false))));
                        detail_lines.push(Line::from(format!("signums:         {}", summarize_set(&leaf.signums, false))));
                        
                        let sig_names: HashSet<String> = leaf.signums.iter().map(|&s| get_signal_name(s).to_string()).collect();
                        let sig_names_vec: Vec<String> = sig_names.into_iter().collect();
                        detail_lines.push(Line::from(format!("signals:         ({})", sig_names_vec.join(","))));
                        detail_lines.push(Line::from(format!("sicodes:         {}", summarize_set(&leaf.sicodes, false))));
                        detail_lines.push(Line::raw(""));
                        
                        detail_lines.push(Line::from(Span::styled("analysis:", Style::default().fg(Color::Red))));
                        
                        let dis_data = if leaf.prefixes.contains(&0) || leaf.prefixes.is_empty() {
                            leaf.raw.clone()
                        } else {
                            let mut d = vec![*leaf.prefixes.iter().next().unwrap()];
                            d.extend_from_slice(&leaf.raw);
                            d
                        };

                        let (c_asm, c_raw) = disassemble_capstone(processor.architecture, &dis_data);
                        detail_lines.push(Line::from(Span::styled("capstone:", Style::default().fg(Color::DarkGray))));
                        detail_lines.push(Line::from(format!("  {:<30}", c_asm)));
                        detail_lines.push(Line::from(Span::styled(format!("  {:<30}", c_raw), Style::default().fg(Color::DarkGray))));
                        detail_lines.push(Line::raw(""));

                        let arch_flag = if processor.architecture == 64 { "-b64" } else { "-b32" };
                        let obj_arch = if processor.architecture == 64 { "-Mx86-64" } else { "-mi386" };

                        let ndisasm_cmd = format!("ndisasm {} {{0}} | tr A-Z a-z | sed '/ db /Q' | sed 's/[0-9a-f]* *[0-9a-f]* *//' | awk 'ORS=\" \"'", arch_flag);
                        let n_asm = disassemble_shell(&ndisasm_cmd, &dis_data);
                        detail_lines.push(Line::from(Span::styled("ndisasm:", Style::default().fg(Color::DarkGray))));
                        detail_lines.push(Line::from(format!("  {:<30}", if n_asm.is_empty() { "(unknown)" } else { &n_asm })));
                        detail_lines.push(Line::raw(""));

                        let obj_arch_flag = if processor.architecture == 64 { "-m i386:x86-64" } else { "-m i386" };

                        let objdump_cmd = format!(
                            "objdump -D -b binary {} -M intel {{0}} | \
                             awk '/^ +0:/ {{ $1=\"\"; $2=\"\"; print $0; exit }}' | \
                             sed 's/^[ \t]*//' | tr -s ' '", 
                            obj_arch_flag
                        );
                        let o_asm = disassemble_shell(&objdump_cmd, &dis_data);
                        let display_obj = if o_asm.is_empty() || o_asm.contains(".byte") {
                            "(invalid or prefix only)".to_string()
                        } else {
                            o_asm
                        };

                        detail_lines.push(Line::from(Span::styled("objdump:", Style::default().fg(Color::DarkGray))));
                        detail_lines.push(Line::from(format!("  {:<30}", display_obj)));
                        detail_lines.push(Line::raw(""));
                    }
                }

                let detail_panel = Paragraph::new(detail_lines)
                    .block(Block::default().borders(Borders::ALL).style(Style::default().fg(Color::DarkGray)))
                    .wrap(Wrap { trim: true });
                f.render_widget(detail_panel, main_chunks[1]);
            }

            let footer_text = vec![
                Line::from(Span::styled("↓/j: down, ↑/k: up    →: PgDn, ←: PgUp    ↵: expand/collapse", Style::default().fg(Color::DarkGray))),
                Line::from(Span::styled("g: start, G: end      L: expand all, H: collapse all     q: quit and print", Style::default().fg(Color::DarkGray))),
            ];
            let footer = Paragraph::new(footer_text);
            f.render_widget(footer, chunks[2]);
        })?;

        if event::poll(Duration::from_millis(50))? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    match key.code {
                        KeyCode::Char('q') => {
                            let mut final_summary = Vec::new();
                            for item in &list_items {
                                final_summary.push(item.text.clone());
                            }
                            return Ok(final_summary);
                        }
                        KeyCode::Down | KeyCode::Char('j') => {
                            let i = list_state.selected().unwrap_or(0);
                            if i < list_items.len().saturating_sub(1) {
                                list_state.select(Some(i + 1));
                            }
                        }
                        KeyCode::Up | KeyCode::Char('k') => {
                            let i = list_state.selected().unwrap_or(0);
                            if i > 0 {
                                list_state.select(Some(i - 1));
                            }
                        }
                        KeyCode::Right => {
                            let i = list_state.selected().unwrap_or(0);
                            list_state.select(Some(std::cmp::min(i + 10, list_items.len().saturating_sub(1))));
                        }
                        KeyCode::Left => {
                            let i = list_state.selected().unwrap_or(0);
                            list_state.select(Some(i.saturating_sub(10)));
                        }
                        KeyCode::Char('g') => list_state.select(Some(0)),
                        KeyCode::Char('G') => list_state.select(Some(list_items.len().saturating_sub(1))),
                        KeyCode::Enter => {
                            let i = list_state.selected().unwrap_or(0);
                            if i < list_items.len() {
                                if let ItemRef::Node(node) = &list_items[i].item {
                                    let mut n = node.borrow_mut();
                                    n.collapsed = !n.collapsed;
                                    drop(n);
                                    list_items.clear();
                                    build_summary(root.clone(), 0, &mut list_items);
                                }
                            }
                        }
                        KeyCode::Char('L') => {
                            root.borrow_mut().expand_all();
                            list_items.clear();
                            build_summary(root.clone(), 0, &mut list_items);
                        }
                        KeyCode::Char('H') => {
                            root.borrow_mut().collapse_all();
                            list_items.clear();
                            build_summary(root.clone(), 0, &mut list_items);
                        }
                        _ => {}
                    }
                }
            }
        }
    }
}

pub fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("You need to specify a log file!");
        std::process::exit(1);
    }
    let mut instructions = Vec::new();
    let mut processor = Processor { architecture: 32, ..Default::default() };

    println!("\nBeginning summarization.");

    // --- Phase 1: Loading ---
    let file = File::open(&args[1]).expect("Invalid file!");
    // We get file metadata to estimate progress by bytes or count lines
    let metadata = file.metadata()?;
    let reader = BufReader::new(file);

    fn create_elegant_style() -> ProgressStyle {
        ProgressStyle::with_template(
            "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos:>7}/{len:7} {msg} ({eta})"
        )
        .unwrap()
        .progress_chars("█▉▊▋▌▍▎▏  ") // Smooth sub-pixel transitions
    }
    
    let pb = ProgressBar::new(metadata.len());
    pb.set_style(create_elegant_style());

    for line in reader.lines() {
        let l = line?;
        pb.inc(l.len() as u64 + 1); // +1 for newline
        
        if l.starts_with('#') {
            if l.contains("arch:") && l.contains("64") { processor.architecture = 64; }
            else if l.contains("processor\t:") { processor.processor = l.split_once(':').unwrap().1.trim().to_string(); }
            else if l.contains("vendor_id\t:") { processor.vendor_id = l.split_once(':').unwrap().1.trim().to_string(); }
            else if l.contains("cpu family\t:") { processor.cpu_family = l.split_once(':').unwrap().1.trim().to_string(); }
            else if l.contains("model\t:") { processor.model = l.split_once(':').unwrap().1.trim().to_string(); }
            else if l.contains("model name\t:") { processor.model_name = l.split_once(':').unwrap().1.trim().to_string(); }
            else if l.contains("stepping\t:") { processor.stepping = l.split_once(':').unwrap().1.trim().to_string(); }
            else if l.contains("microcode\t:") { processor.microcode = l.split_once(':').unwrap().1.trim().to_string(); }

            continue;
        }

        let parts: Vec<&str> = l.split_whitespace().collect();
        if parts.len() >= 6 {
            instructions.push(SifterResult {
                raw: hex::decode(parts[0]).unwrap_or_default(),
                _long_raw: hex::decode(parts[5].trim_matches(|c| c == '(' || c == ')')).unwrap_or_default(),
                valid: parts[1].parse().unwrap_or(0),
                _length: parts[2].parse().unwrap_or(0),
                signum: parts[3].parse().unwrap_or(0),
                sicode: parts[4].parse().unwrap_or(0),
            });
        }
    }
    pb.finish_with_message("Done");

    // --- Phase 2: Condensing ---
    println!("Condensing prefixes:");
    let pb_condense = ProgressBar::new(instructions.len() as u64);
    pb_condense.set_style(create_elegant_style());

    let mut d: BTreeMap<Vec<u8>, CondensedResult> = BTreeMap::new();
    let prefixes = if processor.architecture == 64 {
        [PREFIXES_32, PREFIXES_64].concat()
    } else {
        PREFIXES_32.to_vec()
    };

    for i in instructions {
        pb_condense.inc(1);
        let s = strip_prefixes(&i.raw, &prefixes);
        let mut p = get_prefixes(&i.raw, &prefixes);
        if s.len() == i.raw.len() {
            p.insert(0);
        }

        let entry = d.entry(s.clone()).or_insert_with(|| CondensedResult {
            raw: s.clone(),
            valids: HashSet::new(),
            lengths: HashSet::new(),
            signums: HashSet::new(),
            sicodes: HashSet::new(),
            prefixes: HashSet::new(),
        });

        entry.valids.insert(i.valid);
        entry.lengths.insert(s.len());
        entry.signums.insert(i.signum);
        entry.sicodes.insert(i.sicode);
        entry.prefixes.extend(p);
    }
    pb_condense.finish_with_message("Done");

    // --- Phase 3: Binning ---
    // Since binning is recursive, we can use a "spinner" or just show completion
    println!("Binning results:");
    let condensed_instructions: Vec<CondensedResult> = d.into_values().collect();

    let pb_bin = ProgressBar::new(condensed_instructions.len() as u64);
    pb_bin.set_style(create_elegant_style());

    pb_bin.set_message("Building instruction tree");
    let root = bin(condensed_instructions, 0, Vec::new(), &pb_bin);
    
    pb_bin.finish_with_message("Tree built.");

    // --- Start GUI ---
    enable_raw_mode()?;

    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let summary = run_app(&mut terminal, root, processor.clone())?;

    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    let title = "PROCESSOR ANALYSIS SUMMARY";
    let width = 50;
    println!("{}", "=".repeat(width));
    println!("{}{}", " ".repeat((width - title.len()) / 2), title);
    println!("{}", "=".repeat(width));
    println!("\n{}\n", processor.model_name);
    println!(" arch:       {}", processor.architecture);
    println!(" processor:  {}", processor.processor);
    println!(" vendor_id:  {}", processor.vendor_id);
    println!(" cpu_family: {}", processor.cpu_family);
    println!(" model:      {}", processor.model);
    println!(" stepping:   {}", processor.stepping);
    println!(" microcode:  {}\n", processor.microcode);

    for line in summary {
        println!("{}", line);
    }

    Ok(())
}