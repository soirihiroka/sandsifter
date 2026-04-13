# sandsifter

This repository is a fork of the original
[`xoreaxeaxeax/sandsifter`](https://github.com/xoreaxeaxeax/sandsifter),
with a more modern local workflow and an in-progress Rust implementation.

## What Changed In This Fork

Compared to the original project, this fork makes three major changes:

1. **Python path updated to Python 3**

   The Python frontend and summarizer in this repository follow the Python 3
   port from
   [`laura240406/sandsifter`](https://github.com/laura240406/sandsifter),
   rather than the original Python 2-era workflow from upstream.

2. **`uv`-managed Python workflow**

   The Python entrypoints use inline `uv` metadata and can be run directly once
   `uv` is installed. You do not need to manually create a virtualenv or invoke
   `pip` just to run the scripts.

3. **Rust port**

   This fork includes Rust binaries for:

   - `sifter`
   - `injector`
   - `summarize`

   The Rust implementation is intended to provide a more modern codebase and a
   native alternative to the legacy Python frontend.

## Important Runtime Differences From Upstream

### No `sudo` prefix in normal commands

The original README tells you to launch `sifter.py` with `sudo`. That is not
how this fork is meant to be used.

In this fork, both the Python and Rust sifter frontends check for root access
at runtime and re-exec through `sudo` only when required. In practice, that
means you should run:

```bash
./sifter.py --unk --dis --len --sync --tick -- -P1 -t
```

instead of:

```bash
sudo ./sifter.py --unk --dis --len --sync --tick -- -P1 -t
```

You will be prompted for elevated privileges during execution when needed.

This keeps the normal invocation cleaner while still allowing the injector to
use the privileged features sandsifter relies on, including the null-page
mapping behavior associated with `-0`.

### SELinux handling is improved

Upstream documentation tells you to disable SELinux manually before running the
tool. This fork adds SELinux integration on the Rust path: the Rust `sifter`
checks whether SELinux is enforcing, temporarily switches it to permissive
mode, and restores enforcement on exit.

That is a workflow improvement over the original "disable it yourself first"
instructions. The preserved upstream README in `README.py.md` still reflects
the older manual advice.

## Repository Layout

- `README.py.md`: preserved upstream-style Python README
- `sifter.py`: Python 3 frontend run through `uv`
- `summarize.py`: Python 3 summarizer run through `uv`
- `injector.c`: original C injector
- `src/bin/sifter.rs`: Rust sifter frontend
- `src/bin/injector.rs`: Rust injector entrypoint
- `src/bin/summarize.rs`: Rust summarizer

## Requirements

### Common tools

You will generally want:

- a Linux x86/x86_64 system
- `sudo`
- Capstone development/runtime libraries
- `nasm`/`ndisasm` and `objdump` if you want alternate disassembler modes

### Python path

For the Python scripts, this fork expects:

- Python 3.13+
- [`uv`](https://github.com/astral-sh/uv)

The Python scripts declare their own dependencies inline, so `uv` can resolve
them automatically.

### Rust path

For the Rust binaries, install a current Rust toolchain via `rustup` and build
with Cargo.

## Python Workflow

### Build the original injector

The Python frontend still drives the C injector by default:

```bash
make
```

### Run the Python sifter

With `uv` installed, the script is executable directly:

```bash
./sifter.py --unk --dis --len --sync --tick -- -P1 -t
```

If you prefer, the equivalent explicit form is:

```bash
uv run ./sifter.py --unk --dis --len --sync --tick -- -P1 -t
```

Notes:

- Do not prefix the command with `sudo`.
- The script will request elevation itself if it needs it.
- Python results are written under `./data/`.

### Summarize Python results

```bash
./summarize.py data/log
```

or:

```bash
uv run ./summarize.py data/log
```

## Rust Workflow

### Build the Rust binaries

```bash
cargo build --release
```

This produces:

- `target/release/sifter`
- `target/release/injector`
- `target/release/summarize`

### Run the Rust sifter

The Rust `sifter` defaults to `./injector`, so the simplest options are either
to copy/symlink the built injector into the repository root, or point the
frontend at the Cargo-built binary explicitly.

Explicit path example:

```bash
cargo run --release --bin sifter -- \
  --injector ./target/release/injector \
  --unk --dis --len --sync --tick \
  -P1 -t
```

Notes:

- Do not prefix the command with `sudo`.
- The Rust frontend will request elevation when needed.
- Rust results are written under `./data_rs/` by default.
- The Rust path includes SELinux integration.

### Summarize Rust results

After the run has produced a log:

```bash
cargo run --release --bin summarize -- data_rs/log
```

## Typical Output Files

### Python (`./data/`)

- `log`: final saved artifact log
- `sync`: continuously appended findings when `--sync` is enabled
- `tick`: periodic progress snapshot
- `last`: last instruction used for resume support

### Rust (`./data_rs/` by default)

- `log`: final saved artifact log
- `sync`: continuously appended findings when `--sync` is enabled
- `tick`: periodic progress snapshot
- `last`: last instruction used for resume support
- `injector_stderr.log`: stderr captured from the injector

## About The Porting Direction

This fork is best understood as a practical continuation of sandsifter rather
than a minimal patchset:

- it keeps the original research goal and core injector model
- it adopts the Python 3 fork for the script-based workflow
- it modernizes Python execution around `uv`
- it removes the need to manually start commands with `sudo`
- it adds a Rust-native implementation path
- it improves SELinux ergonomics on the Rust side

If you are comparing behavior with upstream documentation, assume
`README.py.md` is historically useful but not authoritative for the preferred
workflow in this fork.
