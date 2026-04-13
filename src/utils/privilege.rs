use std::os::unix::process::CommandExt;
use std::process::Command;

pub fn get_privilege() -> Result<(), Box<dyn std::error::Error>> {
    if unsafe { libc::geteuid() } == 0 {
        return Ok(());
    }

    println!("This operation requires root privileges. Prompting for sudo...");

    // Gather the current executable path and all arguments passed to it.
    let current_exe = std::env::current_exe()?;
    let args: Vec<String> = std::env::args().collect();

    // Replace the current process with `sudo`.
    let err = Command::new("sudo")
        // Preserve the original environment variables
        .arg("--preserve-env")
        .arg(current_exe)
        .args(&args[1..])
        .exec();

    // `exec()` NEVER returns if it succeeds.
    // If the code execution reaches this line, it means `sudo` failed to launch
    // (e.g., `sudo` is not installed, or path is broken).
    Err(format!("Failed to execute sudo: {}", err).into())
}
