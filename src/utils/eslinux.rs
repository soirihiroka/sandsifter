use std::process::Command;

pub struct SeLinuxGuard {
    needs_restore: bool,
}

impl SeLinuxGuard {
    pub fn init() -> Self {
        let mut needs_restore = false;
        if let Ok(output) = Command::new("getenforce").output() {
            let status = String::from_utf8_lossy(&output.stdout);
            if status.trim().eq_ignore_ascii_case("Enforcing") {
                let _ = Command::new("setenforce").arg("0").output();
                needs_restore = true;
            }
        }
        Self { needs_restore }
    }
}

impl Drop for SeLinuxGuard {
    fn drop(&mut self) {
        if self.needs_restore {
            let _ = Command::new("setenforce").arg("1").output();
        }
    }
}
