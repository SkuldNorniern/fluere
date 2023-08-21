use std::fs::File;
use std::io::Write;
use std::path::Path;

pub struct Log {
    file: File,
}

impl Log {
    #[cfg(target_os = "linux")]
    pub fn new() -> Self {
        let path = "/var/log/fluere/fluere.log";
        let file = File::create(&path).expect("Failed to create log file");
        Log { file }
    }

    #[cfg(target_os = "windows")]
    pub fn new() -> Self {
        let path = "C:\\Program Files\\fluere\\fluere.log";
        let file = File::create(&path).expect("Failed to create log file");
        Log { file }
    }

    #[cfg(target_os = "macos")]
    pub fn new() -> Self {
        let path = "/Library/Logs/fluere/fluere.log";
        let file = File::create(&path).expect("Failed to create log file");
        Log { file }
    }

    #[cfg(target_os = "bsd")]
    pub fn new() -> Self {
        let path = "/var/log/fluere/fluere.log";
        let file = File::create(&path).expect("Failed to create log file");
        Log { file }
    }

    pub fn log(&mut self, severity: Severity, message: &str) {
        let log_message = format!("{:?}: {}", severity, message);
        self.file.write_all(log_message.as_bytes()).expect("Failed to write to log file");
    }
}
