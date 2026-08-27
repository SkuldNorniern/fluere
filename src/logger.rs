use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

use chrono::Local; // Import the Local struct from the chrono crate
use log::{Level, Log, Metadata, Record};

pub enum Logstdout {
    Stdout,
    StdErr,
}

pub struct Logger {
    pub write_to_file: bool,
    pub write_to_std: Option<Logstdout>,
    pub severity: Level,
    pub file: Option<File>,
}

/// Platform default location for the log file.
fn default_log_path() -> PathBuf {
    PathBuf::from(
        #[cfg(target_os = "windows")]
        "C:\\Program Files\\fluere\\fluere.log",
        #[cfg(target_os = "macos")]
        "/Library/Logs/fluere/fluere.log",
        #[cfg(not(any(target_os = "windows", target_os = "macos")))]
        "/var/log/fluere/fluere.log",
    )
}

impl Logger {
    pub fn new(
        file_path: Option<PathBuf>,
        severity: Option<Level>,
        write_to_std: Option<Logstdout>,
        write_to_file: bool,
    ) -> Self {
        let file = if write_to_file {
            Self::open_log_file(file_path)
        } else {
            None
        };

        Logger {
            write_to_file: file.is_some(),
            write_to_std,
            severity: severity.unwrap_or(Level::Info),
            file,
        }
    }

    /// Open the log file, creating its directory if it does not exist.
    ///
    /// Logging must never take the process down, so every failure here falls
    /// back to stderr-only logging. The directory is touched only when file
    /// logging was actually asked for: the default path lives under a system
    /// log directory that an unprivileged run cannot create.
    fn open_log_file(file_path: Option<PathBuf>) -> Option<File> {
        let path = file_path.unwrap_or_else(default_log_path);

        if let Some(parent) = path.parent()
            && let Err(error) = std::fs::create_dir_all(parent)
        {
            eprintln!(
                "fluere: cannot create log directory {}: {}. Logging to stderr only.",
                parent.display(),
                error
            );
            return None;
        }

        match File::create(&path) {
            Ok(file) => Some(file),
            Err(error) => {
                eprintln!(
                    "fluere: cannot create log file {}: {}. Logging to stderr only.",
                    path.display(),
                    error
                );
                None
            }
        }
    }

    // pub fn log(&mut self, severity: Level, message: &str) {
    // let timestamp = Local::now(); // Get the current timestamp using Local::now()
    // let log_message = format!("{:?} {}: {}", timestamp, severity, message); // Format the timestamp and append it to the log message
    // }
}

impl Log for Logger {
    fn enabled(&self, _metadata: &Metadata) -> bool {
        true
    }

    fn log(&self, record: &Record) {
        let to_std = self
            .write_to_std
            .as_ref()
            .filter(|_| record.level() <= self.severity);

        if to_std.is_none() && !self.write_to_file {
            // Nothing would be written, so nothing needs formatting. The
            // timestamp in particular is not free, and this runs for every
            // filtered-out message on the capture path.
            return;
        }

        let message = format!(
            "{} [{}] [{}:{}]: {}",
            Local::now().format("%Y-%m-%d %H:%M:%S %z"),
            record.level(),
            record.file().unwrap_or("unknown"),
            record.line().unwrap_or(0),
            record.args()
        );

        match to_std {
            Some(Logstdout::Stdout) => println!("{}", message),
            Some(Logstdout::StdErr) => eprintln!("{}", message),
            None => {}
        }

        if self.write_to_file
            && let Some(mut file_ref) = self.file.as_ref()
        {
            // A logger cannot report its own failure to log; drop the error.
            let _ = writeln!(file_ref, "{}", message);
        }
    }

    fn flush(&self) {}
}
