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

impl Logger {
    pub fn new(
        file_path: Option<PathBuf>,
        severity: Option<Level>,
        write_to_std: Option<Logstdout>,
        write_to_file: bool,
    ) -> Self {
        let mut path = file_path;
        if path.is_none() {
            path = Some(PathBuf::from(
                #[cfg(target_os = "linux")]
                "/var/log/fluere/fluere.log",
                #[cfg(target_os = "windows")]
                "C:\\Program Files\\fluere\\fluere.log",
                #[cfg(target_os = "macos")]
                "/Library/Logs/fluere/fluere.log",
                #[cfg(target_os = "freebsd")]
                "/var/log/fluere/fluere.log",
                #[cfg(not(any(
                    target_os = "linux",
                    target_os = "windows",
                    target_os = "macos",
                    target_os = "freebsd"
                )))]
                "/var/log/fluere/fluere.log",
            ));
        }
        let mut file = None;

        // check if there is a file at the path and create it if it doesn't exist
        if let Some(path_ref) = path.as_ref() {
            if let Some(parent) = path_ref.parent() {
                std::fs::create_dir_all(parent).expect("Failed to create log directory");
            }
        }

        if write_to_file {
            file = Some(
                File::create(path.as_ref().expect("Log path not set"))
                    .expect("Failed to create log file"),
            );
        }
        Logger {
            write_to_file: false,
            write_to_std,
            severity: severity.unwrap_or(Level::Info),
            file,
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
        let _timestamp = Local::now().format("%Y-%m-%d %H:%M:%S %z").to_string();
        let formatted_message = format!(
            "[{}] [{}:{}]: {}",
            record.level(),
            record.file().unwrap_or("unknown"),
            record.line().unwrap_or(0),
            record.args()
        );

        if let Some(write_to_std) = self.write_to_std.as_ref() {
            if record.level() <= self.severity {
                match write_to_std {
                    Logstdout::Stdout => {
                        println!("{}", formatted_message);
                    }
                    Logstdout::StdErr => {
                        eprintln!("{}", formatted_message);
                    }
                }
            }
        }

        if self.write_to_file {
            if let Some(mut file_ref) = self.file.as_ref() {
                writeln!(file_ref, "{}", formatted_message).expect("Failed to write to log file");
            }
        }
    }

    fn flush(&self) {}
}
