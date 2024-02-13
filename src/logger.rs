use std::fs::File;
use std::io::{stderr, stdout, Write};
use std::path::PathBuf;

use chrono::Local; // Import the Local struct from the chrono crate
use log::{Level, Log, Metadata, Record};

pub enum Logstdout {
    Stdout,
    StdErr,
}

pub struct Logger {
    write_to_file: bool,
    write_to_std: Option<Logstdout>,
    severity: Level,
    file: Option<File>,
}

impl Logger {
    pub fn new(write_to_file: bool, file_path: Option<PathBuf>) -> Self {
        let mut path = file_path;
        if path.is_none() {
            path = Some(PathBuf::from(
                #[cfg(target_os = "linux")]
                "/var/log/fluere/fluere.log",
                #[cfg(target_os = "windows")]
                "C:\\Program Files\\fluere\\fluere.log",
                #[cfg(target_os = "macos")]
                "/Library/Logs/fluere/fluere.log",
                #[cfg(target_os = "bsd")]
                "/var/log/fluere/fluere.log",
                #[cfg(not(any(
                    target_os = "linux",
                    target_os = "windows",
                    target_os = "macos",
                    target_os = "bsd"
                )))]
                "/var/log/fluere/fluere.log",
            ));
        }
        let mut file = None;
        if write_to_file {
            file = Some(File::create(path.as_ref().unwrap()).unwrap());
        }
        Logger {
            write_to_file: true,
            write_to_std: None,
            severity: Level::Info,
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
        let timestamp = Local::now();

        if self.write_to_std.as_ref().is_some() && record.level() <= self.severity {
            match self.write_to_std.as_ref().unwrap() {
                Logstdout::Stdout => {
                    writeln!(
                        stdout(),
                        "[{}]: {}: {}",
                        timestamp,
                        record.level(),
                        record.args()
                    )
                    .unwrap();
                }
                Logstdout::StdErr => {
                    writeln!(
                        stderr(),
                        "[{}]: {}: {}",
                        timestamp,
                        record.level(),
                        record.args()
                    )
                    .unwrap();
                }
            }
        }

        if self.write_to_file {
            writeln!(
                self.file.as_ref().unwrap(),
                "[{}]: {}: {}",
                timestamp,
                record.level(),
                record.args()
            )
            .unwrap();
        }
    }

    fn flush(&self) {}
}
