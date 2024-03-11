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
    pub fn new(file_path: Option<PathBuf>, severity: Option<Level>, write_to_std: Option<Logstdout>, write_to_file: bool) -> Self {
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

        // check if there is a file at the path and create it if it doesn't exist
        if path.as_ref().unwrap().parent().is_some() {
            std::fs::create_dir_all(path.as_ref().unwrap().parent().unwrap()).unwrap();
        }
            

        if write_to_file {
            file = Some(File::create(path.as_ref().unwrap()).unwrap());
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
        let timestamp = Local::now();
        let formatted_message = format!("{} [{}]: {}", timestamp, record.level(), record.args());
        
        if self.write_to_std.as_ref().is_some() && record.level() <= self.severity {
            match self.write_to_std.as_ref().unwrap() {
                Logstdout::Stdout => {
                    println!("{}", formatted_message);
                }
                Logstdout::StdErr => {
                    eprintln!("{}", formatted_message);
                }
            }
        }

        if self.write_to_file {
            writeln!(self.file.as_ref().unwrap(), "{}", formatted_message).unwrap();
        }
    }

    fn flush(&self) {}
}
