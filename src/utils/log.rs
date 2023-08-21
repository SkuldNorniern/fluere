use super::syslog::{self, Logger, Facility, Severity};
use std::fs::File;
use std::io::Write;
use chrono::Local;

pub struct Log {
    logger: Logger,
    level: Severity,
    file: File,
}

impl Log {
    pub fn new(level: Severity) -> Self {
        let logger = match syslog::unix(Facility::LOG_USER) {
            Ok(logger) => logger,
            Err(e) => panic!("Failed to connect to syslog: {}", e),
        };

        let file_name = format!("log_{}.txt", Local::now().format("%Y%m%d%H%M%S"));
        let file = File::create(file_name).expect("Unable to create log file");

        Log { logger, level, file }
    }

    pub fn debug(&self, message: &str) {
        if self.level <= Severity::LOG_DEBUG {
            writeln!(self.file, "DEBUG: {}", message).expect("Unable to write to log file");
            println!("DEBUG: {}", message);
        }
    }

    pub fn info(&self, message: &str) {
        if self.level <= Severity::LOG_INFO {
            writeln!(self.file, "INFO: {}", message).expect("Unable to write to log file");
            println!("INFO: {}", message);
        }
    }

    pub fn warn(&self, message: &str) {
        if self.level <= Severity::LOG_WARNING {
            writeln!(self.file, "WARN: {}", message).expect("Unable to write to log file");
            println!("WARN: {}", message);
        }
    }

    pub fn error(&self, message: &str) {
        if self.level <= Severity::LOG_ERR {
            writeln!(self.file, "ERROR: {}", message).expect("Unable to write to log file");
            println!("ERROR: {}", message);
        }
    }
}
