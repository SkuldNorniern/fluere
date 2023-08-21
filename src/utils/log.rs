use super::syslog::{self, Logger, Facility, Severity};
use std::fs::File;
use std::io::Write;
use chrono::prelude::*;

pub struct Log {
    logger: Logger,
    log_level: Severity,
}

impl Log {
    pub fn new(log_level: Severity) -> Self {
        let now = Local::now();
        let log_file = format!("./logs/{}.log", now.format("%Y-%m-%d_%H:%M:%S"));
        let file = File::create(log_file).expect("Unable to create log file");
        let logger = Logger::new(file, Facility::LOG_USER);
        Log { logger, log_level }
    }

    pub fn log(&self, message: &str, severity: Severity) {
        if severity >= self.log_level {
            self.logger.log(severity, message);
        }
    }
}
