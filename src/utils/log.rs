use super::syslog::{self, Logger, Facility, Severity};
use std::fs::File;
use std::io::Write;
use chrono::prelude::*;

pub struct log(Logger);

impl Log{
    pub fn new() -> Self {
        let now = Local::now();
        let log_file = format!("./logs/{}.log", now.format("%Y-%m-%d_%H:%M:%S"));
        let file = File::create(log_file).expect("Unable to create log file");
        let logger = Logger::new(file, Facility::LOG_USER);
        Log(*logger)
    }

    pub fn log(&self, severity: Severity, message: &str) {
        if severity >= self.0.severity() {
            write!(self.0, "{}", message).expect("Unable to write to log file");
        }
    }
}
