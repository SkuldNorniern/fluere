use super::syslog::{self, Logger, Facility, Severity};

pub struct log(Logger);

impl Log{
    pub fn new() -> Self {
        let now = chrono::Local::now();
        let log_file_name = format!("log_{}.log", now.format("%Y%m%d%H%M%S"));
        let logger = match syslog::unix(Facility::LOG_USER, log_file_name) {
            Ok(logger) => logger,
            Err(e) => panic!("Failed to connect to syslog: {}", e),
        };
        Log(*logger)
    }
}
