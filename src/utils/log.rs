use super::syslog::{self, Logger, Facility, Severity};

pub struct log(Logger);

impl Log{
    pub fn new() -> Self {
        let logger = match syslog::unix(Facility::LOG_USER) {
            Ok(logger) => logger,
            Err(e) => panic!("Failed to connect to syslog: {}", e),
        };
        Log(*logger)
    }
}
