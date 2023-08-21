use super::syslog::{self, Logger, Facility, Severity};
use chrono::prelude::*;

pub struct Log {
    logger: Logger,
    level: Severity,
}

impl Log {
    pub fn new(level: Severity) -> Self {
        let timestamp = Utc::now().format("%Y%m%d%H%M%S").to_string();
        let logger = match syslog::unix(Facility::LOG_USER, format!("log_{}", timestamp)) {
            Ok(logger) => logger,
            Err(e) => panic!("Failed to connect to syslog: {}", e),
        };
        Log { logger, level }
    }

    pub fn log(&self, level: Severity, message: &str) {
        if level <= self.level {
            self.logger.log(level, message);
        }
    }
}
