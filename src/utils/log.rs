use super::syslog::{self, Logger, Facility, Severity};
use chrono::prelude::*;

pub struct Log {
    logger: Logger,
    level: Severity,
}

impl Log {
    pub fn new(level: Severity) -> Self {
        Log { logger: Logger::new(), level }
    }

    pub fn log(&self, level: Severity, message: &str) {
        if level <= self.level {
            self.logger.log(level, message);
        }
    }
}
