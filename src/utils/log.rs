use super::syslog::{self, Logger, Facility, Severity};

pub struct log {
    logger: Logger,
    log_file: File,
}

impl Log{
    pub fn new() -> Self {
        let logger = match syslog::unix(Facility::LOG_USER) {
            Ok(logger) => logger,
            Err(e) => panic!("Failed to connect to syslog: {}", e),
        };
        let log_file = File::create(format!("log_{}.txt", Local::now().format("%Y%m%d%H%M%S"))).unwrap();
        Log {
            logger: *logger,
            log_file,
        }
    }

    pub fn log(&mut self, level: Severity, message: &str) {
        if level >= self.logger.min_severity() {
            writeln!(self.log_file, "[{}] {}", level, message).unwrap();
        }
    }
}
