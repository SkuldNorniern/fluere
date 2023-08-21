use std::fs::File;
use std::io::Write;
use chrono::prelude::*;
use log::{self, LevelFilter, SetLoggerError, Record};

pub struct Log {
    level: LevelFilter,
    log_file: File,
}

impl Log {
    pub fn new(level: LevelFilter) -> Result<Self, SetLoggerError> {
        let dt = Local::now();
        let log_file = File::create(format!("log_{}.txt", dt.format("%Y-%m-%d_%H-%M-%S"))).unwrap();
        log::set_boxed_logger(Box::new(Self { level, log_file }))?;
        log::set_max_level(level);
        Ok(())
    }
}

impl log::Log for Log {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        metadata.level() <= self.level
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            writeln!(self.log_file, "{} - {}", record.level(), record.args()).unwrap();
        }
    }

    fn flush(&self) {}
}
