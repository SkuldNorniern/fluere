use log::{self, LevelFilter};
use simplelog::{FileLogger, Config};

pub struct Log(FileLogger);

impl Log{
    pub fn new() -> Self {
        let logger = match FileLogger::new(
            format!("/var/log/fluere/{}.log", chrono::Local::now().format("%Y-%m-%d_%H:%M:%S")),
            Config::default(),
            LevelFilter::Info,
        ) {
            Ok(logger) => logger,
            Err(e) => panic!("Failed to create log file: {}", e),
        };
        Log(logger)
    }
}
