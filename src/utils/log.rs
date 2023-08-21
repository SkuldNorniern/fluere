use log::{info, LevelFilter};
use log4rs::{
    append::file::FileAppender,
    config::{Appender, Config, Root},
    encode::pattern::PatternEncoder,
};

pub struct Log;

impl Log {
    pub fn new() -> Self {
        let logfile = format!("./logs/{}.log", chrono::Local::now().format("%Y-%m-%d_%H:%M:%S"));
        let file_appender = FileAppender::builder()
            .encoder(Box::new(PatternEncoder::new("{d} {l} - {m}{n}")))
            .build(logfile)
            .unwrap();

        let config = Config::builder()
            .appender(Appender::builder().build("file_appender", Box::new(file_appender)))
            .build(
                Root::builder()
                    .appender("file_appender")
                    .build(LevelFilter::Info),
            )
            .unwrap();

        log4rs::init_config(config).unwrap();
        Log
    }
}