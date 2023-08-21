use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::env;

pub struct Log {
    file: std::fs::File,
}

impl Log {
    pub fn new() -> Self {
        let mut path = env::current_exe().unwrap();
        path.pop(); // remove the executable name
        if cfg!(target_os = "linux") {
            path = PathBuf::from("/var/log/fluere/");
        }
        path.push("fluere.log");
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .append(true)
            .open(path)
            .unwrap();
        Log { file }
    }

    pub fn log(&mut self, level: &str, message: &str) {
        writeln!(self.file, "[{}] {}", level, message).unwrap();
    }
}
