use std::fs;
use std::path::Path;
use std::ffi::OsStr;
use std::io;

pub fn scan_directory(dir: &str) -> io::Result<Vec<String>> {
    let entries = fs::read_dir(dir)?;
    let plugins = entries.filter_map(|entry| {
        let entry = entry.ok()?;
        let path = entry.path();
        if path.is_file() && path.extension() == Some(OsStr::new("rs")) {
            Some(path.file_name()?.to_str()?.to_string())
        } else {
            None
        }
    }).collect::<Vec<String>>();
    Ok(plugins)
}

