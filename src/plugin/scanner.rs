use std::fs;

pub fn scan_plugins(folder: &str) -> Vec<String> {
    let mut plugins = vec![];
    let entries = match fs::read_dir(folder) {
        Ok(entries) => entries,
        Err(e) => {
            println!("Error reading plugins folder: {e}");
            return plugins;
        }
    };

    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(e) => {
                println!("Error reading plugin: {e}");
                continue;
            }
        };
        let path = entry.path();
        let ext = match path.extension() {
            Some(ext) => ext,
            None => continue,
        };
        let ext = ext.to_str().unwrap();
        if ext != "lua" && ext != "py" && ext != "nkl" && ext != "rs" && ext != "dll" {
            continue;
        }
        let plugin = match path.to_str() {
            Some(s) => s.to_owned(),
            None => continue,
        };
        plugins.push(plugin);
    }

    plugins
}
