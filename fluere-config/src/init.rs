use dirs::home_dir;



use crate::{Config};


use std::{default::Default, fs, path::Path, path::PathBuf};


impl Config {
    pub fn new(_name: &str, _version: &str) -> Self {
        let path_base = home_config_path();

        let path_file = path_base.join(Path::new("pacify.toml"));

        if !path_base.exists() {
            fs::create_dir_all(path_base).unwrap();
        }

        if !path_file.exists() {
            Self::save(None, path_file.to_str().unwrap().to_string()).unwrap();
        }

        match Self::load(path_file.to_str().unwrap().to_string()) {
            Ok(config) => config,
            Err(_) => {
                println!("failed to load configuration, using default config");
                Config::default()
            }
        }
    }

    pub fn load(path: String) -> Result<Self, std::io::Error> {
        let path = Path::new(&path);
        let contents = fs::read_to_string(path)?;
        let config = toml::from_str(&contents).expect("failed to parse config");
        Ok(config)
    }

    pub fn save(content: Option<Config>, path: String) -> Result<(), std::io::Error> {
        let path = Path::new(&path);
        let contents = match content {
            Some(config) => toml::to_string(&config).unwrap(),
            None => toml::to_string(&Config::default()).unwrap(),
        };
        fs::write(path, contents)?;
        Ok(())
    }
}

fn home_config_path() -> PathBuf {
    let path_base = home_dir().unwrap();
    #[cfg(target_os = "windows")]
    let path_config = path_base.join("AppData").join("Roaming").join("pacify");
    #[cfg(target_os = "macos")]
    let path_config = path_base.join(".config").join("pacify");
    #[cfg(target_os = "linux")]
    let path_config = path_base.join(".config").join("pacify");
    path_config
}
