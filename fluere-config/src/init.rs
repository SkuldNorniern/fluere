use dirs::config_dir;

use crate::Config;

use std::{default::Default, env, fs, os, path::Path, path::PathBuf};

impl Config {
    pub fn new() -> Self {
        let path_base = home_config_path();

        let path_file = path_base.join(Path::new("fluere.toml"));
        println!("path_file: {:?}", path_file);
        if !path_base.exists() {
            match fs::create_dir_all(&path_base) {
                Ok(_) => (),
                Err(e) => {
                    eprintln!("Failed to create directory at {:?}: {}", path_base, e);
                    return Config::default();
                }
            }
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
    if cfg!(target_os = "linux") {
        let uid = unsafe { libc::getuid() };
        if uid == 0 {
            let sudo_user = env::var("SUDO_USER").expect("Failed to get SUDO_USER");
            let user_home = format!("/home/{}", sudo_user);
            return Path::new(&user_home).join(".config").join("fluere");
        }
        return Path::new("/root").join(".config").join("fluere");
    } else if cfg!(target_os = "windows") {
        if let Some(config_dir) = dirs::config_dir() {
            return config_dir.join("fluere");
        }
    } else if cfg!(target_os = "macos") {
        if let Some(home_dir) = dirs::home_dir() {
            return home_dir.join(".config").join("fluere");
        }
    } else {
        if let Some(home_dir) = dirs::home_dir() {
            return home_dir.join(".config").join("fluere");
        }
    }
    panic!("Unsupported operating system");
}
