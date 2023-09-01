use dirs::config_dir;

use crate::Config;

use std::{default::Default, env, fs, path::Path, path::PathBuf};

impl Config {
    pub fn new() -> Self {
        let path_base = home_config_path();

        let path_file = path_base.join(Path::new("fluere.toml"));
        println!("path_file: {:?}", path_file);
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
    // Check for the SUDO_USER environment variable
    let sudo_user = env::var("SUDO_USER");

    let path_base = match sudo_user {
        Ok(user) => {
            // If SUDO_USER is set, construct the path using the user's home directory
            let user_home = format!("/home/{}", user);
            Path::new(&user_home).join(".config")
        }
        Err(_) => {
            // If not running under sudo, just use the config_dir function as before
            config_dir().unwrap()
        }
    };

    let path_config = path_base.join("fluere");
    path_config
}
