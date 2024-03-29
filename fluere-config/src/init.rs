use std::{default::Default, env, fs, path::Path, path::PathBuf};

use crate::Config;

use dirs::config_dir;

#[cfg(feature = "log")]
use log::{debug, error, warn};

impl Config {
    pub fn new() -> Self {
        let path_base = home_config_path();

        let path_file = path_base.join(Path::new("fluere.toml"));

        #[cfg(feature = "log")]
        debug!("Using config file from: {:?}", path_file);
        #[cfg(not(feature = "log"))]
        println!("Using config file from: {:?}", path_file);
        if !path_base.exists() {
            match fs::create_dir_all(&path_base) {
                Ok(_) => {
                    #[cfg(feature = "log")]
                    debug!("Created directory at {:?}", path_base);
                    ()
                }
                Err(e) => {
                    #[cfg(feature = "log")]
                    error!("Failed to create directory at {:?}: {}", path_base, e);
                    #[cfg(not(feature = "log"))]
                    eprintln!("Failed to create directory at {:?}: {}", path_base, e);

                    return Config::default();
                }
            }
        }

        if !path_file.exists() {
            Self::save(None, path_file.to_str().unwrap().to_string()).unwrap();
        }

        match Self::load(path_file.to_str().unwrap().to_string()) {
            Ok(config) => {
                #[cfg(feature = "log")]
                debug!("Loaded configuration from: {:?}", path_file);

                config
            }
            Err(_) => {
                #[cfg(feature = "log")]
                warn!("failed to load configuration, using default config");
                #[cfg(not(feature = "log"))]
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
            // on macOS just return the config_dir()
            if env::consts::OS == "macos" {
                config_dir().expect("Could not determine the home directory")
            } else {
                // If SUDO_USER is set, construct the path using the user's home directory
                let user_home = format!("/home/{}", user);
                Path::new(&user_home).join(".config")
            }
        }
        Err(_) => {
            // If not running under sudo, just use the config_dir function as before
            config_dir().expect("Could not determine the home directory")
        }
    };
    let path_config = path_base.join("fluere");
    path_config
}
