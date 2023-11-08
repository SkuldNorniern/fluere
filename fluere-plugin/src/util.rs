use dirs::cache_dir;

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

pub fn home_cache_path() -> std::io::Result<PathBuf> {
    // Check for the SUDO_USER environment variable
    let sudo_user = env::var("SUDO_USER");

    let path_base = match sudo_user {
        Ok(user) => {
            // If SUDO_USER is set, construct the path using the user's home directory
            let user_home = format!("/home/{}", user);
            Path::new(&user_home).join(".cache")
        }
        Err(_) => {
            // If not running under sudo, just use the config_dir function as before
            match cache_dir() {
                Ok(dir) => dir,
                Err(_) => return Err(std::io::Error::new(std::io::ErrorKind::Other, "Operation not supported by the OS")),
            }
        }
    };

    let path_config = path_base.join("fluere");
    if !path_config.exists() {
        fs::create_dir_all(path_config.clone())?;
    }
    path_config
}
