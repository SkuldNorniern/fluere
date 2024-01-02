use dirs::cache_dir;

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

pub fn home_cache_path() -> Result<PathBuf, std::io::Error> {
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
            cache_dir().ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "Failed to find cache directory",
                )
            })?
        }
    };

    let path_config = path_base.join("fluere");
    if !path_config.exists() {
        fs::create_dir_all(path_config.clone())?;
    }
    Ok(path_config)
}
