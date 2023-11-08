use dirs::cache_dir;

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

pub fn home_cache_path() -> Result<PathBuf, std::io::Error> {
    // Check for the SUDO_USER environment variable
    let sudo_user = env::var("SUDO_USER");

    let path_base = match sudo_user {
        Ok(user) => {
            // on macOS just return the cache_dir()
            if env::consts::OS == "macos" {
                Ok(cache_dir().expect("Could not determine the home directory"))
            } else {
                // If SUDO_USER is set, construct the path using the user's home directory
                let user_home = format!("/home/{}", user);
                Ok(Path::new(&user_home).join(".cache"))
            }
        }
        Err(_) => {
            // If not running under sudo, just use the cache_dir function as before
            cache_dir().ok_or(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "Could not determine the cache directory",
            ))
        }
    };
    let path_cache = path_base?.join("fluere");
    if !path_cache.exists() {
        fs::create_dir_all(path_cache.clone())?;
    }
    Ok(path_cache)
}
