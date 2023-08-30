use dirs::cache_dir;

use std::path::{Path, PathBuf};
use std::env;

pub fn home_cache_path() -> PathBuf {
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
            cache_dir().unwrap()
        }
    };

    let path_config = path_base.join("fluere");
    path_config
}

