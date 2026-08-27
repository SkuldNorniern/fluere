use dirs::cache_dir;

use std::fs;
use std::path::PathBuf;

/// Where downloaded plugins are cached.
///
/// Under `sudo` this resolves the invoking user's directory rather than root's,
/// so a privileged capture uses the same cache the user's own runs do.
pub fn home_cache_path() -> Result<PathBuf, std::io::Error> {
    let base = match fluere_config::sudo_user_home() {
        Some(home) => fluere_config::cache_dir_in(&home),
        None => cache_dir().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "Failed to find cache directory",
            )
        })?,
    };

    let path = base.join("fluere");
    if !path.exists() {
        fs::create_dir_all(&path)?;
    }

    Ok(path)
}
