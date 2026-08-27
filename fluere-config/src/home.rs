//! Finding the invoking user's home directory.
//!
//! Fluere needs elevated privileges to capture, so it is usually run under
//! `sudo`. The config and plugin caches belong to the user who invoked it, not
//! to root, or every `sudo fluere` would read a different configuration from
//! the one that user edits.

use std::env;
use std::path::{Path, PathBuf};

/// The home directory of the user who invoked a `sudo` session.
///
/// `None` when not running under `sudo`, or when the user cannot be resolved.
///
/// The home directory is read from the passwd database rather than assumed to
/// be `/home/<user>`: macOS puts them under `/Users`, and service accounts and
/// non-default layouts are common enough elsewhere that guessing is wrong more
/// often than it looks.
pub fn sudo_user_home() -> Option<PathBuf> {
    let user = env::var("SUDO_USER").ok()?;
    passwd_home(&user).or_else(|| conventional_home(&user))
}

/// Look the user up in the local passwd database.
///
/// This misses users provided by a directory service, which is what
/// `conventional_home` is the fallback for.
fn passwd_home(user: &str) -> Option<PathBuf> {
    let passwd = std::fs::read_to_string("/etc/passwd").ok()?;

    passwd.lines().find_map(|line| {
        let mut fields = line.split(':');
        (fields.next()? == user)
            .then(|| fields.nth(4))
            .flatten()
            .filter(|home| !home.is_empty())
            .map(PathBuf::from)
    })
}

/// The config directory belonging to `home`.
///
/// Mirrors what `dirs::config_dir` would return for that user, so a privileged
/// run and an unprivileged one read the same file rather than diverging on
/// macOS, where the two places are different.
pub fn config_dir_in(home: &Path) -> PathBuf {
    if cfg!(target_os = "macos") {
        home.join("Library").join("Application Support")
    } else if cfg!(windows) {
        home.join("AppData").join("Roaming")
    } else {
        home.join(".config")
    }
}

/// The cache directory belonging to `home`, on the same reasoning.
pub fn cache_dir_in(home: &Path) -> PathBuf {
    if cfg!(target_os = "macos") {
        home.join("Library").join("Caches")
    } else if cfg!(windows) {
        home.join("AppData").join("Local")
    } else {
        home.join(".cache")
    }
}

/// Where a home directory usually lives, when the database has nothing to say.
fn conventional_home(user: &str) -> Option<PathBuf> {
    let root = if cfg!(target_os = "macos") {
        "/Users"
    } else {
        "/home"
    };

    Some(PathBuf::from(root).join(user))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_user_falls_back_to_the_usual_place() {
        // A name that cannot be in the passwd database.
        let home = conventional_home("nobody-with-this-name").expect("a fallback");

        assert!(home.ends_with("nobody-with-this-name"));
        assert!(home.is_absolute());
    }

    /// The database is authoritative where it has an answer, which is what
    /// makes non-default layouts work.
    #[test]
    fn root_is_read_from_the_passwd_database() {
        let Some(home) = passwd_home("root") else {
            // No /etc/passwd, or no root entry: nothing to assert.
            return;
        };

        assert!(home.is_absolute(), "got {}", home.display());
        assert!(
            !home.starts_with("/home/"),
            "root's home came from the database, not the /home guess: {}",
            home.display()
        );
    }

    /// A privileged run must land on the same file an unprivileged one would,
    /// which means following the platform rather than always using `.config`.
    #[test]
    fn the_config_directory_follows_the_platform() {
        let home = PathBuf::from("/home/someone");
        let config = config_dir_in(&home);

        assert!(config.starts_with(&home));
        if cfg!(target_os = "macos") {
            assert!(config.ends_with("Library/Application Support"));
        } else if cfg!(windows) {
            assert!(config.ends_with("AppData/Roaming"));
        } else {
            assert!(config.ends_with(".config"));
        }
    }

    #[test]
    fn a_user_absent_from_the_database_is_not_invented() {
        assert_eq!(passwd_home("no-such-user-exists-here"), None);
    }
}
