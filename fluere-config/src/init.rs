use std::{fs, path::Path, path::PathBuf};

use dirs::config_dir;

use crate::error::ConfigError;
use crate::{tav, Config};

#[cfg(feature = "log")]
use log::{debug, warn};

/// Config file names Fluere looks for, in preference order. Tavra first: it is
/// the format new installs get written in, and TOML stays readable for anyone
/// who already has one.
const CONFIG_FILES: [&str; 2] = ["fluere.tav", "fluere.toml"];

/// The format a config file is written in, decided by its extension.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Format {
    Tavra,
    Toml,
}

impl Format {
    fn of(path: &Path) -> Result<Self, ConfigError> {
        match path.extension().and_then(|extension| extension.to_str()) {
            Some("tav") => Ok(Format::Tavra),
            Some("toml") => Ok(Format::Toml),
            _ => Err(ConfigError::UnknownFormat(path.to_path_buf())),
        }
    }
}

/// Report a configuration problem without stopping the caller.
macro_rules! config_warn {
    ($($arg:tt)*) => {{
        #[cfg(feature = "log")]
        warn!($($arg)*);
        #[cfg(not(feature = "log"))]
        eprintln!($($arg)*);
    }};
}

impl Config {
    /// Load the user's configuration, falling back to the default on any
    /// problem. A missing, unreadable, or malformed config never stops Fluere
    /// from running: it is reported and the defaults are used.
    pub fn new() -> Self {
        match Self::load_from_config_dir() {
            Ok(config) => config,
            Err(error) => {
                config_warn!("Using the default configuration: {}", error);
                Config::default()
            }
        }
    }

    /// Find the config file in the user's config directory, creating a default
    /// one if none of the supported names exist yet.
    fn load_from_config_dir() -> Result<Self, ConfigError> {
        Self::load_from_dir(&home_config_path()?)
    }

    /// Load the config out of `directory`, writing a default one if none of the
    /// supported file names is present.
    pub fn load_from_dir(directory: &Path) -> Result<Self, ConfigError> {
        if !directory.exists() {
            fs::create_dir_all(directory)?;
            #[cfg(feature = "log")]
            debug!("Created config directory at {}", directory.display());
        }

        for name in CONFIG_FILES {
            let path = directory.join(name);
            if path.exists() {
                #[cfg(feature = "log")]
                debug!("Using config file from: {}", path.display());

                return Self::load(&path);
            }
        }

        // Nothing there yet: write the defaults so the file is available to edit.
        let path = directory.join(CONFIG_FILES[0]);
        #[cfg(feature = "log")]
        debug!("Writing a default config to {}", path.display());

        Self::save(None, &path)?;
        Self::load(&path)
    }

    /// Read a config file, choosing the parser from its extension.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let contents = fs::read_to_string(path)?;

        match Format::of(path)? {
            Format::Tavra => tav::from_str(&contents),
            Format::Toml => {
                toml::from_str(&contents).map_err(|error| ConfigError::Toml(error.to_string()))
            }
        }
    }

    /// Write `content` (or the defaults) to `path`, choosing the format from
    /// its extension.
    pub fn save(content: Option<Config>, path: &Path) -> Result<(), ConfigError> {
        let config = content.unwrap_or_default();

        let contents = match Format::of(path)? {
            Format::Tavra => tav::to_string(&config),
            Format::Toml => {
                toml::to_string(&config).map_err(|error| ConfigError::Toml(error.to_string()))?
            }
        };

        fs::write(path, contents)?;
        Ok(())
    }
}

/// The directory Fluere keeps its config in.
///
/// Under `sudo` this resolves the invoking user's directory rather than root's,
/// so a privileged capture still reads the config the user actually edits.
fn home_config_path() -> Result<PathBuf, ConfigError> {
    // Under `sudo` this resolves the invoking user's directory rather than
    // root's, so a privileged capture reads the config that user actually
    // edits.
    let base = match crate::home::sudo_user_home() {
        Some(home) => home.join(".config"),
        None => config_dir().ok_or(ConfigError::NoConfigDirectory)?,
    };

    Ok(base.join("fluere"))
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::types::Plugin;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "fluere-config-test-{}-{}",
                tag,
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&path);
            TempDir(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn sample() -> Config {
        let mut config = Config::default();
        config.plugins.insert(
            "owner/plugin".to_string(),
            Plugin {
                enabled: true,
                path: Some("/plugins/here".to_string()),
                extra_arguments: None,
            },
        );
        config
    }

    #[test]
    fn a_first_run_writes_a_default_tavra_config() {
        let dir = TempDir::new("first-run");

        let config = Config::load_from_dir(&dir.0).expect("first run succeeds");

        assert!(config.plugins.is_empty());
        assert!(
            dir.0.join("fluere.tav").exists(),
            "a new install should get a .tav config"
        );
    }

    #[test]
    fn an_existing_tavra_config_is_loaded() {
        let dir = TempDir::new("load-tav");
        fs::create_dir_all(&dir.0).expect("temp dir");
        Config::save(Some(sample()), &dir.0.join("fluere.tav")).expect("save");

        let config = Config::load_from_dir(&dir.0).expect("load");
        assert_eq!(config.plugins.len(), 1);
        assert!(config.plugins["owner/plugin"].enabled);
    }

    #[test]
    fn an_existing_toml_config_still_works() {
        let dir = TempDir::new("load-toml");
        fs::create_dir_all(&dir.0).expect("temp dir");
        Config::save(Some(sample()), &dir.0.join("fluere.toml")).expect("save");

        let config = Config::load_from_dir(&dir.0).expect("load");
        assert_eq!(
            config.plugins["owner/plugin"].path.as_deref(),
            Some("/plugins/here")
        );
        assert!(
            !dir.0.join("fluere.tav").exists(),
            "an existing TOML config must not be replaced"
        );
    }

    #[test]
    fn tavra_wins_when_both_files_exist() {
        let dir = TempDir::new("both");
        fs::create_dir_all(&dir.0).expect("temp dir");

        Config::save(Some(sample()), &dir.0.join("fluere.tav")).expect("save tav");
        Config::save(Some(Config::default()), &dir.0.join("fluere.toml")).expect("save toml");

        let config = Config::load_from_dir(&dir.0).expect("load");
        assert_eq!(config.plugins.len(), 1, "the .tav file should be preferred");
    }

    #[test]
    fn a_malformed_config_is_an_error_not_a_panic() {
        let dir = TempDir::new("malformed");
        fs::create_dir_all(&dir.0).expect("temp dir");
        fs::write(dir.0.join("fluere.tav"), "plugins = {{{").expect("write");

        assert!(Config::load_from_dir(&dir.0).is_err());
    }

    #[test]
    fn an_unknown_extension_is_rejected() {
        let path = PathBuf::from("/tmp/fluere.yaml");
        assert!(matches!(
            Config::save(None, &path),
            Err(ConfigError::UnknownFormat(_))
        ));
    }
}
