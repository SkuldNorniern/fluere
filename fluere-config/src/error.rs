use std::fmt;
use std::path::PathBuf;

/// Everything that can go wrong loading or saving Fluere's configuration.
///
/// Configuration problems degrade to the default config rather than stopping
/// a capture, so these are reported and handled, never panicked on.
#[derive(Debug)]
pub enum ConfigError {
    /// The config file or its directory could not be read or written.
    Io(std::io::Error),
    /// The platform has no config directory to fall back on.
    NoConfigDirectory,
    /// A TOML config could not be parsed or rendered.
    Toml(String),
    /// A Tavra config could not be parsed.
    Tavra(String),
    /// The document parsed, but does not describe a Fluere config.
    Shape(String),
    /// The file's extension does not name a format Fluere reads.
    UnknownFormat(PathBuf),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "IO error: {error}"),
            Self::NoConfigDirectory => write!(f, "Could not determine the config directory"),
            Self::Toml(error) => write!(f, "Invalid TOML config: {error}"),
            Self::Tavra(error) => write!(f, "Invalid Tavra config: {error}"),
            Self::Shape(error) => write!(f, "Unexpected config structure: {error}"),
            Self::UnknownFormat(path) => write!(
                f,
                "Unsupported config format for {}: expected .tav or .toml",
                path.display()
            ),
        }
    }
}

impl std::error::Error for ConfigError {}

impl From<std::io::Error> for ConfigError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}
