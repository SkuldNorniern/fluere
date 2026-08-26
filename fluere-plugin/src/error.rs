use std::fmt;

use crate::downloader::DownloadError;

/// Everything that can go wrong while managing plugins.
///
/// A plugin is untrusted, optional code: failures here are reported to the
/// caller or logged and skipped, never turned into a panic that would take a
/// running capture down with it.
#[derive(Debug)]
pub enum PluginError {
    /// The Lua runtime rejected a script or a call into one.
    Lua(mlua::Error),
    /// Reading a plugin, or locating the plugin cache, failed.
    Io(std::io::Error),
    /// Fetching a plugin from its repository failed.
    Download(DownloadError),
    /// The worker is gone, so queued records cannot be delivered.
    WorkerStopped,
}

impl fmt::Display for PluginError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Lua(error) => write!(f, "Lua error: {}", error),
            Self::Io(error) => write!(f, "IO error: {}", error),
            Self::Download(error) => write!(f, "Plugin download error: {}", error),
            Self::WorkerStopped => write!(f, "Plugin worker is no longer running"),
        }
    }
}

impl std::error::Error for PluginError {}

impl From<mlua::Error> for PluginError {
    fn from(error: mlua::Error) -> Self {
        Self::Lua(error)
    }
}

impl From<std::io::Error> for PluginError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<DownloadError> for PluginError {
    fn from(error: DownloadError) -> Self {
        Self::Download(error)
    }
}
