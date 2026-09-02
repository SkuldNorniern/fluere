//! Creating the files a run writes.

use std::fs::{self, File};
use std::path::Path;

use crate::FluereError;

/// Create the directory a run writes into, saying which one if that fails.
///
/// This is the first thing a run does and the first thing to fail on a
/// read-only working directory, where it used to report a bare "Permission
/// denied" with nothing to say what could not be created.
pub fn create_dir(path: impl AsRef<Path>) -> Result<(), FluereError> {
    let path = path.as_ref();

    fs::create_dir_all(path).map_err(|source| FluereError::Output {
        path: path.display().to_string(),
        source,
    })
}

/// Create an output file, saying which one if that fails.
///
/// `File::create` returns a bare `io::Error`, so a missing directory reads as
/// "No such file or directory" with nothing to say what was being written.
pub fn create(path: impl AsRef<Path>) -> Result<File, FluereError> {
    let path = path.as_ref();

    File::create(path).map_err(|source| FluereError::Output {
        path: path.display().to_string(),
        source,
    })
}
