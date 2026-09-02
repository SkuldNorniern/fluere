//! Creating the files a run writes.

use std::fs::File;
use std::path::Path;

use crate::FluereError;

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
