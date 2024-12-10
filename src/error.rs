use crate::net::NetError;
use std::{io, path::PathBuf};

#[derive(Debug)]
pub enum FluereError {
    IoError(io::Error),
    NetworkError(NetError),
    PcapError(pcap::Error),
    ParseError(String),
    ConfigError(String),
    InterfaceError(String),
    ArgumentError(String),
    // Add new variants
    FileNotFound(PathBuf),
    ParameterMissing(String),
    InvalidValue { field: String, value: String },
}

impl std::fmt::Display for FluereError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IoError(e) => write!(f, "IO error: {}", e),
            Self::NetworkError(e) => write!(f, "Network error: {}", e),
            Self::PcapError(e) => write!(f, "PCAP error: {}", e),
            Self::ParseError(e) => write!(f, "Parse error: {}", e),
            Self::ConfigError(e) => write!(f, "Configuration error: {}", e),
            Self::InterfaceError(e) => write!(f, "Interface error: {}", e),
            Self::ArgumentError(e) => write!(f, "Argument error: {}", e),
            Self::FileNotFound(path) => write!(f, "File not found: {}", path.display()),
            Self::ParameterMissing(name) => write!(f, "Required parameter missing: {}", name),
            Self::InvalidValue { field, value } => {
                write!(f, "Invalid value '{}' for field '{}'", value, field)
            }
        }
    }
}

// Implement conversions from other error types
impl From<io::Error> for FluereError {
    fn from(error: io::Error) -> Self {
        FluereError::IoError(error)
    }
}

impl From<pcap::Error> for FluereError {
    fn from(error: pcap::Error) -> Self {
        FluereError::PcapError(error)
    }
}

impl From<NetError> for FluereError {
    fn from(error: NetError) -> Self {
        FluereError::NetworkError(error)
    }
}

impl From<std::num::ParseIntError> for FluereError {
    fn from(error: std::num::ParseIntError) -> Self {
        FluereError::ParseError(error.to_string())
    }
}

// Add conversion for Option to Result
pub trait OptionExt<T> {
    fn required(self, name: &str) -> Result<T, FluereError>;
}

impl<T> OptionExt<T> for Option<T> {
    fn required(self, name: &str) -> Result<T, FluereError> {
        self.ok_or_else(|| FluereError::ParameterMissing(name.to_string()))
    }
}
