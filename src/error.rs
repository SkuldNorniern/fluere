use std::io;
use pcap;
use crate::net::NetError;

#[derive(Debug)]
pub enum FluereError {
    // IO related errors
    IoError(io::Error),
    // Network related errors
    NetworkError(NetError),
    // PCAP related errors
    PcapError(pcap::Error),
    // Parsing related errors
    ParseError(String),
    // Configuration related errors
    ConfigError(String),
    // Interface related errors
    InterfaceError(String),
    // Argument related errors
    ArgumentError(String),
}

impl std::error::Error for FluereError {}

impl std::fmt::Display for FluereError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FluereError::IoError(e) => write!(f, "IO error: {}", e),
            FluereError::NetworkError(e) => write!(f, "Network error: {}", e),
            FluereError::PcapError(e) => write!(f, "PCAP error: {}", e),
            FluereError::ParseError(e) => write!(f, "Parse error: {}", e),
            FluereError::ConfigError(e) => write!(f, "Configuration error: {}", e),
            FluereError::InterfaceError(e) => write!(f, "Interface error: {}", e),
            FluereError::ArgumentError(e) => write!(f, "Argument error: {}", e),
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

// Helper methods for creating errors
impl FluereError {
    pub fn interface_not_found() -> Self {
        FluereError::InterfaceError("Network interface not found".to_string())
    }

    pub fn argument_error<T: std::fmt::Display>(msg: T) -> Self {
        FluereError::ArgumentError(msg.to_string())
    }

    pub fn config_error<T: std::fmt::Display>(msg: T) -> Self {
        FluereError::ConfigError(msg.to_string())
    }

    pub fn parse_error<T: std::fmt::Display>(msg: T) -> Self {
        FluereError::ParseError(msg.to_string())
    }
} 