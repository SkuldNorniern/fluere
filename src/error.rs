use std::{fmt, io, path::PathBuf};

#[derive(Debug)]
pub enum ParseError {
    InvalidPacket,
    EmptyPacket,
    UnknownProtocol(u8),
    UnknownEtherType(String),
    UnknownDSCP(u8),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPacket => write!(f, "Invalid packet"),
            Self::EmptyPacket => write!(f, "Empty packet"),
            Self::UnknownProtocol(protocol) => write!(f, "Unknown protocol: {}", protocol),
            Self::UnknownEtherType(ether_type) => {
                write!(f, "Unknown ether type: {}", ether_type)
            }
            Self::UnknownDSCP(dscp) => write!(f, "Unknown dscp: {}", dscp),
        }
    }
}

#[derive(Debug)]
pub enum CaptureError {
    DeviceNotFound(String),
    InvalidDeviceIndex(usize),
    Interface(String),
    Pcap(pcap::Error),
}

impl fmt::Display for CaptureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DeviceNotFound(device) => write!(f, "Device not found: {}", device),
            Self::InvalidDeviceIndex(index) => write!(f, "Invalid device index: {}", index),
            Self::Interface(error) => write!(f, "Interface error: {}", error),
            Self::Pcap(error) => write!(f, "PCAP error: {}", error),
        }
    }
}

#[derive(Debug)]
pub enum ConfigError {
    Missing(String),
    InvalidValue { field: String, value: String },
    FileNotFound(PathBuf),
    Argument(String),
    Config(String),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing(name) => write!(f, "Required parameter missing: {}", name),
            Self::InvalidValue { field, value } => {
                write!(f, "Invalid value '{}' for field '{}'", value, field)
            }
            Self::FileNotFound(path) => write!(f, "File not found: {}", path.display()),
            Self::Argument(error) => write!(f, "Argument error: {}", error),
            Self::Config(error) => write!(f, "Configuration error: {}", error),
        }
    }
}

#[derive(Debug)]
pub enum FluereError {
    Io(io::Error),
    Parse(ParseError),
    Capture(CaptureError),
    Config(ConfigError),
    Plugin(String),
}

impl fmt::Display for FluereError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "IO error: {}", error),
            Self::Parse(error) => error.fmt(f),
            Self::Capture(error) => error.fmt(f),
            Self::Config(error) => error.fmt(f),
            Self::Plugin(error) => write!(f, "Plugin error: {}", error),
        }
    }
}

impl From<io::Error> for FluereError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<ParseError> for FluereError {
    fn from(error: ParseError) -> Self {
        Self::Parse(error)
    }
}

impl From<CaptureError> for FluereError {
    fn from(error: CaptureError) -> Self {
        Self::Capture(error)
    }
}

impl From<ConfigError> for FluereError {
    fn from(error: ConfigError) -> Self {
        Self::Config(error)
    }
}

impl From<pcap::Error> for CaptureError {
    fn from(error: pcap::Error) -> Self {
        Self::Pcap(error)
    }
}

impl From<pcap::Error> for FluereError {
    fn from(error: pcap::Error) -> Self {
        Self::Capture(CaptureError::Pcap(error))
    }
}

impl From<std::num::ParseIntError> for ConfigError {
    fn from(error: std::num::ParseIntError) -> Self {
        Self::Argument(error.to_string())
    }
}

pub trait OptionExt<T> {
    fn required(self, name: &str) -> Result<T, FluereError>;
}

impl<T> OptionExt<T> for Option<T> {
    fn required(self, name: &str) -> Result<T, FluereError> {
        self.ok_or_else(|| FluereError::Config(ConfigError::Missing(name.to_string())))
    }
}
