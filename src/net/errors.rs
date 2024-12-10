use std::{io, path::PathBuf};

#[derive(Debug)]
pub enum NetError {
    EmptyPacket,
    UnknownProtocol { protocol: String },
    UnknownIPVersion { version: String },
    UnknownDSCP { dscp: u8 },
    DeviceNotFound { name: String },
    CaptureError { msg: String },
    PacketParseError { msg: String },
    PluginError { msg: String },
    FileError { path: PathBuf },
    InterfaceError { msg: String },
    // Add new variants for parameter errors
    ParameterError { name: String, msg: String },
    IoError(io::Error),
    ParseError { value: String, type_name: String },
}

impl std::fmt::Display for NetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyPacket => write!(f, "Unexpected empty packet"),
            Self::UnknownProtocol { protocol } => write!(f, "Unknown protocol `{}`", protocol),
            Self::UnknownIPVersion { version } => write!(f, "Unknown IP version `{}`", version),
            Self::UnknownDSCP { dscp } => write!(f, "Unexpected DSCP value `{}`", dscp),
            Self::DeviceNotFound { name } => write!(f, "Network device not found: {}", name),
            Self::CaptureError { msg } => write!(f, "Capture error: {}", msg),
            Self::PacketParseError { msg } => write!(f, "Packet parse error: {}", msg),
            Self::PluginError { msg } => write!(f, "Plugin error: {}", msg),
            Self::FileError { path } => write!(f, "File operation error: {}", path.display()),
            Self::InterfaceError { msg } => write!(f, "Interface error: {}", msg),
            Self::ParameterError { name, msg } => write!(f, "Parameter '{}' error: {}", name, msg),
            Self::IoError(e) => write!(f, "IO error: {}", e),
            Self::ParseError { value, type_name } => {
                write!(f, "Failed to parse '{}' as {}", value, type_name)
            }
        }
    }
}

impl From<io::Error> for NetError {
    fn from(error: io::Error) -> Self {
        NetError::IoError(error)
    }
}

impl From<std::num::ParseIntError> for NetError {
    fn from(error: std::num::ParseIntError) -> Self {
        NetError::ParseError {
            value: error.to_string(),
            type_name: "integer".to_string(),
        }
    }
}
