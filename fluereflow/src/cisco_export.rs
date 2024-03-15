use crate::netflow_v5::{NetFlowV5Header, NetFlowV5Record};
use crate::netflow_v9::{NetFlowV9FlowSet, NetFlowV9Header};
use std::io;
use std::net::UdpSocket;

pub fn export_netflow_data(version: u8, data: Vec<u8>, collector_address: &str) -> io::Result<()> {
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    match version {
        5 => {
            socket.send_to(&data, collector_address)?;
        }
        9 => {
            socket.send_to(&data, collector_address)?;
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Unsupported NetFlow version",
            ))
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{self, ErrorKind};

    #[test]
    fn test_export_netflow_v5_success() -> io::Result<()> {
        let data = vec![0; 100]; // Mocked data
        let collector_address = "127.0.0.1:9999"; // Mocked address
        assert!(export_netflow_data(5, data, collector_address).is_ok());
        Ok(())
    }

    #[test]
    fn test_export_netflow_v9_success() -> io::Result<()> {
        let data = vec![0; 100]; // Mocked data
        let collector_address = "127.0.0.1:9999"; // Mocked address
        assert!(export_netflow_data(9, data, collector_address).is_ok());
        Ok(())
    }

    #[test]
    fn test_export_netflow_invalid_version() -> io::Result<()> {
        let data = vec![0; 100]; // Mocked data
        let collector_address = "127.0.0.1:9999"; // Mocked address
        let result = export_netflow_data(10, data, collector_address);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), ErrorKind::InvalidInput);
        Ok(())
    }

    #[test]
    fn test_export_netflow_invalid_address() -> io::Result<()> {
        let data = vec![0; 100]; // Mocked data
        let collector_address = "256.256.256.256:9999"; // Invalid address
        let result = export_netflow_data(5, data, collector_address);
        assert!(result.is_err());
        Ok(())
    }
}
