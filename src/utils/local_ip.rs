use if_addrs::get_if_addrs;
use std::io;

pub fn get_local_ip(subnet: Option<(String, u32)>) -> io::Result<String> {
    let interfaces = get_if_addrs()?;
    for interface in interfaces {
        if interface.is_loopback() || !interface.ip().is_ipv4() {
            continue;
        }
        if let Some(subnet) = subnet {
            if is_ip_in_subnet(&interface.ip().to_string(), subnet) {
                return Ok(interface.ip().to_string());
            }
        } else {
            return Ok(interface.ip().to_string());
        }
    }
    Err(io::Error::new(io::ErrorKind::Other, "Failed to retrieve local IP address"))
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_parse_subnet() {
        // Add test cases for parse_subnet function
    }
    
    #[test]
    fn test_is_ip_in_subnet() {
        // Add test cases for is_ip_in_subnet function
    }
}

/// Retrieves the local IP address.
///
/// This function retrieves the local IP address of the system.
/// It accepts an optional subnet parameter of type `Option<(String, u32)>`.
/// If the subnet parameter is provided, it checks if the retrieved IP address is in the specified subnet.
/// Returns a `Result<String, std::io::Error>` where the `Ok` variant contains the local IP address
/// and the `Err` variant contains an error message if the retrieval fails.
pub fn get_local_ip(subnet: Option<(String, u32)>) -> io::Result<String> {
    // Implementation remains the same
}

