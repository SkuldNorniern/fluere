//! Interface listing.

use crate::ConfigError;
use pcap::Device;

/// Print the capture interfaces, in the order their index selects them.
pub fn list() -> Result<(), ConfigError> {
    let devices = Device::list().map_err(|error| {
        ConfigError::Argument(format!("Failed to list network devices: {}", error))
    })?;

    println!("List of network interfaces");
    println!("--------------------------");
    for (index, device) in devices.iter().enumerate() {
        print!("[{}] {:25}", index, device.name);
        if let Some(description) = &device.desc {
            print!(" - {}", description);
        }
        println!();
    }

    Ok(())
}
