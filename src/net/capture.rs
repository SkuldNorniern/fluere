use std::{fmt, time::Instant};

use crate::net::NetError;

use pcap::{Active, Address, Capture, Device, Error as PcapError};

#[derive(Debug)]
pub enum DeviceError {
    DeviceNotFound(String),
    InvalidDeviceIndex(usize),
}

impl fmt::Display for DeviceError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            DeviceError::DeviceNotFound(err) => write!(f, "Device not found: {}", err),
            DeviceError::InvalidDeviceIndex(err) => write!(f, "Invalid device index: {}", err),
        }
    }
}

pub struct CaptureDevice {
    pub name: String,
    pub desc: String,
    pub address: Vec<Address>,
    pub capture: Capture<Active>,
}

impl CaptureDevice {
    pub fn new(device: Device) -> Result<CaptureDevice, PcapError> {
        let capture = initialize_capture(device.clone())?;

        Ok(CaptureDevice {
            name: device.name,
            desc: device.desc.as_deref().unwrap_or("").to_string(),
            address: device.addresses,
            capture,
        })
    }
}

impl Drop for CaptureDevice {
    fn drop(&mut self) {
        println!("Closing capture session for device {}", self.name);
        // self.capture.;
    }
}
pub fn find_device(identifier: &str) -> Result<Device, NetError> {
    let start = Instant::now();
    println!("Requested Device: {}", identifier);

    let devices = Device::list()?;

    if let Ok(index) = identifier.parse::<usize>() {
        if let Some(device) = devices.get(index) {
            let duration = start.elapsed();
            println!("Device {} captured in {:?}", device.name, duration);
            return Ok(device.clone());
        } else {
            return Err(NetError::DeviceError(DeviceError::InvalidDeviceIndex(
                index,
            )));
        }
    }

    for device in devices {
        if device.name == identifier {
            let duration = start.elapsed();
            println!("{} device captured in {:?}", identifier, duration);
            return Ok(device);
        }
    }

    Err(NetError::DeviceError(DeviceError::DeviceNotFound(
        identifier.to_string(),
    )))
}

fn initialize_capture(device: Device) -> Result<Capture<Active>, PcapError> {
    Ok(Capture::from_device(device)?
        .promisc(true)
        .snaplen(1024)
        .timeout(60000)
        .immediate_mode(true)
        .open()?)
}
