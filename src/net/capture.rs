use pcap::{Active, Address, Capture, Device, Error as PcapError};

use std::time::Instant;
use std::fmt;

#[derive(Debug)]
pub enum DeviceError {
    Cap(PcapError),
    DeviceNotFound(String),
    InitializationError(),
    InvalidDeviceIndex(usize),
}

impl From<PcapError> for DeviceError {
    fn from(err: PcapError) -> Self {
        DeviceError::Cap(err)
    }
}
impl fmt::Display for DeviceError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            DeviceError::Cap(err) => err.fmt(f),
            DeviceError::DeviceNotFound(err) => write!(f, "Device not found: {}", err),
            DeviceError::InitializationError() => write!(f, "Initialization error"),
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
    pub fn new(device: Device) -> Result<CaptureDevice, DeviceError> {
        let capture = initialize_capture(device.clone())?;

        Ok(CaptureDevice {
            name: device.name,
            desc: device.desc.as_deref().unwrap_or("").to_string(),
            address: device.addresses,
            capture,
        })
    }
}

pub fn list_devices() -> Result<Vec<Device>, DeviceError> {
    Device::list().map_err(DeviceError::Cap)
}

pub fn find_device(identifier: &str) -> Result<Device, DeviceError> {
    let start = Instant::now();
    println!("Requested Device: {}", identifier);

    let devices = list_devices()?;

    if let Ok(index) = identifier.parse::<usize>() {
        if let Some(device) = devices.get(index) {
            let duration = start.elapsed();
            println!("Device {} captured in {:?}", device.name, duration);
            return Ok(device.clone());
        } else {
            return Err(DeviceError::InvalidDeviceIndex(index));
        }
    }

    for device in devices {
        if device.name == identifier {
            let duration = start.elapsed();
            println!("{} device captured in {:?}", identifier, duration);
            return Ok(device);
        }
    }

    Err(DeviceError::DeviceNotFound(identifier.to_string()))
}

fn initialize_capture(device: Device) -> Result<Capture<Active>, DeviceError> {
    Ok(Capture::from_device(device)
        .map_err(DeviceError::Cap)?
        .promisc(true)
        .snaplen(1024)
        .timeout(60000)
        .immediate_mode(true)
        .open()?)
}
