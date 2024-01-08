use pcap::{Active, Address, Capture, Device, Error as PcapError};
use std::time::Instant;

#[derive(Debug)]
pub enum CaptureError {
    Cap(PcapError),
    Other(String),
    DeviceNotFound(String),
    InitializationError(String),
    InvalidDeviceIndex(String),
}

impl From<pcap::Error> for CaptureError {
    fn from(err: PcapError) -> Self {
        CaptureError::Cap(err)
    }
}

impl From<String> for CaptureError {
    fn from(err: String) -> Self {
        CaptureError::Other(err)
    }
}

pub struct CaptureDevice {
    pub name: String,
    pub desc: String,
    pub address: Vec<Address>,
    pub capture: Capture<Active>,
}

impl CaptureDevice {
    pub fn new(device: Device) -> Result<CaptureDevice, CaptureError> {
        let capture = initialize_capture(device.clone())?;

        Ok(CaptureDevice {
            name: device.name,
            desc: device.desc.as_deref().unwrap_or("").to_string(),
            address: device.addresses,
            capture,
        })
    }
}

pub fn list_devices() -> Result<Vec<Device>, CaptureError> {
    Device::list().map_err(CaptureError::Cap)
}

pub fn find_device(identifier: &str) -> Result<Device, CaptureError> {
    let start = Instant::now();
    println!("Requested Device: {}", identifier);

    let devices = list_devices()?;

    if let Ok(index) = identifier.parse::<usize>() {
        if let Some(device) = devices.get(index) {
            let duration = start.elapsed();
            println!("Device {} captured in {:?}", device.name, duration);
            return Ok(device.clone());
        } else {
            return Err(CaptureError::InvalidDeviceIndex(identifier.to_string()));
        }
    }

    for device in devices {
        if device.name == identifier {
            let duration = start.elapsed();
            println!("{} device captured in {:?}", identifier, duration);
            return Ok(device);
        }
    }

    Err(CaptureError::DeviceNotFound(identifier.to_string()))
}

fn initialize_capture(device: Device) -> Result<Capture<Active>, CaptureError> {
    Capture::from_device(device)
        .map_err(CaptureError::Cap)?
        .promisc(true)
        .snaplen(1024)
        .timeout(60000)
        .immediate_mode(true)
        .open()
        .map_err(|_| CaptureError::InitializationError("Capture initialization error".into()))
}
