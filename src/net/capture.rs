use std::{borrow::Cow, time::Instant};

use crate::error::FluereError;

use log::{debug, info};
use pcap::{Active, Address, Capture, Device, Error as PcapError};

pub struct CaptureDevice {
    pub name: Cow<'static, str>,
    pub desc: Cow<'static, str>,
    pub address: Vec<Address>,
    pub capture: Capture<Active>,
}

impl CaptureDevice {
    pub fn new(device: Device) -> Result<CaptureDevice, PcapError> {
        let capture = initialize_capture(device.clone())?;
        let name: Cow<'static, str> = Cow::Owned(device.name);
        let desc: Cow<'static, str> = Cow::Owned(device.desc.unwrap_or("".to_string()));
        debug!("Using device: {}", name);
        debug!("Device description: {}", desc);
        debug!("Addresses: {:?}", device.addresses);
        Ok(CaptureDevice {
            name,
            desc,
            address: device.addresses,
            capture,
        })
    }
}

impl Drop for CaptureDevice {
    fn drop(&mut self) {
        info!("Closing capture session for device {}", self.name);
    }
}
pub fn find_device(identifier: &str) -> Result<Device, FluereError> {
    let start = Instant::now();
    debug!("Looking for device: {}", identifier);

    let devices = Device::list()?;

    if let Ok(index) = identifier.parse::<usize>() {
        if let Some(device) = devices.get(index) {
            let duration = start.elapsed();
            debug!("Device {} captured in {:?}", device.name, duration);
            return Ok(device.clone());
        } else {
            return Err(FluereError::InvalidDeviceIndex(index));
        }
    }

    for device in devices {
        if device.name == identifier {
            let duration = start.elapsed();
            debug!("Device {} captured in {:?}", device.name, duration);
            return Ok(device);
        }
    }

    Err(FluereError::DeviceNotFound(identifier.to_string()))
}

fn initialize_capture(device: Device) -> Result<Capture<Active>, PcapError> {
    info!("Opening capture session for device {}", device.name);
    Capture::from_device(device)?
        .promisc(true)
        // FEAT:TASK: set snaplen as a Flag from the CLI
        .snaplen(1024)
        .timeout(60000)
        .immediate_mode(true)
        .open()
}
