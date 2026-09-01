use std::{borrow::Cow, time::Instant};

use crate::error::CaptureError;

use log::{debug, info};
use pcap::{Active, Address, Capture, Device};

pub struct CaptureDevice {
    pub name: Cow<'static, str>,
    pub desc: Cow<'static, str>,
    pub address: Vec<Address>,
    pub capture: Capture<Active>,
}

impl CaptureDevice {
    pub fn new(device: Device, snaplen: u64) -> Result<CaptureDevice, CaptureError> {
        let capture = initialize_capture(device.clone(), snaplen)?;
        let name: Cow<'static, str> = Cow::Owned(device.name);
        let desc: Cow<'static, str> = Cow::Owned(device.desc.unwrap_or_default());
        debug!("Using device: {name}");
        debug!("Device description: {desc}");
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
pub fn find_device(identifier: &str) -> Result<Device, CaptureError> {
    let start = Instant::now();
    debug!("Looking for device: {identifier}");

    let devices = Device::list()?;

    if let Ok(index) = identifier.parse::<usize>() {
        if let Some(device) = devices.get(index) {
            let duration = start.elapsed();
            debug!("Device {} captured in {:?}", device.name, duration);
            return Ok(device.clone());
        } else {
            return Err(CaptureError::InvalidDeviceIndex(index));
        }
    }

    for device in devices {
        if device.name == identifier {
            let duration = start.elapsed();
            debug!("Device {} captured in {:?}", device.name, duration);
            return Ok(device);
        }
    }

    Err(CaptureError::DeviceNotFound(identifier.to_string()))
}

/// Open a live capture on `device`.
///
/// `snaplen` is how many bytes of each packet are handed to the parser. Byte
/// accounting still uses the wire length reported by the capture header, but a
/// short snaplen truncates the payload paccel needs to reach inner tunnel
/// headers, so the full-frame default is the right one for flow analysis.
/// How long a read waits for a packet before reporting a timeout, in
/// milliseconds. This is the granularity at which a capture notices it should
/// stop, not a limit on how long it runs.
const POLL_TIMEOUT_MS: i32 = 250;

fn initialize_capture(device: Device, snaplen: u64) -> Result<Capture<Active>, CaptureError> {
    info!(
        "Opening capture session for device {} with snaplen {}",
        device.name, snaplen
    );
    // libpcap takes a signed length; anything past i32::MAX is nonsense, and 0
    // would capture no bytes at all, so clamp into the range it accepts.
    let snaplen = snaplen.clamp(1, i32::MAX as u64) as i32;

    Capture::from_device(device)?
        .promisc(true)
        .snaplen(snaplen)
        // Short enough that a quiet interface still notices `--duration` and a
        // key press promptly. A minute-long timeout meant neither took effect
        // until the next packet happened to arrive.
        .timeout(POLL_TIMEOUT_MS)
        .immediate_mode(true)
        .open()
        .map_err(CaptureError::from)
}
