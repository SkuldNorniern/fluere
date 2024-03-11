//mod fluereflow
pub mod capture;
pub mod errors;
mod flows;
// mod interface;
pub mod live_fluereflow;
mod offline_fluereflows;
pub mod online_fluereflow;
mod packet_pcap;
pub mod parser;
pub mod types;

//pub use flows::packet_capture;
pub use capture::find_device;
pub use capture::CaptureDevice;
pub use capture::DeviceError;
// pub use interface::list_interface_names;
// pub use interface::list_interfaces;
pub use offline_fluereflows::fluereflow_fileparse;
pub use packet_pcap::pcap_capture;
//pub use types::FluereRecord;

use std::fmt::{Display, Formatter, Result as FmtResult};

use pcap::Error;

#[derive(Debug)]
pub enum NetError {
    DeviceError(DeviceError),
    PcapError(Error),
}

impl From<DeviceError> for NetError {
    fn from(err: DeviceError) -> Self {
        NetError::DeviceError(err)
    }
}

impl From<Error> for NetError {
    fn from(err: Error) -> Self {
        NetError::PcapError(err)
    }
}

impl Display for NetError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            NetError::DeviceError(err) => err.fmt(f),
            NetError::PcapError(err) => err.fmt(f),
        }
    }
}
