use std::fs;
use std::time::{Duration, Instant};

use crate::error::{FluereError, OptionExt};
use crate::net::{CaptureDevice, find_device};
use crate::types::Args;
use crate::utils::cur_time_file;

use log::{debug, trace};

pub async fn write_pcap(args: Args) -> Result<(), FluereError> {
    let pcap_file = args.files.pcap.required("pcap")?;
    let interface_name = args.interface.required("interface")?;
    let duration = args.parameters.duration.required("duration")?;
    let _interval = args.parameters.interval.required("interval")?;
    let snaplen = args.parameters.snaplen.required("snaplen")?;

    let interface = find_device(interface_name.as_str())?;
    let mut cap_device = CaptureDevice::new(interface, snaplen)?;
    let cap = &mut cap_device.capture;

    let file_dir = "./output";
    // let mut packet_count = 0;
    fs::create_dir_all(file_dir)?;
    debug!("Created directory: {}", file_dir);

    let file_path = cur_time_file(pcap_file.as_str(), file_dir, ".pcap");
    let mut file: pcap::Savefile = cap.savefile(file_path.as_ref())?;

    let start = Instant::now();

    loop {
        let packet = cap.next_packet()?;
        trace!("received packet");
        //println!("packet: {:?}", packet);
        file.write(&packet);

        // Check if the duration has been reached
        if start.elapsed() >= Duration::from_millis(duration) && duration != 0 {
            break;
        }
    }
    debug!("Captured in {:?}", start.elapsed());
    Ok(())
}
