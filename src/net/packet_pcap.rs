use std::fs;
use std::time::{Duration, Instant};

use crate::net::{find_device, CaptureDevice};
use crate::types::Args;
use crate::utils::cur_time_file;

use log::{debug, trace};

pub async fn pcap_capture(args: Args) {
    let pcap_file = args.files.pcap.unwrap();
    let interface_name = args.interface.expect("interface not found");
    let duration = args.parameters.duration.unwrap();
    let _interval = args.parameters.interval.unwrap();
    let _sleep_windows = args.parameters.sleep_windows.unwrap();

    let interface = find_device(interface_name.as_str()).unwrap();
    let mut cap_device = CaptureDevice::new(interface.clone()).unwrap();
    let cap = &mut cap_device.capture;

    let file_dir = "./output";
    // let mut packet_count = 0;
    match fs::create_dir_all(<&str>::clone(&file_dir)) {
        Ok(_) => debug!("Created directory: {}", file_dir),
        Err(error) => panic!("Problem creating directory: {:?}", error),
    };

    let file_path = cur_time_file(pcap_file.as_str(), file_dir, ".pcap");
    let mut file: pcap::Savefile = match cap.savefile(file_path.as_ref()) {
        Ok(f) => f,
        Err(_) => std::process::exit(1),
    };

    let start = Instant::now();

    loop {
        match cap.next_packet() {
            Err(_) => {
                continue;
            }
            Ok(packet) => {
                trace!("received packet");
                //println!("packet: {:?}", packet);
                file.write(&packet);

                // Check if the duration has been reached
                if start.elapsed() >= Duration::from_millis(duration) && duration != 0 {
                    break;
                }
            }
        }
    }
    debug!("Captured in {:?}", start.elapsed());
}
