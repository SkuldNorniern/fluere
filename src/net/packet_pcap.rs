extern crate chrono;

use pcap::Capture;
use std::fs;

use tokio::time::sleep;

use super::interface::get_interface;
use crate::types::Args;
use crate::utils::cur_time_file;

use std::time::{Duration, Instant};

pub async fn pcap_capture(args: Args) {
    let pcap_file = args.files.pcap.unwrap();
    let interface_name = args.interface.expect("interface not found");
    let duration = args.parameters.duration.unwrap();
    let _interval = args.parameters.interval.unwrap();
    let sleep_windows = args.parameters.sleep_windows.unwrap();
    let verbose = args.verbose.unwrap();

    let interface = get_interface(interface_name.as_str());
    let mut cap = Capture::from_device(interface)
        .unwrap()
        .promisc(true)
        //.buffer_size(1000000000)
        .open()
        .unwrap();

    let file_dir = "./output";
    let file_dir = "./output";
    match fs::create_dir_all(<&str>::clone(&file_dir)) {
        Ok(_) => {
            if verbose >= 1 {
                println!("Created directory: {}", file_dir)
            }
        }
        Err(error) => return Err(()),
    };

    let file_path = cur_time_file(pcap_file.as_str(), file_dir, ".pcap").await;
    let mut file: pcap::Savefile = match cap.savefile(file_path) {
        Ok(f) => f,
        Err(_) => std::process::exit(1),
    };

    let start = Instant::now();
    while let Ok(packet) = cap.next_packet() {
        if verbose >= 3 {
            println!("received packet");
        }
        //println!("packet: {:?}", packet);
        file.write(&packet);

        packet_count += 1;
        // slow down the loop for windows to avoid random shutdown
        if packet_count % sleep_windows == 0 && cfg!(target_os = "windows") {
            if verbose >= 3 {
                println!("Slow down the loop for windows");
            }
            sleep(Duration::from_millis(0)).await;
        }

        // Check if the duration has been reached
        if start.elapsed() >= Duration::from_millis(duration) && duration != 0 {
            break;
        }
    }
    if verbose >= 1 {
        println!("Captured in {:?}", start.elapsed());
    }
}
