extern crate chrono;

use pcap::Capture;
use std::fs;

use tokio::time::sleep;

use super::interface::get_interface;
use crate::utils::cur_time_file;

use std::time::{Duration, Instant};

pub async fn pcap_capture(
    pcap_file: &str,
    interface_name: &str,
    duration: u64,
    _interval: u64,
    sleep_windows: u64,
    verbose: u8,
) {
    let interface = get_interface(interface_name);
    let mut cap = Capture::from_device(interface)
        .unwrap()
        .promisc(true)
        .open()
        .unwrap();

    let file_dir = "./output";
    let mut packet_count = 0;
    match fs::create_dir_all(<&str>::clone(&file_dir)) {
        Ok(_) => {
            if verbose >= 1 {
                println!("Created directory: {}", file_dir)
            }
        }
        Err(error) => panic!("Problem creating directory: {:?}", error),
    };

    let file_path = cur_time_file(pcap_file, file_dir, ".pcap").await;
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
        if packet_count % 10 == 0 && cfg!(target_os = "windows") {
            if verbose >= 3 {
                println!("Slow down the loop for windows");
            }
            sleep(Duration::from_millis(sleep_windows)).await;
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
