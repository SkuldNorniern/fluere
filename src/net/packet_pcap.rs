extern crate chrono;

use chrono::Local;
use pcap::Capture;
use std::fs;

use super::interface::get_interface;

use std::time::Instant;

pub fn packet_capture(interface_name: &str) {
    let interface = get_interface(interface_name);
    let mut cap = Capture::from_device(interface)
        .unwrap()
        .timeout(0)
        .buffer_size(10000000)
        .open()
        .unwrap();

    let date = Local::now();
    let file_dir = "./output";
    fs::create_dir_all(file_dir.clone());
    let file_path = format!("{}/{}.pcap", file_dir, date.format("%Y-%m-%d_%H-%M-%S"));
    let mut file: pcap::Savefile = match cap.savefile(file_path) {
        Ok(f) => f,
        Err(_) => std::process::exit(1),
    };
    let start = Instant::now();
    while let Ok(packet) = cap.next_packet() {
        println!("received packet");
        println!("packet: {:?}", packet);
        file.write(&packet);
    }
    let duration = start.elapsed();
    println!("Captured in {:?}", duration);
}
