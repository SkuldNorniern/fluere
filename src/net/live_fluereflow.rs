extern crate csv;

use crossterm::{
    event::{DisableMouseCapture, EnableMouseCapture},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use fluereflow::FluereRecord;
use pcap::Capture;
use ratatui::{
    backend::CrosstermBackend,
    widgets::{Block, Borders},
    Terminal,
};
use tokio::task;
use tokio::time::sleep;

use super::interface::get_interface;

use crate::{
    net::{
        parser::{parse_fluereflow, parse_keys, parse_microseconds}, 
        flows::update_flow,
        types::{Key, TcpFlags},
    },
    types::{Args,UDFlowKey},
    utils::{cur_time_file, fluere_exporter},
};

use std::{
    collections::HashMap,
    fs,
    io,
    time::{Duration, Instant},
};

pub async fn packet_capture(arg: Args) -> Result<(), io::Error> {
    println!("TUI");
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    terminal.draw(|f| {
        let size = f.size();
        let block = Block::default().title("Block").borders(Borders::ALL);
        f.render_widget(block, size);
    })?;
    let tasks = task::spawn(async move {
        online_packet_capture(arg).await;
    });

    let _ = tasks.await;

    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;
    Ok(())
}

pub async fn online_packet_capture(
    arg: Args,
    //csv_file: &str,
    // use_mac: bool,
    // interface_name: &str,
    // duration: u64,
    // interval: u64,
    // flow_timeout: u64,
    // sleep_windows: u64,
    // verbose: u8,
) {
    let csv_file = arg.files.csv.unwrap();
    let use_mac = arg.parameters.use_mac.unwrap();
    let interface_name = arg.interface.expect("interface not found");
    let duration = arg.parameters.duration.unwrap();
    let interval = arg.parameters.interval.unwrap();
    let flow_timeout = arg.parameters.timeout.unwrap();
    let sleep_windows = arg.parameters.sleep_windows.unwrap();
    let verbose = arg.verbose.unwrap();

    let interface = get_interface(interface_name.as_str());
    let mut cap = Capture::from_device(interface)
        .unwrap()
        .promisc(true)
        //.buffer_size(100000000)
        //.immediate_mode(true)
        .open()
        .unwrap();

    let file_dir = "./output";
    match fs::create_dir_all(<&str>::clone(&file_dir)) {
        Ok(_) => {
            if verbose >= 1 {
                println!("Created directory: {}", file_dir)
            }
        }
        Err(error) => panic!("Problem creating directory: {:?}", error),
    };

    let start = Instant::now();
    let mut last_export = Instant::now();
    let mut file_path = cur_time_file(csv_file.as_str(), file_dir, ".csv").await;
    let mut file = fs::File::create(file_path.clone()).unwrap();

    //let mut wtr = csv::Writer::from_writer(file);

    let mut records: Vec<FluereRecord> = Vec::new();
    let mut active_flow: HashMap<Key, FluereRecord> = HashMap::new();
    let mut packet_count = 0;

    while let Ok(packet) = cap.next_packet() {
        if verbose >= 3 {
            println!("received packet");
        }

        let (mut key_value, mut reverse_key) = match parse_keys(packet.clone()) {
            Ok(keys) => keys,
            Err(_) => continue,
        };
        if !use_mac {
            key_value.mac_defaultate();
            reverse_key.mac_defaultate();
        }

        let (doctets, raw_flags, flowdata) = match parse_fluereflow(packet.clone()) {
            Ok(result) => result,
            Err(_) => continue,
        };

        let flags = TcpFlags::new(raw_flags);
        //pushing packet in to active_flows if it is not present
        let is_reverse = match active_flow.get(&key_value) {
            None => match active_flow.get(&reverse_key) {
                None => {
                    // if the protocol is TCP, check if is a syn packet
                    if flowdata.get_prot() == 6 {
                        if flags.syn > 0 {
                            active_flow.insert(key_value, flowdata);
                            if verbose >= 2 {
                                println!("flow established");
                            }
                        } else {
                            continue;
                        }
                    } else {
                        active_flow.insert(key_value, flowdata);
                        if verbose >= 2 {
                            println!("flow established");
                        }
                    }

                    false
                }
                Some(_) => true,
            },
            Some(_) => false,
        };

        let time = parse_microseconds(
            packet.header.ts.tv_sec as u64,
            packet.header.ts.tv_usec as u64,
        );
        //println!("time: {:?}", time);
        let pkt = flowdata.get_min_pkt();
        let ttl = flowdata.get_min_ttl();
        //println!("current inputed flow{:?}", active_flow.get(&key_value).unwrap());
        let flow_key = if is_reverse { &reverse_key } else { &key_value };
        if let Some(flow) = active_flow.get_mut(flow_key) {
            let update_key = UDFlowKey {
                doctets,
                pkt,
                ttl,
                flags,
                time,
            };
            update_flow(flow, is_reverse, update_key);

            if verbose >= 2 {
                println!("{} flow updated", if is_reverse { "reverse" } else { "forward" });
            }

            if flags.fin == 1 || flags.rst == 1 {
                if verbose >= 2 {
                    println!("flow finished");
                }
                records.push(*flow);
                active_flow.remove(flow_key);
            }   
        }

        packet_count += 1;
        // slow down the loop for windows to avoid random shutdown
        if packet_count % sleep_windows == 0 && cfg!(target_os = "windows") {
            if verbose >= 3 {
                println!("Slow down the loop for windows");
            }
            sleep(Duration::from_millis(0)).await;
        }

        // Export flows if the interval has been reached
        if last_export.elapsed() >= Duration::from_millis(interval) && interval != 0 {
            let mut expired_flows = vec![];
            packet_count = 0;
            for (key, flow) in active_flow.iter() {
                if flow_timeout > 0 && flow.get_last() < (time - (flow_timeout * 1000)) {
                    if verbose >= 2 {
                        println!("flow expired");
                    }
                    records.push(*flow);
                    expired_flows.push(*key);
                }
            }
            active_flow.retain(|key, _| !expired_flows.contains(key));
            let cloned_records = records.clone();
            records.clear();
            let tasks = task::spawn(async {
                fluere_exporter(cloned_records, file).await;
            });

            let result = tasks.await;
            if verbose >= 1 {
                println!("Export {} result: {:?}", file_path, result);
            }
            file_path = cur_time_file(csv_file.as_str(), file_dir, ".csv").await;
            file = fs::File::create(file_path.clone()).unwrap();
            last_export = Instant::now();
        }

        // Check if the duration has been reached
        if start.elapsed() >= Duration::from_millis(duration) && duration != 0 {
            let mut expired_flows = vec![];
            for (key, flow) in active_flow.iter() {
                if flow.get_last() < (time - (flow_timeout * 1000)) {
                    if verbose >= 2 {
                        println!("flow expired");
                    }
                    records.push(*flow);
                    expired_flows.push(*key);
                }
            }
            active_flow.retain(|key, _| !expired_flows.contains(key));
            break;
        }
    }
    if verbose >= 1 {
        println!("Captured in {:?}", start.elapsed());
    }
    for (_key, flow) in active_flow.iter() {
        records.push(*flow);
    }
    let tasks = task::spawn(async {
        fluere_exporter(records, file).await;
    });

    let result = tasks.await;
    if verbose >= 1 {
        println!("Exporting task excutation result: {:?}", result);
    }
    //println!("records {:?}", records);
}