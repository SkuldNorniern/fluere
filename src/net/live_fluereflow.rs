extern crate csv;

use crossterm::{
    event::{self, KeyCode, KeyEvent, DisableMouseCapture, EnableMouseCapture},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use fluereflow::FluereRecord;
use pcap::Capture;
use ratatui::{
    layout::{Constraint, Direction, Layout},
    backend::{CrosstermBackend,Backend},
    widgets::{Block, Borders,List, ListItem,Gauge, Paragraph},
    style::{Color, Style},
    Terminal,
    Frame
};
use tokio::task;
use tokio::time::sleep;


use super::interface::get_interface;

use crate::{
    net::{
        parser::{parse_fluereflow, parse_keys, parse_microseconds,microseconds_to_timestamp}, 
        flows::update_flow,
        types::TcpFlags,
    },
    types::{Args,UDFlowKey},
    utils::{cur_time_file, fluere_exporter},
};

use std::{
    collections::HashMap,
    fs,
    io,
    sync::{Arc, Mutex},
    time::{Duration, Instant,SystemTime},
};

pub async fn packet_capture(arg: Args) -> Result<(), io::Error> {
    println!("TUI");
    online_packet_capture(arg).await;
    Ok(())
}
#[derive(Debug, Clone)]
struct FlowSummary {
    src: String,
    dst: String,
    src_port: String,
    dst_port: String,
    protocol: String
    //flow_data: String, // or any other relevant data you want to display
}


pub async fn online_packet_capture(
    arg: Args,
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
    let mut last_export_unix_time = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).expect("SystemTime before UNIX EPOCH").as_secs();
    let mut last_export = Instant::now();
    let mut file_path = cur_time_file(csv_file.as_str(), file_dir, ".csv").await;
    let mut file = fs::File::create(file_path.clone()).unwrap();

    //let mut wtr = csv::Writer::from_writer(file);

    let mut records: Vec<FluereRecord> = Vec::new();
    let recent_flows: Arc<Mutex<Vec<FlowSummary>>> = Arc::new(Mutex::new(Vec::new()));
    let active_flow = Arc::new(async_mutex::Mutex::new(HashMap::new()));

    let mut packet_count = 0;
    
    enable_raw_mode().expect("Unable to enable raw mode");
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture).expect("Unable to enter alt screen");
    let backend = CrosstermBackend::new(io::stdout());
    let terminal = Arc::new(Mutex::new(Terminal::new(backend).expect("Failed to initialize terminal")));
    terminal.lock().unwrap().clear().expect("Failed to clear terminal");

    let terminal_clone = Arc::clone(&terminal);
    let recent_flows_clone = Arc::clone(&recent_flows);
    let active_flow_clone = active_flow.clone();

    let draw_task = tokio::task::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_millis(100)).await;

            let flow_summaries: Vec<FlowSummary> = {
                let recent_flows_guard = recent_flows_clone.lock().unwrap();
                recent_flows_guard.clone().into_iter().collect()

            };
            let mut terminal = terminal_clone.lock().unwrap();
            
            terminal.draw(|f| {
                let progress = last_export.elapsed().as_millis() as f64 / interval as f64;
                let active_flow_count = match active_flow_clone.try_lock(){
                    Some(ac_flow) => ac_flow.len(),
                    None => 0
                };
                let recent_exported_time = last_export_unix_time.clone();// or however you format the time

                draw_ui(f, &flow_summaries, progress, active_flow_count,recent_exported_time);
            }).unwrap();
        }
    });

    tokio::spawn(listen_for_exit_keys());

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
        //let mut active_flow: HashMap<Key, FluereRecord> = HashMap::new();
        let mut active_flow_guard = active_flow.lock().await;

        let is_reverse = match active_flow_guard.get(&key_value) {
            None => match active_flow_guard.get(&reverse_key) {
                None => {
                    // if the protocol is TCP, check if is a syn packet
                    if flowdata.get_prot() == 6 {
                        if flags.syn > 0 {
                            active_flow_guard.insert(key_value, flowdata);
                            if verbose >= 2 {
                                println!("flow established");
                            }
                            let mut recent_flows_guard = recent_flows.lock().unwrap();
                            recent_flows_guard.push(FlowSummary {
                                src: key_value.src_ip.to_string(),
                                dst: key_value.dst_ip.to_string(),
                                src_port: key_value.src_port.to_string(),
                                dst_port: key_value.dst_port.to_string(),
                                protocol: key_value.protocol.to_string()
                                //flow_data: format!("{:?}", flowdata),
                            });
                        } else {
                            continue;
                        }
                    } else {
                        active_flow_guard.insert(key_value, flowdata);
                        if verbose >= 2 {
                            println!("flow established");
                        }
                        let mut recent_flows_guard = recent_flows.lock().unwrap();
                        recent_flows_guard.push(FlowSummary {
                            src: key_value.src_ip.to_string(),
                            dst: key_value.dst_ip.to_string(),
                            src_port: key_value.src_port.to_string(),
                            dst_port: key_value.dst_port.to_string(),
                            protocol: key_value.protocol.to_string()
                            //flow_data: format!("{:?}", flowdata),
                        });
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
        if let Some(flow) = active_flow_guard.get_mut(flow_key) {
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
                active_flow_guard.remove(flow_key);
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
            for (key, flow) in active_flow_guard.iter() {
                if flow_timeout > 0 && flow.get_last() < (time - (flow_timeout * 1000)) {
                    if verbose >= 2 {
                        println!("flow expired");
                    }
                    records.push(*flow);
                    expired_flows.push(*key);
                }
            }
            active_flow_guard.retain(|key, _| !expired_flows.contains(key));
            let cloned_records = records.clone();
            records.clear();
            let tasks = task::spawn(async {
                fluere_exporter(cloned_records, file).await;
            });

            let _result = tasks.await;
            /*if verbose >= 1 {
                println!("Export {} result: {:?}", file_path, result);
            }*/
            file_path = cur_time_file(csv_file.as_str(), file_dir, ".csv").await;
            file = fs::File::create(file_path.clone()).unwrap();
            last_export = Instant::now();
            last_export_unix_time = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).expect("SystemTime before UNIX EPOCH").as_secs();
        }

        // Check if the duration has been reached
        if start.elapsed() >= Duration::from_millis(duration) && duration != 0 {
            let mut expired_flows = vec![];
            for (key, flow) in active_flow_guard.iter() {
                if flow.get_last() < (time - (flow_timeout * 1000)) {
                    if verbose >= 2 {
                        println!("flow expired");
                    }
                    records.push(*flow);
                    expired_flows.push(*key);
                }
            }
            active_flow_guard.retain(|key, _| !expired_flows.contains(key));
            break;
        }
    }
    if verbose >= 1 {
        println!("Captured in {:?}", start.elapsed());
    }
    let active_flow_guard = active_flow.lock().await;

    for (_key, flow) in active_flow_guard.iter() {
        records.push(*flow);
    }
    let tasks = task::spawn(async {
        fluere_exporter(records, file).await;
    });

    let result = tasks.await;
    if verbose >= 1 {
        println!("Exporting task excutation result: {:?}", result);
    }
    let _ =draw_task.await;
    disable_raw_mode().expect("failed to disable raw mode");
    execute!(
        terminal.lock().unwrap().backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    ).expect("failed to restore terminal");
    terminal.lock().unwrap().show_cursor().expect("failed to show the cursor");
    terminal.lock().unwrap().clear().expect("failed to clear terminal");

    //println!("records {:?}", records);
}
fn draw_ui<B: Backend>(
    f: &mut Frame<B>,
    recent_flows: &[FlowSummary],
    progress: f64,
    active_flow_count: usize,
    recent_exported_time: u64
) {
    // Define the layout
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(2)
        .constraints(
            [
                Constraint::Length(3), // For the progress bar
                Constraint::Length(5), // For the summary box
                Constraint::Percentage(100), // For the list of flows
            ]
            .as_ref(),
        )
        .split(f.size());

    // Progress bar
    let progress_bar = Gauge::default()
        .block(Block::default().borders(Borders::ALL).title("Next Export Progress"))
        .gauge_style(Style::default().fg(Color::White))
        .percent((progress * 100.0) as u16);
    f.render_widget(progress_bar, chunks[0]);

    // Summary box
    let summary_text = vec![
        format!("Active Flow Count: {}", active_flow_count),
        format!("Recent Exported Time: {}", microseconds_to_timestamp(recent_exported_time).as_str()),
    ];
    let summary_paragraph = Paragraph::new(summary_text.join("  |  "))
        .block(Block::default().borders(Borders::ALL).title("Summary"));
    f.render_widget(summary_paragraph, chunks[1]);

    // Split the flows chunk into individual columns
    let flow_columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints(
            [
                Constraint::Percentage(33), // src
                Constraint::Percentage(10), // src_port
                Constraint::Percentage(5), // arrow
                Constraint::Percentage(33), // dst
                Constraint::Percentage(10), // dst_port
                Constraint::Percentage(9), // protocol
            ]
            .as_ref(),
        )
        .split(chunks[2]);

    // Render each column
    let srcs: Vec<ListItem> = recent_flows.iter().map(|f| ListItem::new(f.src.clone())).collect();
    let src_ports: Vec<ListItem> = recent_flows.iter().map(|f| ListItem::new(f.src_port.to_string())).collect();
    let arrows: Vec<ListItem> = recent_flows.iter().map(|_| ListItem::new("->".to_string())).collect();
    let dsts: Vec<ListItem> = recent_flows.iter().map(|f| ListItem::new(f.dst.clone())).collect();
    let dst_ports: Vec<ListItem> = recent_flows.iter().map(|f| ListItem::new(f.dst_port.to_string())).collect();
    let protocols: Vec<ListItem> = recent_flows.iter().map(|f| ListItem::new(f.protocol.clone())).collect();


    f.render_widget(List::new(srcs).block(Block::default().borders(Borders::ALL).title("SRC")), flow_columns[0]);
    f.render_widget(List::new(src_ports).block(Block::default().borders(Borders::ALL).title("SRC PORT")), flow_columns[1]);
    f.render_widget(List::new(arrows).block(Block::default().borders(Borders::ALL).title("")), flow_columns[2]);
    f.render_widget(List::new(dsts).block(Block::default().borders(Borders::ALL).title("DST")), flow_columns[3]);
    f.render_widget(List::new(dst_ports).block(Block::default().borders(Borders::ALL).title("DST PORT")), flow_columns[4]);
    f.render_widget(List::new(protocols).block(Block::default().borders(Borders::ALL).title("PROTOCOL")), flow_columns[5]);
}
async fn listen_for_exit_keys() -> Result<(), crossterm::ErrorKind> {
    loop {
        if event::poll(std::time::Duration::from_millis(100))? {
            if let event::Event::Key(KeyEvent { code, modifiers, .. }) = event::read()? {
                match code {
                    KeyCode::Char('c') if modifiers == event::KeyModifiers::CONTROL => {
                        println!("Ctrl+C pressed. Exiting...");
                        std::process::exit(0);
                    },
                    KeyCode::Char('q') | KeyCode::Char('Q') => {
                        println!("'q' or 'Q' pressed. Exiting...");
                        std::process::exit(0);
                    },
                    _ => {}
                }
            }

        }
    }
}

