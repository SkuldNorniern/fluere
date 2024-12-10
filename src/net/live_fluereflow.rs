// This file contains the implementation of the live packet capture functionality.
// It uses the pcap library to capture packets from a network interface and the fluereflow library to convert the packets into NetFlow data.
// The data is then displayed in a terminal user interface using the ratatui library.
use crate::{
    net::{
        find_device,
        flows::update_flow,
        parser::{microseconds_to_timestamp, parse_fluereflow, parse_keys, parse_microseconds},
        types::TcpFlags,
        CaptureDevice,
    },
    types::{Args, UDFlowKey},
    utils::{cur_time_file, fluere_exporter},
    FluereError,
};
use std::{
    borrow::Cow,
    collections::HashMap,
    fs, io,
    sync::Arc,
    time::{Duration, Instant, SystemTime},
};

use fluere_config::Config;
use fluere_plugin::PluginManager;
use fluereflow::FluereRecord;

use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, KeyCode, KeyEvent},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use log::{debug, error, trace};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Style},
    widgets::{Block, Borders, Gauge, List, ListItem, Paragraph},
    Frame, Terminal,
};
use tokio::{sync::Mutex, task};

const MAX_RECENT_FLOWS: usize = 50;

// This function is the entry point for the live packet capture functionality.
// It takes the command line arguments as input and calls the online_packet_capture function.
// It returns a Result indicating whether the operation was successful.
pub async fn packet_capture(arg: Args) -> Result<(), FluereError> {
    debug!("Starting Terminal User Interface");

    online_packet_capture(arg).await?;
    debug!("Terminal User Interface Stopped");
    Ok(())
}
#[derive(Debug, Clone)]
struct FlowSummary {
    src: Cow<'static, str>,
    dst: Cow<'static, str>,
    src_port: Cow<'static, str>,
    dst_port: Cow<'static, str>,
    protocol: Cow<'static, str>, //flow_data: String, // or any other relevant data you want to display
}

// This function captures packets from a network interface and converts them into NetFlow data.
// It takes the command line arguments as input, which specify the network interface to capture from and other parameters.
// The function runs indefinitely, capturing packets and updating the terminal user interface with the captured data.
pub async fn online_packet_capture(arg: Args) -> Result<(), FluereError> {
    let csv_file = arg
        .files
        .csv
        .ok_or_else(|| FluereError::ConfigError("CSV file not specified".to_string()))?;
    let use_mac = arg.parameters.use_mac.unwrap();
    let interface_name = arg.interface.expect("interface not found");
    let duration = arg.parameters.duration.unwrap();
    let interval = arg.parameters.interval.unwrap();
    let flow_timeout = arg.parameters.timeout.unwrap();
    let _sleep_windows = arg.parameters.sleep_windows.unwrap();
    let config = Config::new();
    let plugin_manager = PluginManager::new().expect("Failed to create plugin manager");
    let plugin_worker = plugin_manager.start_worker();

    plugin_manager
        .load_plugins(&config)
        .await
        .expect("Failed to load plugins");

    let interface = find_device(interface_name.as_str()).unwrap();
    let mut cap_device = CaptureDevice::new(interface.clone()).unwrap();
    let cap = &mut cap_device.capture;

    let file_dir = "./output";
    fs::create_dir_all(file_dir)?;

    let start = Instant::now();
    let last_export_unix_time = Arc::new(Mutex::new(
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("SystemTime before UNIX EPOCH")
            .as_secs(),
    ));
    let last_export = Arc::new(Mutex::new(Instant::now()));
    let mut file_path = cur_time_file(csv_file.as_str(), file_dir, ".csv");
    let mut file = fs::File::create(file_path.as_ref())?;

    let mut records: Vec<FluereRecord> = Vec::new();
    let recent_flows: Arc<Mutex<Vec<FlowSummary>>> = Arc::new(Mutex::new(Vec::new()));
    let active_flow = Arc::new(Mutex::new(HashMap::new()));

    match enable_raw_mode() {
        Ok(_) => debug!("Raw mode enabled"),
        Err(e) => {
            error!("Failed to enable raw mode: {:?}", e);
            return Err(FluereError::from(e));
        }
    };
    let mut stdout = io::stdout();
    match execute!(stdout, EnterAlternateScreen, EnableMouseCapture) {
        Ok(_) => debug!("Terminal entered alt screen"),
        Err(e) => {
            error!("Failed to enter alt screen: {:?}", e);
            return Err(FluereError::from(e));
        }
    };
    let backend = CrosstermBackend::new(io::stdout());
    let terminal = Arc::new(Mutex::new(Terminal::new(backend)?));
    match terminal.lock().await.clear() {
        Ok(_) => debug!("Terminal cleared"),
        Err(e) => {
            error!("Failed to clear terminal: {:?}", e);
            return Err(FluereError::from(e));
        }
    };

    let draw_task = tokio::task::spawn({
        let terminal_clone = Arc::clone(&terminal);
        let recent_flows_clone = Arc::clone(&recent_flows);
        let last_export_clone = Arc::clone(&last_export);
        let last_export_unix_time_clone = Arc::clone(&last_export_unix_time);
        let active_flow_clone = active_flow.clone();
        async move {
            loop {
                tokio::time::sleep(Duration::from_millis(100)).await;
                let flow_summaries: Vec<FlowSummary> = {
                    let recent_flows_guard = recent_flows_clone.lock().await;
                    recent_flows_guard.clone()
                };
                let (progress, recent_exported_time): (f64, u64) = {
                    let last_export_unix_time_guard = last_export_unix_time_clone.lock().await;
                    let last_export_guard = last_export_clone.lock().await;
                    let progress = (last_export_guard.elapsed().as_millis() as f64
                        / interval as f64)
                        .clamp(0.0, 1.0);
                    (progress, *last_export_unix_time_guard)
                };
                let active_flow_count: usize = {
                    let active_flow_guard = active_flow_clone.lock().await;
                    active_flow_guard.len()
                };
                let mut terminal = terminal_clone.lock().await;
                terminal
                    .draw(|f| {
                        draw_ui(
                            f,
                            &flow_summaries,
                            progress,
                            active_flow_count,
                            recent_exported_time,
                        );
                    })
                    .unwrap();
            }
        }
    });

    tokio::spawn(listen_for_exit_keys());

    let mut tasks = vec![];
    let mut export_tasks = vec![];

    loop {
        match cap.next_packet() {
            Err(_) => {
                continue;
            }
            Ok(packet) => {
                trace!("received packet");

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
                    Err(e) => {
                        debug!("{}", e);
                        continue;
                    }
                };

                let flags = TcpFlags::new(raw_flags);
                //pushing packet in to active_flows if it is not present
                //let mut active_flow: HashMap<Key, FluereRecord> = HashMap::new();
                let mut active_flow_guard = active_flow.lock().await;

                let is_reverse = match active_flow_guard.get(&key_value) {
                    None => match active_flow_guard.get(&reverse_key) {
                        None => {
                            // if the protocol is TCP, check if is a syn packet
                            if flowdata.prot == 6 {
                                if flags.syn > 0 {
                                    active_flow_guard.insert(key_value, flowdata);
                                    trace!("flow established");
                                    let mut recent_flows_guard = recent_flows.lock().await;
                                    recent_flows_guard.push(FlowSummary {
                                        src: Cow::from(key_value.src_ip.to_string()),
                                        dst: Cow::from(key_value.dst_ip.to_string()),
                                        src_port: Cow::from(key_value.src_port.to_string()),
                                        dst_port: Cow::from(key_value.dst_port.to_string()),
                                        protocol: Cow::from(key_value.protocol.to_string()), //flow_data: format!("{:?}", flowdata),
                                    });
                                    if recent_flows_guard.len() > MAX_RECENT_FLOWS {
                                        recent_flows_guard.remove(0);
                                    }
                                } else {
                                    continue;
                                }
                            } else {
                                active_flow_guard.insert(key_value, flowdata);
                                trace!("flow established");
                                let mut recent_flows_guard = recent_flows.lock().await;
                                recent_flows_guard.push(FlowSummary {
                                    src: Cow::from(key_value.src_ip.to_string()),
                                    dst: Cow::from(key_value.dst_ip.to_string()),
                                    src_port: Cow::from(key_value.src_port.to_string()),
                                    dst_port: Cow::from(key_value.dst_port.to_string()),
                                    protocol: Cow::from(key_value.protocol.to_string()), //flow_data: format!("{:?}", flowdata),
                                });
                                if recent_flows_guard.len() > MAX_RECENT_FLOWS {
                                    recent_flows_guard.remove(0);
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
                let pkt = flowdata.min_pkt;
                let ttl = flowdata.min_ttl;
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

                    trace!(
                        "{} flow updated",
                        if is_reverse { "reverse" } else { "forward" }
                    );

                    if flags.fin == 1 || flags.rst == 1 {
                        trace!("flow finished");
                        plugin_manager.process_flow_data(*flow).await.unwrap();
                        records.push(*flow);
                        active_flow_guard.remove(flow_key);
                    }
                }

                // Export flows if the interval has been reached
                let mut last_export_guard = last_export.lock().await;
                let mut last_export_unix_time_guard = last_export_unix_time.lock().await;
                if last_export_guard.elapsed() >= Duration::from_millis(interval) && interval != 0 {
                    let mut expired_flows = vec![];
                    let mut expired_flow_data: Vec<FluereRecord> = vec![];

                    debug!("Calculating timeout start");
                    for (key, flow) in active_flow_guard.iter() {
                        if flow_timeout > 0 && flow.last < (time - (flow_timeout * 1000)) {
                            trace!("flow expired");

                            //plugin_manager.process_flow_data(*flow).await.unwrap();
                            records.push(*flow);
                            expired_flows.push(*key);
                            expired_flow_data.push(*flow);
                        }
                    }

                    let cloned_plugin_manager = plugin_manager.clone();
                    tasks.push(task::spawn(async move {
                        for flow in &expired_flow_data {
                            cloned_plugin_manager
                                .process_flow_data(*flow)
                                .await
                                .unwrap();
                        }
                        debug!(
                            "Sending {} expired flows to plugins done",
                            expired_flow_data.len()
                        );
                    }));

                    active_flow_guard.retain(|key, _| !expired_flows.contains(key));
                    let cloned_records = records.clone();
                    records.clear();
                    //let tasks = task::spawn(async {
                    //fluere_exporter(cloned_records, file).await;
                    //});
                    let file_path_clone = file_path.clone();
                    export_tasks.push(task::spawn(async move {
                        let _ = fluere_exporter(cloned_records, file).await;
                        debug!("Export {} Finished", file_path_clone);
                    }));

                    /*if verbose >= 1 {
                    println!("Export {} result: {:?}", file_path, result);
                    }*/
                    file_path = cur_time_file(csv_file.as_str(), file_dir, ".csv");
                    file = fs::File::create(file_path.as_ref()).map_err(FluereError::IoError)?;
                    *last_export_guard = Instant::now();
                    *last_export_unix_time_guard = SystemTime::now()
                        .duration_since(SystemTime::UNIX_EPOCH)
                        .expect("SystemTime before UNIX EPOCH")
                        .as_secs();
                }

                // Check if the duration has been reached
                if start.elapsed() >= Duration::from_millis(duration) && duration != 0 {
                    let mut expired_flows = vec![];
                    for (key, flow) in active_flow_guard.iter() {
                        if flow.last < (time - (flow_timeout * 1000)) {
                            trace!("flow expired");
                            plugin_manager.process_flow_data(*flow).await.unwrap();
                            records.push(*flow);
                            expired_flows.push(*key);
                        }
                    }
                    active_flow_guard.retain(|key, _| !expired_flows.contains(key));
                    break;
                }
            }
        }
    }
    debug!("Captured in {:?}", start.elapsed());
    let active_flow_guard = active_flow.lock().await;

    for (_key, flow) in active_flow_guard.iter() {
        plugin_manager.process_flow_data(*flow).await.unwrap();
        records.push(*flow);
    }

    for task in tasks {
        let _ = task.await;
    }

    let cloned_records = records.clone();
    export_tasks.push(task::spawn(async {
        let _ = fluere_exporter(cloned_records, file).await;
    }));
    plugin_manager.await_completion(plugin_worker).await;
    drop(plugin_manager);
    for task in export_tasks {
        let _ = task.await;
    }

    let _ = draw_task.await;
    match disable_raw_mode() {
        Ok(_) => debug!("Raw mode disabled"),
        Err(e) => {
            error!("Failed to disable raw mode: {:?}", e);
            return Err(FluereError::from(e));
        }
    };
    let mut terminal_guard = terminal.lock().await;
    match execute!(
        terminal_guard.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    ) {
        Ok(_) => debug!("Terminal restored"),
        Err(e) => {
            error!("Failed to restore terminal: {:?}", e);
            return Err(FluereError::from(e));
        }
    };

    match terminal.lock().await.show_cursor() {
        Ok(_) => debug!("Cursor shown"),
        Err(e) => {
            error!("Failed to show the cursor: {:?}", e);
            return Err(FluereError::from(e));
        }
    };
    match terminal.lock().await.clear() {
        Ok(_) => debug!("Terminal cleared"),
        Err(e) => {
            error!("Failed to clear terminal: {:?}", e);
            return Err(FluereError::from(e));
        }
    };

    Ok(())
}
fn draw_ui(
    f: &mut Frame,
    recent_flows: &[FlowSummary],
    progress: f64,
    active_flow_count: usize,
    recent_exported_time: u64,
) {
    // Define the layout
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(2)
        .constraints(
            [
                Constraint::Length(3),       // For the progress bar
                Constraint::Length(5),       // For the summary box
                Constraint::Percentage(100), // For the list of flows
            ]
            .as_ref(),
        )
        .split(f.size());

    // Progress bar
    let progress_bar = Gauge::default()
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Next Export Progress"),
        )
        .gauge_style(Style::default().fg(Color::White))
        .percent((progress * 100.0) as u16);
    f.render_widget(progress_bar, chunks[0]);

    // Summary box
    let summary_text = [
        format!("Active Flow Count: {}", active_flow_count),
        format!(
            "Recent Exported Time: {}",
            microseconds_to_timestamp(recent_exported_time).as_str()
        ),
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
                Constraint::Percentage(5),  // arrow
                Constraint::Percentage(33), // dst
                Constraint::Percentage(10), // dst_port
                Constraint::Percentage(9),  // protocol
            ]
            .as_ref(),
        )
        .split(chunks[2]);

    // Render each column
    let srcs: Vec<ListItem> = recent_flows
        .iter()
        .map(|f| ListItem::new(f.src.clone()))
        .collect();
    let src_ports: Vec<ListItem> = recent_flows
        .iter()
        .map(|f| ListItem::new(f.src_port.to_string()))
        .collect();
    let arrows: Vec<ListItem> = recent_flows
        .iter()
        .map(|_| ListItem::new("->".to_string()))
        .collect();
    let dsts: Vec<ListItem> = recent_flows
        .iter()
        .map(|f| ListItem::new(f.dst.clone()))
        .collect();
    let dst_ports: Vec<ListItem> = recent_flows
        .iter()
        .map(|f| ListItem::new(f.dst_port.to_string()))
        .collect();
    let protocols: Vec<ListItem> = recent_flows
        .iter()
        .map(|f| ListItem::new(f.protocol.clone()))
        .collect();

    f.render_widget(
        List::new(srcs).block(Block::default().borders(Borders::ALL).title("SRC")),
        flow_columns[0],
    );
    f.render_widget(
        List::new(src_ports).block(Block::default().borders(Borders::ALL).title("SRC PORT")),
        flow_columns[1],
    );
    f.render_widget(
        List::new(arrows).block(Block::default().borders(Borders::ALL).title("")),
        flow_columns[2],
    );
    f.render_widget(
        List::new(dsts).block(Block::default().borders(Borders::ALL).title("DST")),
        flow_columns[3],
    );
    f.render_widget(
        List::new(dst_ports).block(Block::default().borders(Borders::ALL).title("DST PORT")),
        flow_columns[4],
    );
    f.render_widget(
        List::new(protocols).block(Block::default().borders(Borders::ALL).title("PROTOCOL")),
        flow_columns[5],
    );
}
async fn listen_for_exit_keys() -> Result<(), std::io::Error> {
    loop {
        if event::poll(std::time::Duration::from_millis(100))? {
            if let event::Event::Key(KeyEvent {
                code, modifiers, ..
            }) = event::read()?
            {
                match code {
                    KeyCode::Char('c') if modifiers == event::KeyModifiers::CONTROL => {
                        debug!("Exiting due to control-c");
                        std::process::exit(0);
                    }
                    KeyCode::Char('q') | KeyCode::Char('Q') => {
                        debug!("Exiting due to q/Q");
                        std::process::exit(0);
                    }
                    _ => {}
                }
            }
        }
    }
}
