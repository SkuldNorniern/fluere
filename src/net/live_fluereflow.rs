// This file contains the implementation of the live packet capture functionality.
// It uses the pcap library to capture packets from a network interface and the fluereflow library to convert the packets into NetFlow data.
// The data is then displayed in a terminal user interface using the ratatui library.
use crate::{
    FluereError,
    error::OptionExt,
    net::{
        CaptureDevice, find_device,
        flow_engine::FlowEngine,
        observe_packet,
        parser::{PacketObservation, ParserState, microseconds_to_timestamp},
        types::Key,
    },
    types::Args,
    utils::{cur_time_file, fluere_exporter},
};
use std::{
    borrow::Cow,
    fs, io,
    mem::take,
    time::{Duration, Instant, SystemTime},
};

use crate::net::Flow;
use fluere_config::Config;
use fluere_plugin::PluginManager;

use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, KeyCode, KeyEvent},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use log::{debug, error, trace};
use ratatui::{
    Frame, Terminal,
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Style},
    widgets::{Block, Borders, Gauge, List, ListItem, Paragraph},
};
use tokio::{
    sync::{oneshot, watch},
    task,
};

const MAX_RECENT_FLOWS: usize = 50;

struct LiveArgs {
    csv_file: String,
    use_mac: bool,
    snaplen: u64,
    interface_name: String,
    duration: u64,
    interval: u64,
    flow_timeout: u64,
}

fn extract_live_args(arg: Args) -> Result<LiveArgs, FluereError> {
    let csv_file = arg
        .files
        .csv
        .required("this should be defaulted to `output` on construction")?;
    let use_mac = arg
        .parameters
        .use_mac
        .required("this should be defaulted to `false` on construction")?;
    let interface_name = arg.interface.required("interface should be provided")?;
    let duration = arg
        .parameters
        .duration
        .required("this should be defaulted to `0(infinite)` on construction")?;
    let interval = arg
        .parameters
        .interval
        .required("this should be defaulted to `30 minutes` on construction")?;
    let flow_timeout = arg
        .parameters
        .timeout
        .required("this should be defaulted to `10 minutes` on construction")?;
    let snaplen = arg
        .parameters
        .snaplen
        .required("this should be defaulted to `65535` on construction")?;
    Ok(LiveArgs {
        csv_file,
        use_mac,
        snaplen,
        interface_name,
        duration,
        interval,
        flow_timeout,
    })
}

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

/// When the last export happened, and how often the next one is due.
struct ExportSchedule<'a> {
    interval: u64,
    last_export: &'a mut Instant,
    last_export_unix_time: &'a mut u64,
}

/// Everything the terminal draws, as published by the capture loop.
///
/// The capture task owns the flow engine and the export schedule outright; the
/// render task owns its terminal. Neither reaches into the other's state: the
/// capture task publishes a snapshot and the render task reads the latest one.
/// Nothing needs locking, and drawing cannot stall the capture.
#[derive(Debug, Clone)]
struct UiSnapshot {
    recent_flows: Vec<FlowSummary>,
    active_flows: usize,
    /// Used to work out how far through the current export interval we are.
    last_export: Instant,
    /// Unix seconds of the last export, for display.
    last_export_unix_time: u64,
}

impl Default for UiSnapshot {
    fn default() -> Self {
        UiSnapshot {
            recent_flows: Vec::new(),
            active_flows: 0,
            last_export: Instant::now(),
            last_export_unix_time: unix_time_seconds(),
        }
    }
}

/// How often the capture loop republishes what the terminal draws.
///
/// The terminal redraws every 100ms, so publishing faster than this would only
/// copy the recent-flow list for frames nobody sees.
const UI_PUBLISH_INTERVAL: Duration = Duration::from_millis(50);

fn next_packet(cap: &mut pcap::Capture<pcap::Active>) -> Option<pcap::Packet<'_>> {
    match cap.next_packet() {
        Ok(packet) => Some(packet),
        Err(error) => {
            trace!("Error capturing packet: {}", error);
            None
        }
    }
}

fn duration_reached(start: Instant, duration: u64) -> bool {
    start.elapsed() >= Duration::from_millis(duration) && duration != 0
}

fn add_recent_flow(recent_flows: &mut Vec<FlowSummary>, key: Key) {
    recent_flows.push(FlowSummary {
        src: Cow::from(key.source.to_string()),
        dst: Cow::from(key.destination.to_string()),
        src_port: Cow::from(key.ports().0.to_string()),
        dst_port: Cow::from(key.ports().1.to_string()),
        protocol: Cow::from(key.protocol.to_string()),
    });
    if recent_flows.len() > MAX_RECENT_FLOWS {
        recent_flows.remove(0);
    }
}

async fn emit_completed_flows(
    completed: Vec<Flow>,
    plugin_manager: &PluginManager,
    records: &mut Vec<Flow>,
) -> Result<(), FluereError> {
    for flow in completed {
        trace!("flow completed");
        plugin_manager
            .process_flow_data(flow.record, crate::net::identity::for_plugin(&flow))
            .await
            .map_err(|error| FluereError::Plugin(error.to_string()))?;
        records.push(flow);
    }
    Ok(())
}

async fn process_packet(
    observation: PacketObservation,
    engine: &mut FlowEngine,
    recent_flows: &mut Vec<FlowSummary>,
    plugin_manager: &PluginManager,
    records: &mut Vec<Flow>,
) -> Result<(), FluereError> {
    let outcome = engine.accept(observation);

    if outcome.opened_flow {
        add_recent_flow(recent_flows, observation.key);
    }
    emit_completed_flows(outcome.completed, plugin_manager, records).await
}

async fn export_if_due(
    records: &mut Vec<Flow>,
    file: fs::File,
    file_path: Cow<'static, str>,
    csv_file: &str,
    file_dir: &str,
    schedule: ExportSchedule<'_>,
    export_tasks: &mut Vec<task::JoinHandle<()>>,
) -> Result<(fs::File, Cow<'static, str>), FluereError> {
    if schedule.last_export.elapsed() >= Duration::from_millis(schedule.interval)
        && schedule.interval != 0
    {
        let records_to_export = take(records);
        let file_path_clone = file_path.clone();
        export_tasks.push(task::spawn(async move {
            if let Err(error) = fluere_exporter(records_to_export, file).await {
                error!("Export error: {}", error);
            }
            debug!("Export {} Finished", file_path_clone);
        }));

        let file_path = cur_time_file(csv_file, file_dir, ".csv");
        let file = fs::File::create(file_path.as_ref())?;
        *schedule.last_export = Instant::now();
        *schedule.last_export_unix_time = unix_time_seconds();
        return Ok((file, file_path));
    }
    Ok((file, file_path))
}

async fn await_render_task(
    draw_task: task::JoinHandle<Result<(), FluereError>>,
) -> Result<(), FluereError> {
    match draw_task.await {
        Ok(result) => result,
        Err(error) => Err(FluereError::from(io::Error::other(format!(
            "render task failed: {error}"
        )))),
    }
}

async fn await_export_tasks(export_tasks: Vec<task::JoinHandle<()>>) {
    for export_task in export_tasks {
        if let Err(error) = export_task.await {
            error!("Export task failed: {}", error);
        }
    }
}

// This function captures packets from a network interface and converts them into NetFlow data.
// It takes the command line arguments as input, which specify the network interface to capture from and other parameters.
// The function runs indefinitely, capturing packets and updating the terminal user interface with the captured data.
pub async fn online_packet_capture(arg: Args) -> Result<(), FluereError> {
    let LiveArgs {
        csv_file,
        use_mac,
        snaplen,
        interface_name,
        duration,
        interval,
        flow_timeout,
    } = extract_live_args(arg)?;
    let config = Config::new();
    let (plugin_manager, plugin_worker) = PluginManager::start(&config)
        .await
        .map_err(|error| FluereError::Plugin(error.to_string()))?;

    let interface = find_device(interface_name.as_str())?;
    let mut cap_device = CaptureDevice::new(interface.clone(), snaplen)?;
    let cap = &mut cap_device.capture;
    let linktype = u16::try_from(cap.get_datalink().0).unwrap_or(1);

    let file_dir = "./output";
    fs::create_dir_all(file_dir)?;

    let start = Instant::now();
    let mut last_export_unix_time = unix_time_seconds();
    let mut last_export = Instant::now();
    let mut file_path = cur_time_file(csv_file.as_str(), file_dir, ".csv");
    let mut file = fs::File::create(file_path.as_ref())?;

    let mut records: Vec<Flow> = Vec::new();
    let mut recent_flows: Vec<FlowSummary> = Vec::new();
    let mut engine = FlowEngine::new(flow_timeout);

    // The capture loop publishes what the terminal draws; the render task only
    // ever reads the latest snapshot.
    let (ui_tx, ui_rx) = watch::channel(UiSnapshot::default());
    let mut last_publish = Instant::now();

    let (render_ready_tx, render_ready_rx) = oneshot::channel();
    let (render_shutdown_tx, render_shutdown_rx) = oneshot::channel();
    let draw_task = task::spawn(render_ui(
        ui_rx,
        interval,
        render_ready_tx,
        render_shutdown_rx,
    ));

    render_ready_rx.await.map_err(|error| {
        io::Error::other(format!("render task stopped during setup: {error}"))
    })??;

    let exit_key_task = tokio::spawn(listen_for_exit_keys());
    let mut export_tasks = vec![];

    let mut parser_state = ParserState::new();

    let capture_result: Result<(), FluereError> = async {
        loop {
            let Some(packet) = next_packet(cap) else {
                continue;
            };
            trace!("received packet");
            let Some(observation) = observe_packet(packet, use_mac, linktype, &mut parser_state)
            else {
                continue;
            };
            process_packet(
                observation,
                &mut engine,
                &mut recent_flows,
                &plugin_manager,
                &mut records,
            )
            .await?;

            (file, file_path) = export_if_due(
                &mut records,
                file,
                file_path,
                csv_file.as_str(),
                file_dir,
                ExportSchedule {
                    interval,
                    last_export: &mut last_export,
                    last_export_unix_time: &mut last_export_unix_time,
                },
                &mut export_tasks,
            )
            .await?;

            // Republished at a bounded rate: the terminal redraws ten times a
            // second, so copying the recent-flow list per packet would be work
            // for frames nobody sees.
            if last_publish.elapsed() >= UI_PUBLISH_INTERVAL {
                last_publish = Instant::now();
                let _ = ui_tx.send(UiSnapshot {
                    recent_flows: recent_flows.clone(),
                    active_flows: engine.active_count(),
                    last_export,
                    last_export_unix_time,
                });
            }

            if duration_reached(start, duration) {
                break;
            }
        }

        debug!("Captured in {:?}", start.elapsed());
        for flow in engine.drain() {
            plugin_manager
                .process_flow_data(flow.record, crate::net::identity::for_plugin(&flow))
                .await
                .map_err(|error| FluereError::Plugin(error.to_string()))?;
            records.push(flow);
        }

        let records_to_export = take(&mut records);
        export_tasks.push(task::spawn(async move {
            if let Err(error) = fluere_exporter(records_to_export, file).await {
                error!("Export error: {}", error);
            }
        }));

        Ok(())
    }
    .await;

    let _ = render_shutdown_tx.send(());
    exit_key_task.abort();
    let render_result = await_render_task(draw_task).await;

    // Consumes the manager: dropping its sender is what lets the worker drain
    // the queue and stop before plugin cleanup runs.
    plugin_manager.shutdown(plugin_worker).await;
    await_export_tasks(export_tasks).await;

    capture_result?;
    render_result?;
    Ok(())
}

type LiveTerminal = Terminal<CrosstermBackend<io::Stdout>>;

fn setup_terminal() -> io::Result<LiveTerminal> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    if let Err(error) = execute!(stdout, EnterAlternateScreen, EnableMouseCapture) {
        let _ = disable_raw_mode();
        return Err(error);
    }

    let backend = CrosstermBackend::new(stdout);
    let mut terminal = match Terminal::new(backend) {
        Ok(terminal) => terminal,
        Err(error) => {
            let _ = disable_raw_mode();
            return Err(error);
        }
    };
    if let Err(error) = terminal.clear() {
        let _ = restore_terminal(&mut terminal);
        return Err(error);
    }
    debug!("Terminal initialized");
    Ok(terminal)
}

fn restore_terminal(terminal: &mut LiveTerminal) -> io::Result<()> {
    let raw_mode_result = disable_raw_mode();
    let screen_result = execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    );
    let cursor_result = terminal.show_cursor();
    let clear_result = terminal.clear();

    raw_mode_result?;
    screen_result?;
    cursor_result?;
    clear_result?;
    debug!("Terminal restored");
    Ok(())
}

async fn render_ui(
    ui: watch::Receiver<UiSnapshot>,
    interval: u64,
    ready_tx: oneshot::Sender<io::Result<()>>,
    mut shutdown_rx: oneshot::Receiver<()>,
) -> Result<(), FluereError> {
    let mut terminal = match setup_terminal() {
        Ok(terminal) => {
            let _ = ready_tx.send(Ok(()));
            terminal
        }
        Err(error) => {
            let _ = ready_tx.send(Err(error));
            return Ok(());
        }
    };

    loop {
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_millis(100)) => {
                refresh_ui(&mut terminal, &ui.borrow(), interval);
            }
            _ = &mut shutdown_rx => break,
        }
    }

    restore_terminal(&mut terminal)?;
    Ok(())
}

/// How far through the current export interval, as 0.0 to 1.0.
///
/// An interval of zero means exports are not scheduled at all, so there is no
/// progress to show rather than a bar permanently at full.
fn export_progress(since_last_export: Duration, interval: u64) -> f64 {
    if interval == 0 {
        return 0.0;
    }

    (since_last_export.as_millis() as f64 / interval as f64).clamp(0.0, 1.0)
}

fn refresh_ui(terminal: &mut LiveTerminal, snapshot: &UiSnapshot, interval: u64) {
    let progress = export_progress(snapshot.last_export.elapsed(), interval);

    if let Err(error) = terminal.draw(|f| {
        draw_ui(
            f,
            &snapshot.recent_flows,
            progress,
            snapshot.active_flows,
            snapshot.last_export_unix_time,
        );
    }) {
        error!("Failed to draw terminal UI: {}", error);
    }
}

fn unix_time_seconds() -> u64 {
    match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
        Ok(duration) => duration.as_secs(),
        Err(error) => {
            error!("System time is before UNIX epoch: {}", error);
            0
        }
    }
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
        .split(f.area());

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
        if event::poll(std::time::Duration::from_millis(100))?
            && let event::Event::Key(KeyEvent {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn export_progress_runs_from_empty_to_full() {
        assert_eq!(export_progress(Duration::from_millis(0), 1_000), 0.0);
        assert_eq!(export_progress(Duration::from_millis(500), 1_000), 0.5);
        assert_eq!(export_progress(Duration::from_millis(1_000), 1_000), 1.0);
    }

    /// Overdue exports must not run the bar past the end.
    #[test]
    fn export_progress_is_clamped() {
        assert_eq!(export_progress(Duration::from_millis(9_000), 1_000), 1.0);
    }

    /// With no export interval there is nothing to be partway through. The
    /// previous code divided by the interval regardless, which left the bar
    /// pinned at full for a capture that never exports on a timer.
    #[test]
    fn an_unscheduled_export_shows_no_progress() {
        assert_eq!(export_progress(Duration::from_millis(5_000), 0), 0.0);
    }

    /// The snapshot is what the render task reads; a fresh one must be drawable
    /// before the capture loop has published anything.
    #[test]
    fn a_default_snapshot_is_drawable() {
        let snapshot = UiSnapshot::default();

        assert!(snapshot.recent_flows.is_empty());
        assert_eq!(snapshot.active_flows, 0);
        assert_eq!(export_progress(snapshot.last_export.elapsed(), 1_000), 0.0);
    }

    /// The recent-flow list is bounded, so a long capture cannot grow the
    /// snapshot the capture loop clones on every publish.
    #[test]
    fn the_recent_flow_list_stays_bounded() {
        use crate::net::types::Key;
        use fluereflow::{Endpoints, MacAddress, VlanTags};
        use std::net::{IpAddr, Ipv4Addr};

        let mut recent = Vec::new();
        for port in 0..(MAX_RECENT_FLOWS as u16 * 3) {
            add_recent_flow(
                &mut recent,
                Key {
                    source: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
                    destination: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2)),
                    endpoints: Endpoints::Ports {
                        source: port,
                        destination: 443,
                    },
                    protocol: 6,
                    source_mac: MacAddress::new([0; 6]),
                    destination_mac: MacAddress::new([1; 6]),
                    vlan: VlanTags::default(),
                    encapsulation: None,
                },
            );
        }

        assert!(recent.len() <= MAX_RECENT_FLOWS + 1, "got {}", recent.len());
    }
}
