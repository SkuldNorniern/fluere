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
        parser::{FragmentTracker, PacketObservation, microseconds_to_timestamp},
        types::Key,
    },
    types::Args,
    utils::{cur_time_file, fluere_exporter},
};
use std::{
    borrow::Cow,
    fs, io,
    mem::take,
    sync::Arc,
    time::{Duration, Instant, SystemTime},
};

use fluere_config::Config;
use fluere_plugin::PluginManager;
use fluereflow::FluereRecord;

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
    sync::{Mutex, oneshot},
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

struct ExportSchedule<'a> {
    interval: u64,
    last_export: &'a Mutex<Instant>,
    last_export_unix_time: &'a Mutex<u64>,
}

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

async fn add_recent_flow(recent_flows: &Mutex<Vec<FlowSummary>>, key: Key) {
    let mut recent_flows_guard = recent_flows.lock().await;
    recent_flows_guard.push(FlowSummary {
        src: Cow::from(key.src_ip.to_string()),
        dst: Cow::from(key.dst_ip.to_string()),
        src_port: Cow::from(key.src_port.to_string()),
        dst_port: Cow::from(key.dst_port.to_string()),
        protocol: Cow::from(key.protocol.to_string()),
    });
    if recent_flows_guard.len() > MAX_RECENT_FLOWS {
        recent_flows_guard.remove(0);
    }
}

async fn emit_completed_flows(
    completed: Vec<FluereRecord>,
    plugin_manager: &PluginManager,
    records: &mut Vec<FluereRecord>,
) -> Result<(), FluereError> {
    for flow in completed {
        trace!("flow completed");
        plugin_manager
            .process_flow_data(flow)
            .await
            .map_err(|error| FluereError::Plugin(error.to_string()))?;
        records.push(flow);
    }
    Ok(())
}

async fn process_packet(
    observation: PacketObservation,
    engine: &Mutex<FlowEngine>,
    recent_flows: &Mutex<Vec<FlowSummary>>,
    plugin_manager: &PluginManager,
    records: &mut Vec<FluereRecord>,
) -> Result<(), FluereError> {
    // Held only for the engine update, so the capture loop is not blocked on
    // the plugin and TUI work that follows.
    let outcome = {
        let mut engine_guard = engine.lock().await;
        engine_guard.accept(observation)
    };

    if outcome.opened_flow {
        add_recent_flow(recent_flows, observation.key).await;
    }
    emit_completed_flows(outcome.completed, plugin_manager, records).await
}

async fn export_if_due(
    records: &mut Vec<FluereRecord>,
    file: fs::File,
    file_path: Cow<'static, str>,
    csv_file: &str,
    file_dir: &str,
    schedule: ExportSchedule<'_>,
    export_tasks: &mut Vec<task::JoinHandle<()>>,
) -> Result<(fs::File, Cow<'static, str>), FluereError> {
    let mut last_export_guard = schedule.last_export.lock().await;
    let mut last_export_unix_time_guard = schedule.last_export_unix_time.lock().await;
    if last_export_guard.elapsed() >= Duration::from_millis(schedule.interval)
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
        *last_export_guard = Instant::now();
        *last_export_unix_time_guard = unix_time_seconds();
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
    let plugin_manager =
        PluginManager::new().map_err(|error| FluereError::Plugin(error.to_string()))?;
    let plugin_worker = plugin_manager.start_worker();

    plugin_manager
        .load_plugins(&config)
        .await
        .map_err(|error| FluereError::Plugin(error.to_string()))?;

    let interface = find_device(interface_name.as_str())?;
    let mut cap_device = CaptureDevice::new(interface.clone(), snaplen)?;
    let cap = &mut cap_device.capture;
    let linktype = u16::try_from(cap.get_datalink().0).unwrap_or(1);

    let file_dir = "./output";
    fs::create_dir_all(file_dir)?;

    let start = Instant::now();
    let last_export_unix_time = Arc::new(Mutex::new(unix_time_seconds()));
    let last_export = Arc::new(Mutex::new(Instant::now()));
    let mut file_path = cur_time_file(csv_file.as_str(), file_dir, ".csv");
    let mut file = fs::File::create(file_path.as_ref())?;

    let mut records: Vec<FluereRecord> = Vec::new();
    let recent_flows: Arc<Mutex<Vec<FlowSummary>>> = Arc::new(Mutex::new(Vec::new()));
    let engine = Arc::new(Mutex::new(FlowEngine::new(flow_timeout)));

    let (render_ready_tx, render_ready_rx) = oneshot::channel();
    let (render_shutdown_tx, render_shutdown_rx) = oneshot::channel();
    let draw_task = task::spawn({
        let recent_flows_clone = Arc::clone(&recent_flows);
        let last_export_clone = Arc::clone(&last_export);
        let last_export_unix_time_clone = Arc::clone(&last_export_unix_time);
        let engine_clone = Arc::clone(&engine);
        async move {
            render_ui(
                recent_flows_clone,
                last_export_clone,
                last_export_unix_time_clone,
                engine_clone,
                interval,
                render_ready_tx,
                render_shutdown_rx,
            )
            .await
        }
    });

    render_ready_rx.await.map_err(|error| {
        io::Error::other(format!("render task stopped during setup: {error}"))
    })??;

    let exit_key_task = tokio::spawn(listen_for_exit_keys());
    let mut export_tasks = vec![];

    let mut fragments = FragmentTracker::new();

    let capture_result: Result<(), FluereError> = async {
        loop {
            let Some(packet) = next_packet(cap) else {
                continue;
            };
            trace!("received packet");
            let Some(observation) = observe_packet(packet, use_mac, linktype, &mut fragments)
            else {
                continue;
            };
            process_packet(
                observation,
                &engine,
                &recent_flows,
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
                    last_export: &last_export,
                    last_export_unix_time: &last_export_unix_time,
                },
                &mut export_tasks,
            )
            .await?;

            if duration_reached(start, duration) {
                break;
            }
        }

        debug!("Captured in {:?}", start.elapsed());
        let remaining = {
            let mut engine_guard = engine.lock().await;
            engine_guard.drain()
        };
        for flow in remaining {
            plugin_manager
                .process_flow_data(flow)
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
    recent_flows: Arc<Mutex<Vec<FlowSummary>>>,
    last_export: Arc<Mutex<Instant>>,
    last_export_unix_time: Arc<Mutex<u64>>,
    engine: Arc<Mutex<FlowEngine>>,
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
                refresh_ui(
                    &mut terminal,
                    &recent_flows,
                    &last_export,
                    &last_export_unix_time,
                    &engine,
                    interval,
                ).await;
            }
            _ = &mut shutdown_rx => break,
        }
    }

    restore_terminal(&mut terminal)?;
    Ok(())
}

async fn refresh_ui(
    terminal: &mut LiveTerminal,
    recent_flows: &Mutex<Vec<FlowSummary>>,
    last_export: &Mutex<Instant>,
    last_export_unix_time: &Mutex<u64>,
    engine: &Mutex<FlowEngine>,
    interval: u64,
) {
    let flow_summaries: Vec<FlowSummary> = {
        let recent_flows_guard = recent_flows.lock().await;
        recent_flows_guard.clone()
    };
    let (progress, recent_exported_time): (f64, u64) = {
        let last_export_unix_time_guard = last_export_unix_time.lock().await;
        let last_export_guard = last_export.lock().await;
        let progress =
            (last_export_guard.elapsed().as_millis() as f64 / interval as f64).clamp(0.0, 1.0);
        (progress, *last_export_unix_time_guard)
    };
    let active_flow_count: usize = {
        let engine_guard = engine.lock().await;
        engine_guard.active_count()
    };
    if let Err(error) = terminal.draw(|f| {
        draw_ui(
            f,
            &flow_summaries,
            progress,
            active_flow_count,
            recent_exported_time,
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
