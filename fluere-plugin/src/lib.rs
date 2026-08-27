//! Loading and running Fluere's plugins.
//!
//! Plugins are untrusted, optional code. Nothing a plugin does - failing to
//! load, raising an error, or missing an expected function - is allowed to stop
//! the capture that feeds it.
//!
//! A plugin is written for one of the [runtimes](runtime) compiled into this
//! build, and is claimed by the first runtime whose entry file its directory
//! contains. Adding a language is a new [`PluginRuntime`] implementation behind
//! a feature; nothing here changes.

use std::path::PathBuf;

pub mod downloader;
mod error;
pub mod runtime;
mod util;
pub mod view;

use downloader::download_plugin_from_github;
use util::home_cache_path;

pub use downloader::DownloadError;
pub use error::PluginError;
pub use runtime::{PluginRuntime, Runtime};
pub use view::{FieldValue, FlowIdentity, FlowView, SCHEMA_VERSION};

use fluere_config::{Config, Plugin};
use fluereflow::FlowRecord;
use tokio::sync::mpsc;

#[cfg(feature = "log")]
use log::{debug, info};

/// Capacity of the queue between the capture path and the plugin worker.
const CHANNEL_CAPACITY: usize = 100;

/// Report a plugin problem without bringing anything down.
#[macro_export]
macro_rules! plugin_warn {
    ($($arg:tt)*) => {{
        #[cfg(feature = "log")]
        log::warn!($($arg)*);
        #[cfg(not(feature = "log"))]
        println!($($arg)*);
    }};
}

/// Report that a plugin is up.
macro_rules! plugin_info {
    ($($arg:tt)*) => {{
        #[cfg(feature = "log")]
        info!($($arg)*);
        #[cfg(not(feature = "log"))]
        println!($($arg)*);
    }};
}

/// Handle to the background task that feeds records to loaded plugins.
///
/// Returned by [`PluginManager::start`] alongside the manager, and handed back to
/// [`PluginManager::shutdown`], which is the only supported way to stop it.
#[derive(Debug)]
pub struct PluginWorker {
    handle: tokio::task::JoinHandle<()>,
}

/// Hands finished flows to the loaded plugins.
///
/// Only a channel sender: everything with state - the interpreters, the plugins
/// loaded into them, the queue - is owned by the worker task and never shared.
/// That is what keeps this free of reference counting and locks, and why the
/// manager is cheap to hold and to clone.
#[derive(Debug, Clone)]
pub struct PluginManager {
    sender: mpsc::Sender<(FlowRecord, FlowIdentity)>,
}

impl PluginManager {
    /// Load every enabled plugin in `config` and start feeding them flows.
    ///
    /// A plugin that cannot be found, downloaded, read, or initialised is
    /// reported and skipped; the remaining plugins still load.
    pub async fn start(config: &Config) -> Result<(Self, PluginWorker), PluginError> {
        #[cfg(feature = "log")]
        debug!("Loading plugins");

        let mut runtimes = Runtime::available();
        let mut loaded = 0usize;

        for (name, plugin_config) in &config.plugins {
            if !plugin_config.enabled {
                continue;
            }

            let directory = match plugin_directory(name, plugin_config) {
                Ok(directory) => directory,
                Err(error) => {
                    plugin_warn!("Unable to locate plugin {}: {}", name, error);
                    continue;
                }
            };

            let arguments = plugin_config.extra_arguments.clone().unwrap_or_default();

            let Some(runtime) = runtimes
                .iter_mut()
                .find(|runtime| directory.join(runtime.entry_file()).is_file())
            else {
                match entry_files() {
                    Some(entries) => plugin_warn!(
                        "No runtime can load plugin {}: none of {} found in {}",
                        name,
                        entries,
                        directory.display()
                    ),
                    None => plugin_warn!(
                        "Cannot load plugin {}: this build has no plugin runtimes compiled in",
                        name
                    ),
                }
                continue;
            };

            match runtime.load(name, &directory, &arguments) {
                Ok(()) => {
                    let language = runtime.name();
                    loaded += 1;
                    plugin_info!("Loaded {} plugin {}", language, name);
                }
                Err(error) => plugin_warn!("Failed to load plugin {}: {}", name, error),
            }
        }

        let (sender, receiver) = mpsc::channel::<(FlowRecord, FlowIdentity)>(CHANNEL_CAPACITY);

        #[cfg(feature = "log")]
        debug!("{} plugin(s) loaded", loaded);
        #[cfg(not(feature = "log"))]
        let _ = loaded;

        Ok((PluginManager { sender }, spawn_worker(runtimes, receiver)))
    }

    /// Queue one finished flow for the plugins.
    ///
    /// `identity` is what separated this flow from another with the same
    /// addresses and ports; it lives on the flow key rather than the record.
    pub async fn process_flow_data(
        &self,
        data: FlowRecord,
        identity: FlowIdentity,
    ) -> Result<(), PluginError> {
        self.sender
            .send((data, identity))
            .await
            .map_err(|_| PluginError::WorkerStopped)
    }

    /// Drain the queue, stop the worker, then run each plugin's cleanup hook.
    ///
    /// Consuming `self` is what makes the ordering reliable: dropping the last
    /// sender closes the channel, so the worker processes everything already
    /// queued and only then cleans up and returns.
    pub async fn shutdown(self, worker: PluginWorker) {
        drop(self.sender);

        if let Err(error) = worker.handle.await {
            plugin_warn!("Plugin worker did not stop cleanly: {}", error);
        }
    }
}

/// Spawn the task that owns the runtimes for the rest of the run.
///
/// It holds them outright rather than borrowing them back from the manager, so
/// no lock is needed to hand a flow to a plugin, and cleanup happens here once
/// the queue has drained rather than being coordinated from outside.
fn spawn_worker(
    mut runtimes: Vec<Runtime>,
    mut receiver: mpsc::Receiver<(FlowRecord, FlowIdentity)>,
) -> PluginWorker {
    let handle = tokio::spawn(async move {
        while let Some((record, identity)) = receiver.recv().await {
            // Built once and marshalled by each runtime, so the field list
            // lives in one place however many languages are loaded.
            let view = FlowView::new(&record, &identity);

            for runtime in runtimes.iter_mut() {
                if !runtime.is_empty() {
                    runtime.on_flow(&view);
                }
            }
        }

        // The channel is closed and the queue is empty: every flow that will
        // ever arrive has been handed over.
        for runtime in runtimes.iter_mut() {
            runtime.cleanup();
        }
    });

    PluginWorker { handle }
}

/// Where a plugin's entry file lives: the configured path, or the cache
/// directory it gets downloaded into.
fn plugin_directory(name: &str, plugin_config: &Plugin) -> Result<PathBuf, PluginError> {
    match plugin_config.path.as_ref() {
        Some(path) => Ok(PathBuf::from(path)),
        None => {
            download_plugin_from_github(name)?;
            let directory = name.rsplit('/').next().unwrap_or(name);
            Ok(home_cache_path()?.join(directory))
        }
    }
}

/// The entry files this build knows how to load, or `None` when no runtime is
/// compiled in at all.
fn entry_files() -> Option<String> {
    let names: Vec<&str> = Runtime::available()
        .iter()
        .map(|runtime| runtime.entry_file())
        .collect();

    (!names.is_empty()).then(|| names.join(", "))
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::path::{Path, PathBuf};

    use super::*;

    /// A plugin that appends one line per record and one on cleanup, so the
    /// resulting file shows the exact order the two happened in.
    const RECORDING_PLUGIN: &str = r#"
local plugin = {}
local path

function plugin.init(args)
    path = args.out
    local file = io.open(path, "w")
    file:close()
end

function plugin.process_data(record)
    local file = io.open(path, "a")
    file:write("record " .. record.frame_octets .. "\n")
    file:close()
end

function plugin.cleanup()
    local file = io.open(path, "a")
    file:write("cleanup\n")
    file:close()
end

return plugin
"#;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "fluere-plugin-test-{}-{}",
                tag,
                std::process::id()
            ));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir_all(&path).expect("temp dir");
            TempDir(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// A one-packet flow whose size identifies it, so an ordering test can
    /// tell one record from another.
    fn record(marker: u16) -> FlowRecord {
        let mut record = FlowRecord::open(
            fluereflow::Timestamp::from_micros(1_000),
            fluereflow::TimeResolution::Microseconds,
            fluereflow::StartState::NotApplicable,
        );
        record.observe(
            fluereflow::Direction::Forward,
            fluereflow::PacketFacts {
                time: fluereflow::Timestamp::from_micros(1_000),
                frame_octets: u32::from(marker),
                captured_octets: u32::from(marker),
                ttl: Some(64),
                tcp_flags: None,
                icmp: None,
            },
        );
        record
    }

    fn config_for(dir: &Path, arguments: Option<HashMap<String, String>>) -> Config {
        let mut plugins = fluere_config::Plugins::new();
        plugins.insert(
            "recorder".to_string(),
            Plugin {
                enabled: true,
                path: Some(dir.display().to_string()),
                extra_arguments: arguments,
            },
        );
        Config { plugins }
    }

    #[tokio::test]
    async fn every_queued_record_is_processed_before_cleanup() {
        let dir = TempDir::new("ordering");
        std::fs::write(dir.0.join("init.lua"), RECORDING_PLUGIN).expect("write plugin");
        let output = dir.0.join("out.txt");

        let mut arguments = HashMap::new();
        arguments.insert("out".to_string(), output.display().to_string());

        let (manager, worker) = PluginManager::start(&config_for(&dir.0, Some(arguments)))
            .await
            .expect("plugins load");

        for port in 0..25u16 {
            manager
                .process_flow_data(record(port), FlowIdentity::default())
                .await
                .expect("queued");
        }

        manager.shutdown(worker).await;

        let written = std::fs::read_to_string(&output).expect("plugin output");
        let lines: Vec<&str> = written.lines().collect();

        assert_eq!(lines.len(), 26, "25 records plus one cleanup: {:?}", lines);
        assert_eq!(
            lines.last(),
            Some(&"cleanup"),
            "cleanup must run after every queued record"
        );
        for (port, line) in lines[..25].iter().enumerate() {
            assert_eq!(*line, format!("record {}", port));
        }
    }

    /// Asserts inside Lua that each field arrived with its natural type.
    const TYPE_PROBE_PLUGIN: &str = r#"
local plugin = {}
local path

function plugin.init(args)
    path = args.out
    local file = io.open(path, "w")
    file:close()
end

function plugin.process_data(record)
    local file = io.open(path, "a")
    file:write("schema=" .. tostring(record.schema_version) .. "\n")
    file:write("packets=" .. type(record.packets) .. "\n")
    file:write("start_state=" .. type(record.start_state) .. "\n")
    file:write("truncated=" .. type(record.truncated) .. "\n")
    -- Arithmetic straight on the field, with no tonumber() call.
    file:write("doubled=" .. tostring(record.frame_octets * 2) .. "\n")
    file:close()
end

return plugin
"#;

    #[tokio::test]
    async fn plugins_see_typed_fields_and_a_schema_version() {
        let dir = TempDir::new("types");
        std::fs::write(dir.0.join("init.lua"), TYPE_PROBE_PLUGIN).expect("write plugin");
        let output = dir.0.join("out.txt");

        let mut arguments = HashMap::new();
        arguments.insert("out".to_string(), output.display().to_string());

        let (manager, worker) = PluginManager::start(&config_for(&dir.0, Some(arguments)))
            .await
            .expect("plugins load");
        manager
            .process_flow_data(record(21), FlowIdentity::default())
            .await
            .expect("queued");
        manager.shutdown(worker).await;

        let written = std::fs::read_to_string(&output).expect("plugin output");
        assert!(
            written.contains(&format!("schema={}", SCHEMA_VERSION)),
            "{}",
            written
        );
        assert!(written.contains("packets=number"), "{}", written);
        assert!(written.contains("start_state=string"), "{}", written);
        assert!(written.contains("truncated=boolean"), "{}", written);
        assert!(written.contains("doubled=42"), "{}", written);
    }

    #[tokio::test]
    async fn a_plugin_without_extra_arguments_still_loads() {
        let dir = TempDir::new("no-args");
        // Uses no arguments, so it can run without an output path.
        std::fs::write(
            dir.0.join("init.lua"),
            "local p = {}\nfunction p.init(a) end\nfunction p.process_data(r) end\nreturn p\n",
        )
        .expect("write plugin");

        let (manager, worker) = PluginManager::start(&config_for(&dir.0, None))
            .await
            .expect("a plugin with no extra_arguments must not fail to load");
        manager
            .process_flow_data(record(1), FlowIdentity::default())
            .await
            .expect("queued");
        manager.shutdown(worker).await;
    }

    #[tokio::test]
    async fn a_broken_plugin_is_skipped_without_stopping_the_others() {
        let dir = TempDir::new("broken");
        std::fs::write(dir.0.join("init.lua"), "this is not lua(((").expect("write plugin");

        let (manager, worker) = PluginManager::start(&config_for(&dir.0, None))
            .await
            .expect("a broken plugin must not fail the whole load");
        manager
            .process_flow_data(record(1), FlowIdentity::default())
            .await
            .expect("queued");
        manager.shutdown(worker).await;
    }
}
