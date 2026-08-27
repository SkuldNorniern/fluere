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

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;

pub mod downloader;
mod error;
pub mod runtime;
mod util;
pub mod view;

use downloader::download_plugin_from_github;
use util::home_cache_path;

pub use downloader::DownloadError;
pub use error::PluginError;
pub use runtime::PluginRuntime;
pub use view::{FieldValue, FlowIdentity, FlowView, SCHEMA_VERSION};

use fluere_config::{Config, Plugin};
use fluereflow::FluereRecord;
use tokio::sync::{mpsc, Mutex};

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
/// Obtained from [`PluginManager::start_worker`] and handed back to
/// [`PluginManager::shutdown`], which is the only supported way to stop it.
#[derive(Debug)]
pub struct PluginWorker {
    handle: tokio::task::JoinHandle<()>,
}

pub struct PluginManager {
    runtimes: Arc<Mutex<Vec<Box<dyn PluginRuntime>>>>,
    sender: mpsc::Sender<(FluereRecord, FlowIdentity)>,
    receiver: Arc<Mutex<mpsc::Receiver<(FluereRecord, FlowIdentity)>>>,
    /// Names of the plugins that loaded, for reporting.
    loaded: Arc<Mutex<HashSet<String>>>,
}

impl PluginManager {
    pub fn new() -> Result<Self, PluginError> {
        let (sender, receiver) = mpsc::channel::<(FluereRecord, FlowIdentity)>(CHANNEL_CAPACITY);

        Ok(PluginManager {
            runtimes: Arc::new(Mutex::new(runtime::available())),
            sender,
            receiver: Arc::new(Mutex::new(receiver)),
            loaded: Arc::new(Mutex::new(HashSet::new())),
        })
    }

    /// Load every enabled plugin named in `config`.
    ///
    /// A plugin that cannot be found, downloaded, read, or initialised is
    /// reported and skipped; the remaining plugins still load.
    pub async fn load_plugins(&self, config: &Config) -> Result<(), PluginError> {
        #[cfg(feature = "log")]
        debug!("Loading plugins");

        let mut runtimes = self.runtimes.lock().await;
        let mut loaded = self.loaded.lock().await;

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
                    loaded.insert(name.clone());
                    plugin_info!("Loaded {} plugin {}", language, name);
                }
                Err(error) => plugin_warn!("Failed to load plugin {}: {}", name, error),
            }
        }

        Ok(())
    }

    /// Spawn the task that hands captured records to every loaded plugin.
    pub fn start_worker(&self) -> PluginWorker {
        let runtimes = self.runtimes.clone();
        let receiver = self.receiver.clone();

        let handle = tokio::spawn(async move {
            let mut receiver = receiver.lock().await;

            while let Some((record, identity)) = receiver.recv().await {
                // Built once and marshalled by each runtime, so the field list
                // lives in one place however many languages are loaded.
                let view = FlowView::new(&record, &identity);

                let mut runtimes = runtimes.lock().await;
                for runtime in runtimes.iter_mut() {
                    if !runtime.is_empty() {
                        runtime.on_flow(&view);
                    }
                }
            }
        });

        PluginWorker { handle }
    }

    /// Queue one finished flow for the plugins.
    ///
    /// `identity` is what separated this flow from another with the same
    /// addresses and ports; it lives on the flow key rather than the record.
    pub async fn process_flow_data(
        &self,
        data: FluereRecord,
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
    /// queued and only then returns. Cleanup runs after that, never alongside
    /// records still in flight.
    pub async fn shutdown(self, worker: PluginWorker) {
        let PluginManager {
            runtimes,
            sender,
            receiver: _,
            loaded: _,
        } = self;

        drop(sender);

        if let Err(error) = worker.handle.await {
            plugin_warn!("Plugin worker did not stop cleanly: {}", error);
        }

        let mut runtimes = runtimes.lock().await;
        for runtime in runtimes.iter_mut() {
            runtime.cleanup();
        }
    }
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
    let names: Vec<&str> = runtime::available()
        .iter()
        .map(|runtime| runtime.entry_file())
        .collect();

    (!names.is_empty()).then(|| names.join(", "))
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr};
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
    file:write("record " .. record.src_port .. "\n")
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

    fn record(src_port: u16) -> FluereRecord {
        FluereRecord::new(
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2)),
            1,
            60,
            1,
            1,
            src_port,
            443,
            60,
            60,
            64,
            64,
            0,
            1,
            0,
            60,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            6,
            0,
            false,
        )
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

        let manager = PluginManager::new().expect("manager");
        manager
            .load_plugins(&config_for(&dir.0, Some(arguments)))
            .await
            .expect("plugins load");
        let worker = manager.start_worker();

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
    file:write("d_pkts=" .. type(record.d_pkts) .. "\n")
    file:write("source=" .. type(record.source) .. "\n")
    file:write("mid_stream=" .. type(record.mid_stream) .. "\n")
    -- Arithmetic straight on the field, with no tonumber() call.
    file:write("doubled=" .. tostring(record.src_port * 2) .. "\n")
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

        let manager = PluginManager::new().expect("manager");
        manager
            .load_plugins(&config_for(&dir.0, Some(arguments)))
            .await
            .expect("plugins load");
        let worker = manager.start_worker();
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
        assert!(written.contains("d_pkts=number"), "{}", written);
        assert!(written.contains("source=string"), "{}", written);
        assert!(written.contains("mid_stream=boolean"), "{}", written);
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

        let manager = PluginManager::new().expect("manager");
        manager
            .load_plugins(&config_for(&dir.0, None))
            .await
            .expect("a plugin with no extra_arguments must not fail to load");

        let worker = manager.start_worker();
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

        let manager = PluginManager::new().expect("manager");
        manager
            .load_plugins(&config_for(&dir.0, None))
            .await
            .expect("a broken plugin must not fail the whole load");

        let worker = manager.start_worker();
        manager
            .process_flow_data(record(1), FlowIdentity::default())
            .await
            .expect("queued");
        manager.shutdown(worker).await;
    }
}
