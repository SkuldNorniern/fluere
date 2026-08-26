//! Loading and running Fluere's Lua plugins.
//!
//! Plugins are untrusted, optional code. Nothing a plugin does — failing to
//! load, raising a Lua error, or missing an expected function — is allowed to
//! stop the capture that feeds it.

use std::borrow::Cow;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub mod downloader;
mod error;
mod record;
mod util;

use downloader::download_plugin_from_github;
use util::home_cache_path;

pub use downloader::DownloadError;
pub use error::PluginError;

use fluere_config::{Config, Plugin};
use fluereflow::FluereRecord;
use mlua::Lua;
use tokio::sync::{mpsc, Mutex};

#[cfg(feature = "log")]
use log::{debug, info, warn};

/// Capacity of the queue between the capture path and the plugin worker.
const CHANNEL_CAPACITY: usize = 100;

/// Report a plugin problem without bringing anything down.
macro_rules! plugin_warn {
    ($($arg:tt)*) => {{
        #[cfg(feature = "log")]
        warn!($($arg)*);
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

#[derive(Debug)]
pub struct PluginManager {
    lua: Arc<Mutex<Lua>>,
    sender: mpsc::Sender<FluereRecord>,
    receiver: Arc<Mutex<mpsc::Receiver<FluereRecord>>>,
    plugins: Arc<Mutex<HashSet<Cow<'static, str>>>>,
}

impl PluginManager {
    pub fn new() -> Result<Self, PluginError> {
        let (sender, receiver) = mpsc::channel::<FluereRecord>(CHANNEL_CAPACITY);

        Ok(PluginManager {
            lua: Arc::new(Mutex::new(Lua::new())),
            sender,
            receiver: Arc::new(Mutex::new(receiver)),
            plugins: Arc::new(Mutex::new(HashSet::new())),
        })
    }

    /// Load every enabled plugin named in `config`.
    ///
    /// A plugin that cannot be found, downloaded, read, or initialised is
    /// reported and skipped; the remaining plugins still load.
    pub async fn load_plugins(&self, config: &Config) -> Result<(), PluginError> {
        #[cfg(feature = "log")]
        debug!("Loading plugins");

        let mut loaded = self.plugins.lock().await;

        for (name, plugin_config) in &config.plugins {
            if !plugin_config.enabled {
                continue;
            }

            let directory = match self.plugin_directory(name, plugin_config) {
                Ok(directory) => directory,
                Err(error) => {
                    plugin_warn!("Unable to locate plugin {}: {}", name, error);
                    continue;
                }
            };

            match self.load_plugin(name, &directory, plugin_config).await {
                Ok(()) => {
                    loaded.insert(Cow::Owned(name.clone()));
                    plugin_info!("Loaded plugin {}", name);
                }
                Err(error) => plugin_warn!("Failed to load plugin {}: {}", name, error),
            }
        }

        Ok(())
    }

    /// Where a plugin's `init.lua` lives: the configured path, or the cache
    /// directory it gets downloaded into.
    fn plugin_directory(&self, name: &str, plugin_config: &Plugin) -> Result<PathBuf, PluginError> {
        match plugin_config.path.as_ref() {
            Some(path) => Ok(PathBuf::from(path)),
            None => {
                download_plugin_from_github(name)?;
                let directory = name.rsplit('/').next().unwrap_or(name);
                Ok(home_cache_path()?.join(directory))
            }
        }
    }

    /// Evaluate one plugin's `init.lua`, call its `init`, and register the
    /// table it returns under the plugin's name.
    async fn load_plugin(
        &self,
        name: &str,
        directory: &Path,
        plugin_config: &Plugin,
    ) -> Result<(), PluginError> {
        let code = std::fs::read_to_string(directory.join("init.lua"))?;

        let lua_guard = self.lua.lock().await;
        let lua = &*lua_guard;

        #[cfg(feature = "log")]
        debug!("Lua path: {}", directory.display());

        // Let the plugin `require` its own modules.
        let package_path = format!(
            "package.path = package.path .. \";{}/?.lua\"",
            directory.display()
        );
        if let Err(error) = lua.load(package_path).exec() {
            plugin_warn!("Could not extend package.path for {}: {}", name, error);
        }

        let plugin_table: mlua::Table = lua.load(&code).eval()?;
        let init: mlua::Function = plugin_table.get("init")?;

        let arguments = lua.create_table()?;
        if let Some(extra) = plugin_config.extra_arguments.as_ref() {
            #[cfg(feature = "log")]
            debug!("extra argument details {:?}", extra);

            for (key, value) in extra {
                arguments.set(key.as_str(), value.as_str())?;
            }
        }

        init.call::<_, ()>(arguments)?;
        lua.globals().set(name, plugin_table)?;

        Ok(())
    }

    /// Spawn the task that hands captured records to every loaded plugin.
    pub fn start_worker(&self) -> PluginWorker {
        let lua = self.lua.clone();
        let plugins = self.plugins.clone();
        let receiver = self.receiver.clone();

        let handle = tokio::spawn(async move {
            let mut receiver = receiver.lock().await;

            while let Some(data) = receiver.recv().await {
                let lua_guard = lua.lock().await;
                let plugins_guard = plugins.lock().await;

                let table = match record::to_lua_table(&lua_guard, &data) {
                    Ok(table) => table,
                    Err(error) => {
                        plugin_warn!("Could not build the record table: {}", error);
                        continue;
                    }
                };

                for plugin_name in plugins_guard.iter() {
                    dispatch(&lua_guard, plugin_name, &table);
                }
            }
        });

        PluginWorker { handle }
    }

    /// Queue one record for the plugins.
    pub async fn process_flow_data(&self, data: FluereRecord) -> Result<(), PluginError> {
        self.sender
            .send(data)
            .await
            .map_err(|_| PluginError::WorkerStopped)
    }

    /// Drain the queue, stop the worker, then run each plugin's `cleanup`.
    ///
    /// Consuming `self` is what makes the ordering reliable: dropping the last
    /// sender closes the channel, so the worker processes everything already
    /// queued and only then returns. Cleanup runs after that, never alongside
    /// records still in flight.
    pub async fn shutdown(self, worker: PluginWorker) {
        let PluginManager {
            lua,
            sender,
            receiver: _,
            plugins,
        } = self;

        drop(sender);

        if let Err(error) = worker.handle.await {
            plugin_warn!("Plugin worker did not stop cleanly: {}", error);
        }

        let lua_guard = lua.lock().await;
        let plugins_guard = plugins.lock().await;

        for plugin_name in plugins_guard.iter() {
            let plugin_table: mlua::Table = match lua_guard.globals().get(plugin_name.as_ref()) {
                Ok(table) => table,
                Err(error) => {
                    plugin_warn!("Plugin table missing for {}: {}", plugin_name, error);
                    continue;
                }
            };

            match plugin_table.get::<_, mlua::Function>("cleanup") {
                Ok(cleanup) => {
                    if let Err(error) = cleanup.call::<(), ()>(()) {
                        plugin_warn!("Error in cleanup of plugin {}: {}", plugin_name, error);
                    }
                }
                Err(_) => plugin_warn!("cleanup function not found in plugin: {}", plugin_name),
            }
        }
    }
}

/// Call one plugin's `process_data` with the record table.
///
/// Errors are reported and swallowed: one broken plugin must not stop the
/// others from seeing the record, nor stop the worker.
fn dispatch(lua: &Lua, plugin_name: &str, table: &mlua::Table<'_>) {
    let plugin_table: mlua::Table = match lua.globals().get(plugin_name) {
        Ok(table) => table,
        Err(error) => {
            plugin_warn!("Plugin table missing for {}: {}", plugin_name, error);
            return;
        }
    };

    match plugin_table.get::<_, mlua::Function>("process_data") {
        Ok(process) => {
            if let Err(error) = process.call::<mlua::Table<'_>, ()>(table.clone()) {
                plugin_warn!("Error in plugin {}: {}", plugin_name, error);
            }
        }
        Err(_) => plugin_warn!(
            "'process_data' function not found in plugin: {}",
            plugin_name
        ),
    }
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
                .process_flow_data(record(port))
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
        manager.process_flow_data(record(1)).await.expect("queued");
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
        manager.process_flow_data(record(1)).await.expect("queued");
        manager.shutdown(worker).await;
    }
}
