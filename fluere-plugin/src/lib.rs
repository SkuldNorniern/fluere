use std::collections::HashSet;
use std::sync::Arc;

mod downloader;
mod util;

use std::borrow::Cow;

use downloader::download_plugin_from_github;
use util::home_cache_path;

use fluere_config::Config;
use fluereflow::FluereRecord;
use mlua::{Lua, Result};
use tokio::sync::{mpsc, Mutex};

#[cfg(feature = "log")]
use log::{debug, error, info, warn};

pub struct PluginManager {
    lua: Arc<Mutex<Lua>>,
    sender: mpsc::Sender<FluereRecord>,
    receiver: Arc<Mutex<mpsc::Receiver<FluereRecord>>>,
    plugins: Arc<Mutex<HashSet<Cow<'static, str>>>>,
}

impl PluginManager {
    pub fn new() -> Result<Self> {
        let lua = Arc::new(Mutex::new(Lua::new()));
        let (sender, receiver) = mpsc::channel::<FluereRecord>(100); // 100 is the channel capacity
        let plugins = Arc::new(Mutex::new(HashSet::new()));

        Ok(PluginManager {
            lua,
            sender,
            receiver: Arc::new(Mutex::new(receiver)),
            plugins,
        })
    }

    pub async fn load_plugins(&self, config: &Config) -> Result<()> {
        #[cfg(feature = "log")]
        debug!("Loading plugins");

        let plugins_clone = self.plugins.clone();
        let mut plugins_guard = plugins_clone.lock().await;
        for (name, plugin_config) in &config.plugins {
            if plugin_config.enabled {
                // Assuming the path in the config points to a Lua script
                match plugin_config.path.clone() {
                    Some(path) => {
                        let mut owned_path_str = path.clone();
                        let name_of_main_file = "/init.lua";
                        owned_path_str.push_str(name_of_main_file);

                        match std::fs::read_to_string(owned_path_str) {
                            Ok(code) => {
                                let lua_clone = self.lua.clone();
                                let lua_guard = lua_clone.lock().await;
                                let lua = &*lua_guard;

                                #[cfg(feature = "log")]
                                debug!("Lua path: {}", path);

                                let lua_plugin_path =
                                    format!("package.path = package.path .. \";{}/?.lua\"", path);
                                let _ = lua.load(lua_plugin_path).exec();

                                let chunk = lua.load(&code);
                                let plugin_table: mlua::Table = chunk.eval()?;
                                let func: mlua::Function = plugin_table.get("init")?;

                                let argument_table = lua.create_table()?;

                                #[cfg(feature = "log")]
                                debug!("extra argument details{:?}", plugin_config.extra_arguments);

                                for (key, value) in
                                    plugin_config.extra_arguments.clone().unwrap().iter()
                                {
                                    argument_table.set(key.as_str(), value.as_str())?;
                                }

                                func.call(argument_table)?;
                                lua.globals().set(name.as_str(), plugin_table)?;
                                /*let _ = lua_guard.context(|ctx| -> mlua::Result<()> {
                                // Load the Lua plugin code into a chunk
                                let chunk = ctx.load(&code);

                                // Execute the chunk, which will return the plugin table
                                let plugin_table: rlua::Table = chunk.eval()?;

                                // Try to retrieve the init function
                                let func: rlua::Function = plugin_table.get("init").expect("init function not found");
                                func.call("alive")?;

                                // Store the table in the global context with the plugin's name
                                ctx.globals().set(name.as_str(), plugin_table)?;

                                Ok(())
                                }).expect(format!("Error on plugin: {}", name).as_str(()));*/
                                //lua_guard.load(&code).exec().expect(format!("Error on plugin: {}", name).as_str());
                                let _ = plugins_guard.insert(std::borrow::Cow::Owned(name.clone()));
                                #[cfg(feature = "log")]
                                info!("Loaded plugin {}", name);
                                #[cfg(not(feature = "log"))]
                                println!("Loaded plugin {}", name);
                            }
                            Err(err) => {
                                #[cfg(feature = "log")]
                                {
                                    warn!("Failed to read plugin: {}", name);
                                    error!("Error: {}", err);
                                }
                                #[cfg(not(feature = "log"))]
                                {
                                    println!("Failed to read plugin: {}", name);
                                    println!("Error: {}", err);
                                }
                                continue;
                            }
                        };
                    }
                    None => {
                        match download_plugin_from_github(name) {
                            Ok(_) => {
                                let path = home_cache_path()?.join(name.split('/').last().unwrap());
                                match std::fs::read_to_string(path.join("init.lua")) {
                                    Ok(code) => {
                                        let lua_clone = self.lua.clone();
                                        let lua_guard = lua_clone.lock().await;
                                        let lua = &*lua_guard;

                                        let lua_plugin_path = format!(
                                            "package.path = package.path .. \";{}/?.lua\"",
                                            path.to_str().unwrap()
                                        );
                                        let _ = lua.load(lua_plugin_path).exec();
                                        // println!("lua path: {}", path.to_str().unwrap());

                                        let chunk = lua.load(&code);
                                        let plugin_table: mlua::Table = chunk.eval()?;
                                        let func: mlua::Function = plugin_table.get("init")?;

                                        let argument_table = lua.create_table()?;

                                        // println!("extra argument details{:?}", plugin_config.extra_arguments);
                                        for (key, value) in
                                            plugin_config.extra_arguments.clone().unwrap().iter()
                                        {
                                            argument_table.set(key.as_str(), value.as_str())?;
                                        }

                                        func.call(argument_table)?;
                                        lua.globals().set(name.as_str(), plugin_table)?;
                                        /*let _ = lua_guard.context(|ctx| -> rlua::Result<()> {
                                        // Load the Lua plugin code into a chunk
                                        let chunk = ctx.load(&code);
                                        let chunk =
                                        // Execute the chunk, which will return the plugin table
                                        let plugin_table: rlua::Table = chunk.eval()?;

                                        // Try to retrieve the init function
                                        let func: rlua::Function = plugin_table.get("init").expect("init function not found");
                                        func.call("alive")?;

                                        // Store the table in the global context with the plugin's name
                                        ctx.globals().set(name.as_str(), plugin_table)?;

                                        Ok(())
                                        }).expect(format!("Error on plugin: {}", name).as_str());*/
                                        let _ = plugins_guard
                                            .insert(std::borrow::Cow::Owned(name.clone()));
                                        #[cfg(feature = "log")]
                                        info!("Loaded plugin {}", name);
                                        #[cfg(not(feature = "log"))]
                                        println!("Loaded plugin {}", name);
                                    }
                                    Err(eri) => {
                                        #[cfg(feature = "log")]
                                        {
                                            warn!("Failed to read plugin: {}", name);
                                            error!("Error: {}", eri);
                                        }
                                        #[cfg(not(feature = "log"))]
                                        {
                                            println!("Failed to read plugin: {}", name);
                                            println!("Error: {}", eri);
                                        }
                                        continue;
                                    }
                                }
                            }
                            Err(eri) => {
                                #[cfg(feature = "log")]
                                {
                                    warn!("Unable to download plugin: {}", name);
                                    error!("Error: {}", eri);
                                }
                                #[cfg(not(feature = "log"))]
                                {
                                    println!("Unable to download plugin: {}", name);
                                    println!("Error: {}", eri);
                                }
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }
    pub fn start_worker(&self) -> Arc<Mutex<tokio::task::JoinHandle<()>>> {
        let lua_clone = self.lua.clone();
        let plugins_clone = self.plugins.clone();
        let receiver_clone = self.receiver.clone();

        Arc::new(Mutex::new(tokio::spawn(async move {
            let mut receiver_guard = receiver_clone.lock().await;
            while let Some(data) = receiver_guard.recv().await {
                let lua_clone = lua_clone.clone();
                let plugins_clone = plugins_clone.clone();
                tokio::task::spawn(async move {
                    let lua_guard = lua_clone.lock().await;
                    let plugins = plugins_clone.lock().await;

                    let record_vec = data.to_vec();
                    let lua = &*lua_guard;
                    let lua_table = lua.create_table().expect("Failed to create Lua table");

                    // Set the values in the Lua table
                    for (index, key) in [
                        "source",
                        "destination",
                        "d_pkts",
                        "d_octets",
                        "first",
                        "last",
                        "src_port",
                        "dst_port",
                        "min_pkt",
                        "max_pkt",
                        "min_ttl",
                        "max_ttl",
                        "in_pkts",
                        "out_pkts",
                        "in_bytes",
                        "out_bytes",
                        "fin_cnt",
                        "syn_cnt",
                        "rst_cnt",
                        "psh_cnt",
                        "ack_cnt",
                        "urg_cnt",
                        "ece_cnt",
                        "cwr_cnt",
                        "ns_cnt",
                        "prot",
                        "tos",
                    ]
                    .iter()
                    .enumerate()
                    {
                        lua_table
                            .set(*key, record_vec[index].clone())
                            .unwrap_or_else(|_| panic!("Failed to set key: {}", key));
                    }

                    for plugin_name in plugins.iter() {
                        let plugin_table: mlua::Table = lua
                            .globals()
                            .get(plugin_name.as_ref())
                            .expect("Plugin table not found");

                        if let Ok(func) = plugin_table.get::<_, mlua::Function>("process_data") {
                            func.call::<mlua::Table<'_>, ()>(lua_table.clone())
                                .unwrap_or_else(|_| panic!("Error on plugin: {}", plugin_name));
                        } else {
                            #[cfg(feature = "log")]
                            error!(
                                "'process_data' function not found in plugin: {}",
                                plugin_name
                            );

                            #[cfg(not(feature = "log"))]
                            println!(
                                "'process_data' function not found in plugin: {}",
                                plugin_name
                            );
                        }
                    }
                })
                .await
                .expect("Error on plugin");
            }
        })))
    }

    pub async fn process_flow_data(&self, data: FluereRecord) -> Result<()> {
        self.sender.send(data).await.unwrap();
        Ok(())
    }

    pub async fn await_completion(&self, target_worker: Arc<Mutex<tokio::task::JoinHandle<()>>>) {
        let worker_clone = target_worker.clone();
        let worker = worker_clone.lock().await;

        // Cleanup each plugin before exiting
        let lua_clone = self.lua.clone();
        let plugins_clone = self.plugins.clone();

        let lua = lua_clone.lock().await;
        let plugins = plugins_clone.lock().await;

        for plugin_name in plugins.iter() {
            let plugin_table: mlua::Table = lua
                .globals()
                .get(plugin_name.as_ref())
                .expect("Plugin table not found");

            if let Ok(func) = plugin_table.get::<_, mlua::Function>("cleanup") {
                func.call::<(), ()>(())
                    .unwrap_or_else(|_| panic!("Error on plugin: {}", plugin_name));
            } else {
                #[cfg(feature = "log")]
                warn!("cleanup function not found in plugin: {}", plugin_name);
                #[cfg(not(feature = "log"))]
                println!("cleanup function not found in plugin: {}", plugin_name);
            }
        }

        drop(lua);
        drop(plugins);
        drop(worker);
    }
}

impl Drop for PluginManager {
    fn drop(&mut self) {
        drop(self.plugins.lock());
        drop(self.lua.lock());
    }
}
