use fluere_config::Config;
use fluereflow::FluereRecord;
use mlua::{Lua, Result};
use tokio::sync::{mpsc, Mutex};

use std::sync::Arc;
use std::collections::HashSet;

mod downloader;
mod util;

use downloader::download_plugin_from_github;
use util::home_cache_path;

pub struct PluginManager {
    lua: Arc<Mutex<Lua>>,
    sender: mpsc::Sender<FluereRecord>,
    receiver: Arc<Mutex<mpsc::Receiver<FluereRecord>>>,
    //worker: Arc<Mutex<tokio::task::JoinHandle<()>>>,
    plugins: Arc<Mutex<HashSet<String>>>,
}

impl PluginManager {
    pub fn new() -> Result<Self> {
        let lua = Arc::new(Mutex::new(Lua::new()));
        let (sender, receiver) = mpsc::channel::<FluereRecord>(100); // 100 is the channel capacity
        let plugins =  Arc::new(Mutex::new(HashSet::new()));
        //let _ = Self::load_plugins config).await;

        //let worker = Self::start_worker(lua.clone(), receiver, plugins.clone());
        ;        /*
        let worker = Arc::new(Mutex::new(tokio::spawn(async move {
        while let Some(data) = receiver.recv().await {
        let lua_guard = lua_clone.lock().await;
        let plugins = plugins_clone.lock().await;

        let _ = lua_guard.context(|ctx| -> rlua::Result<()> {
        // Convert the FluereRecord to a Vec<String>
        let record_vec = data.to_vec();

        // Convert the Vec<String> to a Lua table
        let lua_table = ctx.create_table()?;
        lua_table.set("source", record_vec[0].clone())?;
        lua_table.set("destination", record_vec[1].clone())?;
        lua_table.set("d_pkts", record_vec[2].clone())?;
        lua_table.set("d_octets", record_vec[3].clone())?;
        lua_table.set("first", record_vec[4].clone())?;
        lua_table.set("last", record_vec[5].clone())?;
        lua_table.set("src_port", record_vec[6].clone())?;
        lua_table.set("dst_port", record_vec[7].clone())?;
        lua_table.set("min_pkt", record_vec[8].clone())?;
        lua_table.set("max_pkt", record_vec[9].clone())?;
        lua_table.set("min_ttl", record_vec[10].clone())?;
        lua_table.set("max_ttl", record_vec[11].clone())?;
        lua_table.set("in_pkts", record_vec[12].clone())?;
        lua_table.set("out_pkts", record_vec[13].clone())?;
        lua_table.set("in_bytes", record_vec[14].clone())?;
        lua_table.set("out_bytes", record_vec[15].clone())?;
        lua_table.set("fin_cnt", record_vec[16].clone())?;
        lua_table.set("syn_cnt", record_vec[17].clone())?;
        lua_table.set("rst_cnt", record_vec[18].clone())?;
        lua_table.set("psh_cnt", record_vec[19].clone())?;
        lua_table.set("ack_cnt", record_vec[20].clone())?;
        lua_table.set("urg_cnt", record_vec[21].clone())?;
        lua_table.set("ece_cnt", record_vec[22].clone())?;
        lua_table.set("cwr_cnt", record_vec[23].clone())?;
        lua_table.set("ns_cnt", record_vec[24].clone())?;
        lua_table.set("prot", record_vec[25].clone())?;
        lua_table.set("tos", record_vec[26].clone())?;

        // Assuming there's a function in Lua named `process_data`
        for plugin_name in plugins.iter() {
        let plugin_table: rlua::Table = ctx.globals().get(plugin_name.as_str())?;
        let func: rlua::Function = plugin_table.get("process_data")?;
        func.call(lua_table.clone())?;
        }
        Ok(())
        });
        }
        })));
         */
        Ok(PluginManager {
            lua,
            sender,
            receiver: Arc::new(Mutex::new(receiver)),
            //worker: Arc::new(Mutex::new(tokio::task::JoinHandle::new())),
            plugins
        })
    }

    pub async fn load_plugins(&self, config: &Config) -> Result<()> {

        let plugins_clone= self.plugins.clone();
        let mut plugins_guard = plugins_clone.lock().await;
        for (name, plugin_config) in &config.plugins {
            if plugin_config.enabled {
                // Assuming the path in the config points to a Lua script
                match plugin_config.path.clone() {
                    Some(path) => {
                        match std::fs::read_to_string(path) {
                            Ok(code) => {
                                let lua_clone = self.lua.clone();
                                let lua_guard = lua_clone.lock().await;
                                let lua = &*lua_guard;
                                let chunk = lua.load(&code);
                                let plugin_table: mlua::Table = chunk.eval()?;
                                let func: mlua::Function = plugin_table.get("init")?;
                                func.call("alive")?;
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

                                plugins_guard.insert(name.clone());
                                println!("Loaded plugin {}", name);
                            },
                            Err(_) => {
                                println!("Failed to read plugin: {}", name);
                                continue;
                            }
                        };
                    }
                    None => {
                        match download_plugin_from_github(name) {
                            Ok(_) => {
                                match std::fs::read_to_string(
                                    home_cache_path()
                                        .join(name.split('/').last().unwrap())
                                        .join("init.lua"),
                                ) {
                                    Ok(code) => {
                                        let lua_clone = self.lua.clone();
                                        let lua_guard = lua_clone.lock().await;
                                        let lua = &*lua_guard;
                                        let chunk = lua.load(&code);
                                        let plugin_table: mlua::Table = chunk.eval()?;
                                        let func: mlua::Function = plugin_table.get("init")?;
                                        func.call("alive")?;
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
                                        plugins_guard.insert(name.clone());
                                        println!("Loaded plugin {}", name);
                                    },
                                    Err(_) => {
                                        println!("Failed to read plugin: {}", name);
                                        continue;
                                    }
                                }
                                println!("Loaded plugin {}", name);
                            }
                            Err(_) => {
                                println!("Unable to download plugin: {}", name);
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
                        "source", "destination", "d_pkts", "d_octets", "first", "last", "src_port", "dst_port",
                        "min_pkt", "max_pkt", "min_ttl", "max_ttl", "in_pkts", "out_pkts", "in_bytes", "out_bytes",
                        "fin_cnt", "syn_cnt", "rst_cnt", "psh_cnt", "ack_cnt", "urg_cnt", "ece_cnt", "cwr_cnt",
                        "ns_cnt", "prot", "tos"
                    ].iter().enumerate() {
                        lua_table.set(*key, record_vec[index].clone())
                            .expect(format!("Failed to set key: {}", key).as_str());
                    }

                    for plugin_name in plugins.iter() {
                        let plugin_table: mlua::Table = lua.globals().get(plugin_name.as_str())
                            .expect("Plugin table not found");

                        if let Ok(func) = plugin_table.get::<_, mlua::Function>("process_data") {
                            func.call::<mlua::Table<'_>, ()>(lua_table.clone())
                                .expect(format!("Error on plugin: {}", plugin_name).as_str());
                        } else {
                            println!("'process_data' function not found in plugin: {}", plugin_name);
                        }
                    }
                }).await.expect("Error on plugin");
            }
        })))
    }

    pub async fn process_flow_data(&self, data: FluereRecord) -> Result<()> {
        self.sender.send(data).await.unwrap();
        Ok(())
    }

    pub async fn await_completion(&self, target_worker: Arc<Mutex<tokio::task::JoinHandle<()>>>) {
        let worker_clone = target_worker.clone();
        let _ = worker_clone.lock().await;

        // Cleanup each plugin before exiting

    }

}



