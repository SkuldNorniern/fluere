use fluere_config::Config;
use fluereflow::FluereRecord;
use rlua::{Lua, Result};
use tokio::sync::{mpsc, Mutex};

use std::sync::Arc;
pub struct PluginManager {
    lua: Arc<Mutex<Lua>>,
    sender: mpsc::Sender<FluereRecord>,
    worker: Arc<Mutex<tokio::task::JoinHandle<()>>>,
}

impl PluginManager {
    pub fn new() -> Result<Self> {
        let lua = Arc::new(Mutex::new(Lua::new()));
        let (sender, mut receiver) = mpsc::channel::<FluereRecord>(100); // 100 is the channel capacity

        let lua_clone = lua.clone();
        let worker = Arc::new(Mutex::new(tokio::spawn(async move {
            while let Some(data) = receiver.recv().await {
                let lua_guard = lua_clone.lock().await;
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
                    let func: rlua::Function = ctx.globals().get("process_data")?;
                    func.call(lua_table)?;
                    Ok(())
                });
            }
        })));

        Ok(PluginManager {
            lua,
            sender,
            worker,
        })
    }

    pub async fn load_plugins(&self, config: &Config) -> Result<()> {
        for (name, plugin_config) in &config.plugins {
            if plugin_config.enabled {
                // Assuming the path in the config points to a Lua script
                let lua_code = match std::fs::read_to_string(&plugin_config.path.clone().unwrap()) {
                    Ok(code) => code,
                    Err(_) => {
                        println!("Failed to read plugin: {}", name);
                        continue;
                    }
                };
                let lua_clone = self.lua.clone();
                let lua_guard = lua_clone.lock().await;
                lua_guard
                    .context(|ctx| {
                        // Load and execute the Lua plugin code
                        ctx.load(&lua_code).exec()
                    })
                    .expect("Failed to load plugin {name}");
                println!("Loaded plugin {}", name);
            }
        }
        Ok(())
    }

    pub async fn process_flow_data(&self, data: FluereRecord) -> Result<()> {
        self.sender.send(data).await.unwrap();
        Ok(())
    }

    pub async fn await_completion(&self) {
        let worker_clone = self.worker.clone();
        let _ = worker_clone.lock().await;
    }

}
