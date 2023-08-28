use fluere_config::Config;
use fluereflow::FluereRecord;
use rlua::{Lua, Result};

pub struct PluginManager {
    lua: Lua,
}

impl PluginManager {
    pub fn new() -> Result<Self> {
        let lua = Lua::new();
        Ok(PluginManager { lua })
    }

    pub fn load_plugins(&self, config: &Config) -> Result<()> {
        for (name, plugin_config) in &config.plugins {
            if plugin_config.enabled {
                // Assuming the path in the config points to a Lua script
                let lua_code = match std::fs::read_to_string(&plugin_config.path){
                    Ok(code) => code,
                    Err(_) => {
                        println!("Failed to read plugin: {}", name);
                        continue;
                    }
                };

                self.lua.context(|ctx| {
                    // Load and execute the Lua plugin code
                    ctx.load(&lua_code).exec()
                }).expect("Failed to load plugin {name}");
                println!("Loaded plugin {}", name);
            }
        }
        Ok(())
    }


    pub fn process_flow_data(&self, data: &FluereRecord) -> Result<()> {
    self.lua.context(|ctx| {
        // Convert the FluereRecord to a Vec<String>
        let lua_slice = data.to_slice();

        // Convert the Vec<String> to a Lua table
        let lua_table = ctx.create_table()?;
        for (index, value) in lua_slice.iter().enumerate() {
            lua_table.set(index + 1, value.as_str())?;
        }

        // Assuming there's a function in Lua named `process_data`
        let func: rlua::Function = ctx.globals().get("process_data")?;
        func.call(lua_table)
    })?;
    Ok(())
}




}
