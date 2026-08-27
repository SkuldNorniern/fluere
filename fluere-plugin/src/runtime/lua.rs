//! The Lua plugin runtime.

use std::collections::HashMap;
use std::path::Path;

use mlua::Lua;

use crate::error::PluginError;
use crate::view::{FieldValue, FlowView};
use crate::{plugin_warn, runtime::PluginRuntime};

#[cfg(feature = "log")]
use log::debug;

/// Holds one Lua state with every Lua plugin loaded into it.
#[derive(Debug)]
pub struct LuaRuntime {
    lua: Lua,
    /// Global names the loaded plugin tables are registered under.
    plugins: Vec<String>,
}

impl LuaRuntime {
    pub fn new() -> Self {
        LuaRuntime {
            lua: Lua::new(),
            plugins: Vec::new(),
        }
    }

    /// Build the table a plugin's `process_data` receives.
    fn table<'lua>(lua: &'lua Lua, view: &FlowView) -> mlua::Result<mlua::Table<'lua>> {
        let table = lua.create_table()?;
        table.set("schema_version", view.schema_version)?;

        for (name, value) in &view.fields {
            match value {
                FieldValue::Text(text) => table.set(*name, text.as_str())?,
                FieldValue::Unsigned(number) => table.set(*name, *number)?,
                FieldValue::Bool(flag) => table.set(*name, *flag)?,
                // Left unset: in Lua an absent key reads as nil, which is what
                // "does not apply to this flow" means. Writing 0 would make it
                // indistinguishable from a real zero.
                FieldValue::Absent => {}
            }
        }

        Ok(table)
    }

    /// Call `hook` on every loaded plugin, reporting failures without stopping.
    fn call_hook(&self, hook: &str, table: Option<&mlua::Table<'_>>) {
        for plugin in &self.plugins {
            let plugin_table: mlua::Table = match self.lua.globals().get(plugin.as_str()) {
                Ok(table) => table,
                Err(error) => {
                    plugin_warn!("Plugin table missing for {}: {}", plugin, error);
                    continue;
                }
            };

            let Ok(function) = plugin_table.get::<_, mlua::Function>(hook) else {
                plugin_warn!("'{}' function not found in plugin: {}", hook, plugin);
                continue;
            };

            let result = match table {
                Some(table) => function.call::<mlua::Table<'_>, ()>(table.clone()),
                None => function.call::<(), ()>(()),
            };
            if let Err(error) = result {
                plugin_warn!("Error in {} of plugin {}: {}", hook, plugin, error);
            }
        }
    }
}

impl Default for LuaRuntime {
    fn default() -> Self {
        Self::new()
    }
}

impl PluginRuntime for LuaRuntime {
    fn name(&self) -> &'static str {
        "lua"
    }

    fn entry_file(&self) -> &'static str {
        "init.lua"
    }

    fn load(
        &mut self,
        plugin: &str,
        directory: &Path,
        arguments: &HashMap<String, String>,
    ) -> Result<(), PluginError> {
        let code = std::fs::read_to_string(directory.join(self.entry_file()))?;

        #[cfg(feature = "log")]
        debug!("Loading Lua plugin from {}", directory.display());

        // Let the plugin `require` its own modules.
        let package_path = format!(
            "package.path = package.path .. \";{}/?.lua\"",
            directory.display()
        );
        if let Err(error) = self.lua.load(package_path).exec() {
            plugin_warn!("Could not extend package.path for {}: {}", plugin, error);
        }

        let plugin_table: mlua::Table = self.lua.load(&code).eval()?;
        let init: mlua::Function = plugin_table.get("init")?;

        let argument_table = self.lua.create_table()?;
        for (key, value) in arguments {
            argument_table.set(key.as_str(), value.as_str())?;
        }

        init.call::<_, ()>(argument_table)?;
        self.lua.globals().set(plugin, plugin_table)?;
        self.plugins.push(plugin.to_string());

        Ok(())
    }

    fn on_flow(&mut self, view: &FlowView) {
        let table = match Self::table(&self.lua, view) {
            Ok(table) => table,
            Err(error) => {
                plugin_warn!("Could not build the record table: {}", error);
                return;
            }
        };

        self.call_hook("process_data", Some(&table));
    }

    fn cleanup(&mut self) {
        self.call_hook("cleanup", None);
    }

    fn is_empty(&self) -> bool {
        self.plugins.is_empty()
    }
}
