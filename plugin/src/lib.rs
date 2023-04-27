use std::collections::HashMap;

// A trait that all plugins must implement
trait Plugin {
    fn run(&self);
}

// A struct that represents an in-process plugin
pub struct InProcessPlugin {
    name: String,
    path: String,
}

impl InProcessPlugin {
    pub fn new(name: String, path: String) -> InProcessPlugin {
        InProcessPlugin { name, path }
    }
}

impl Plugin for InProcessPlugin {
    fn run(&self) {
        println!(
            "Running in-process plugin: {} from path: {}",
            self.name, self.path
        );
    }
}

// A struct that represents an external program plugin
pub struct ExternalProgramPlugin {
    name: String,
    path: String,
}

impl ExternalProgramPlugin {
    pub fn new(name: String, path: String) -> ExternalProgramPlugin {
        ExternalProgramPlugin { name, path }
    }
}

impl Plugin for ExternalProgramPlugin {
    fn run(&self) {
        println!(
            "Running external program plugin: {} from path: {}",
            self.name, self.path
        );
    }
}

// A struct that represents the plugin manager
pub struct PluginManager {
    plugins: HashMap<String, Box<dyn Plugin>>,
}

impl PluginManager {
    pub fn new() -> PluginManager {
        PluginManager {
            plugins: HashMap::new(),
        }
    }

    pub fn add_in_process_plugin(&mut self, plugin: InProcessPlugin) {
        self.plugins
            .insert(plugin.name.clone(), Box::new(plugin) as Box<dyn Plugin>);
    }

    pub fn add_external_program_plugin(&mut self, plugin: ExternalProgramPlugin) {
        self.plugins
            .insert(plugin.name.clone(), Box::new(plugin) as Box<dyn Plugin>);
    }

    pub fn run_plugins(&self) {
        for (_, plugin) in self.plugins.iter() {
            plugin.run();
        }
    }
}
