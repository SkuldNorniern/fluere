//! Plugin runtimes.
//!
//! A runtime owns an interpreter and the plugins loaded into it. Adding a
//! language means adding an implementation here and a feature to select it;
//! nothing in [`PluginManager`](crate::PluginManager) needs to change.

use std::collections::HashMap;
use std::path::Path;

use crate::error::PluginError;
use crate::view::FlowView;

#[cfg(feature = "lua")]
pub mod lua;

/// One language a plugin can be written in.
///
/// A runtime holds every plugin loaded into it and fans each flow out to all
/// of them, so one interpreter is shared rather than one per plugin.
pub trait PluginRuntime: Send {
    /// Short name, used in log messages.
    fn name(&self) -> &'static str;

    /// The entry file this runtime claims. A plugin directory is handed to the
    /// first runtime whose entry file it contains.
    fn entry_file(&self) -> &'static str;

    /// Evaluate the plugin in `directory` and call its initialiser.
    fn load(
        &mut self,
        plugin: &str,
        directory: &Path,
        arguments: &HashMap<String, String>,
    ) -> Result<(), PluginError>;

    /// Hand one finished flow to every plugin loaded into this runtime.
    ///
    /// A plugin that errors is reported and skipped: one bad plugin must not
    /// stop the others from seeing the flow.
    fn on_flow(&mut self, view: &FlowView);

    /// Run each loaded plugin's cleanup hook. Called once, after the queue has
    /// drained and the worker has stopped.
    fn cleanup(&mut self);

    /// Whether any plugin is loaded into this runtime.
    fn is_empty(&self) -> bool;
}

/// Every runtime compiled into this build, in the order plugin directories are
/// offered to them.
pub fn available() -> Vec<Box<dyn PluginRuntime>> {
    let runtimes: Vec<Box<dyn PluginRuntime>> = vec![
        #[cfg(feature = "lua")]
        Box::new(lua::LuaRuntime::new()),
    ];
    runtimes
}
