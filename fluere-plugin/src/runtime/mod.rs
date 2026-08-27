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

/// A runtime compiled into this build.
///
/// An enum rather than a boxed trait object: the set of runtimes is fixed at
/// compile time by the feature flags, so there is nothing to gain from dynamic
/// dispatch and an allocation per runtime. [`PluginRuntime`] stays as the shared
/// interface each variant implements, which is what makes adding a language a
/// self-contained change.
#[derive(Debug)]
pub enum Runtime {
    #[cfg(feature = "lua")]
    Lua(lua::LuaRuntime),
    /// Present only when no runtime feature is enabled, so the enum is never
    /// empty and the manager needs no special case for it.
    #[cfg(not(feature = "lua"))]
    None,
}

impl Runtime {
    /// Every runtime this build can use, in the order plugin directories are
    /// offered to them.
    pub fn available() -> Vec<Runtime> {
        vec![
            #[cfg(feature = "lua")]
            Runtime::Lua(lua::LuaRuntime::new()),
        ]
    }

    /// Borrow the variant as the shared interface.
    fn as_runtime(&mut self) -> &mut dyn PluginRuntime {
        match self {
            #[cfg(feature = "lua")]
            Runtime::Lua(runtime) => runtime,
            #[cfg(not(feature = "lua"))]
            Runtime::None => unreachable!("no runtime is compiled into this build"),
        }
    }
}

impl PluginRuntime for Runtime {
    fn name(&self) -> &'static str {
        match self {
            #[cfg(feature = "lua")]
            Runtime::Lua(runtime) => runtime.name(),
            #[cfg(not(feature = "lua"))]
            Runtime::None => "none",
        }
    }

    fn entry_file(&self) -> &'static str {
        match self {
            #[cfg(feature = "lua")]
            Runtime::Lua(runtime) => runtime.entry_file(),
            #[cfg(not(feature = "lua"))]
            Runtime::None => "",
        }
    }

    fn load(
        &mut self,
        plugin: &str,
        directory: &Path,
        arguments: &HashMap<String, String>,
    ) -> Result<(), PluginError> {
        self.as_runtime().load(plugin, directory, arguments)
    }

    fn on_flow(&mut self, view: &FlowView) {
        self.as_runtime().on_flow(view);
    }

    fn cleanup(&mut self) {
        self.as_runtime().cleanup();
    }

    fn is_empty(&self) -> bool {
        match self {
            #[cfg(feature = "lua")]
            Runtime::Lua(runtime) => runtime.is_empty(),
            #[cfg(not(feature = "lua"))]
            Runtime::None => true,
        }
    }
}
