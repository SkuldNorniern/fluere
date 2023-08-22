use fluereplugin::PluginManager;
use fluereplugin::InProcessPlugin;

pub fn plugin_setup() {
    let mut plugin_manager = PluginManager::new();
    plugin_manager.load_plugin(
        "test_plugin".to_string(),
        "target/debug/libtest_plugin.so".to_string(),
    );
    plugin_manager.run_plugins();
}
pub fn plugin_execute() {
    let mut plugin_manager = PluginManager::new();
    plugin_manager.run_plugins();
}

pub fn plugin_stage() {
    plugin_setup();
    plugin_execute();
}
