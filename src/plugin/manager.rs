use fluere_plugin::InProcessPlugin;
use fluere_plugin::PluginManager;

pub fn plugin_setup() {
    let test = InProcessPlugin::new(
        "test_plugin".to_string(),
        "target/debug/libtest_plugin.so".to_string(),
    );

    let mut plugin_manager = PluginManager::new();
    plugin_manager.add_in_process_plugin(test);
    plugin_manager.run_plugins();
}
pub fn plugin_execute() {
    let plugin_manager = PluginManager::new();
    plugin_manager.run_plugins();
}

pub fn plugin_stage() {
    plugin_setup();
    plugin_execute();
}
