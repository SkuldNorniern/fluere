use ipc_channel::ipc::{self, IpcSender, IpcReceiver};
use tokio::task;
use std::sync::Arc;
use std::thread;

use fluere_config::Plugin;
use fluere_config::Plugins;
use fluere_config::Config;
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};

pub struct PluginManager {
    plugins: Plugins,
    ipc_senders: Vec<IpcSender<String>>,
}

impl PluginManager {
    pub fn new() -> Self {
        PluginManager {
            plugins: Plugins::new(),
            ipc_senders: Vec::new(),
        }
    }

    pub async fn load_plugin(&mut self, path: &str) {
        // Create an IPC channel
        let (tx, rx) = ipc::channel().unwrap();

        // Store the sender in the manager
        self.ipc_senders.push(tx);

        // Start the plugin in a new tokio task
        //task::spawn(async move {

        //});
    }

    pub async fn process_flow_data(&mut self, data: &str) {
        // Send the data to all plugins via IPC
        for sender in &self.ipc_senders {
            sender.send(data.to_string()).unwrap();
        }
    }
}
