use ipc_channel::ipc::{self, IpcReceiver};

use std::sync::Arc;

pub trait PluginWrapperTrait {
    fn name(&self) -> String;
    fn process_flow_data(&mut self, data: &str);
}

pub struct PluginWrapper {
    plugin: Box<dyn PluginWrapperTrait>,
    receiver: Arc<IpcReceiver<String>>,
}

impl PluginWrapper {
    pub fn new(plugin: Box<dyn PluginWrapperTrait>, receiver: IpcReceiver<String>) -> Self {
        PluginWrapper {
            plugin,
            receiver: Arc::new(receiver),
        }
    }

    pub fn run(&mut self) {
        loop {
            match self.receiver.recv() {
                Ok(data) => {
                    self.plugin.process_flow_data(&data);
                }
                Err(_) => break, // Handle error or exit condition
            }
        }
    }
}

