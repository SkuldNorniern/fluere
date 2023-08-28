use ipc_channel::ipc::IpcReceiver;
use std::sync::Arc;

pub trait PluginWrapperTrait {
    fn name(&self) -> String;
    fn run(&mut self, receiver: Arc<IpcReceiver<String>>);
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
        self.plugin.run(self.receiver.clone());
    }
}

