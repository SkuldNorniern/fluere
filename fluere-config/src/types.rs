use serde::{Deserialize, Serialize};

use std::collections::BTreeMap;

pub type Plugins = BTreeMap<String, Plugin>;

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct Plugin {
    pub path: String,
    pub enabled: bool,
    // Add other fields as needed
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct Config {
    pub plugins: Plugins,
}
