use serde::{Deserialize, Serialize};

use std::collections::BTreeMap;
use std::collections::HashMap;

pub type Plugins = BTreeMap<String, Plugin>;

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct Plugin {
    pub enabled: bool,
    pub path: Option<String>, // for unpublished plugins
    pub extra_arguments: Option<HashMap<String, String>>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct Config {
    pub plugins: Plugins,
}
