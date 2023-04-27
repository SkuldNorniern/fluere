use std::fs;
use toml;

pub fn read_config() -> toml::Value {
    let config = fs::read_to_string("config.toml").unwrap();
    let config: toml::Value = toml::from_str(&config).unwrap();

    config
}
