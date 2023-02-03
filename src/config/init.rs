use std::fs;
use std::path::Path;

pub fn generate_config() -> Result<(), std::io::Error> {
    let sample_config = include_str!("config_sample.toml");

    if !Path::new("config.toml").exists() {
        fs::write("config.toml", sample_config)?;
    }

    Ok(())
}