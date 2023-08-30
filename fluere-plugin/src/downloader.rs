use std::process::Command;
use crate::util::home_cache_path;

pub fn download_plugin_from_github(repo_name: &str) -> Result<(), std::io::Error> {
    let url = format!("https://github.com/{}.git", repo_name);
    let path = home_cache_path();
    let cd_cmd = format!("cd {}", path.display());
    if !path.exists() {
        std::fs::create_dir_all(path)?;
    }
    if path.join(repo_name.split('/').last().unwrap()).exists() {
        Command::new("bash")
            .arg("-c")
            .arg(cd_cmd + ";git fetch ;git pull")
            .output()?;
    }else {
        Command::new("bash")
            .arg("-c")
            .arg(cd_cmd + "; git clone " + &url)
            .output()?;
    }
    Ok(())
}
