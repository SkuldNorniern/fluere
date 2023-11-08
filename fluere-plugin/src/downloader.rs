use crate::util::home_cache_path;
use std::process::Command;

pub fn download_plugin_from_github(repo_name: &str) -> Result<(), std::io::Error> {
    let url = format!("https://github.com/{}.git", repo_name);
    let path = home_cache_path();
    let cd_cmd = format!("cd {}", path.display());
    if !path.exists() {
        std::fs::create_dir_all(path.clone())?;
    }
    if path.join(repo_name.split('/').last().unwrap()).exists() {
        let output = Command::new("bash")
            .arg("-c")
            .arg(cd_cmd + ";git fetch ;git pull")
            .output()?;
        if !output.status.success() {
            return Err(std::io::Error::new(std::io::ErrorKind::Other, "git pull operation failed"));
        }
    } else {
        let output = Command::new("bash")
            .arg("-c")
            .arg(cd_cmd + "; git clone " + &url)
            .output()?;
        if !output.status.success() {
            return Err(std::io::Error::new(std::io::ErrorKind::Other, "git clone operation failed"));
        }
    }
    Ok(())
}
