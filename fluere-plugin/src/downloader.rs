use crate::util::home_cache_path;
use std::process::Command;

pub fn download_plugin_from_github(repo_name: &str) -> Result<(), std::io::Error> {
    let url = format!("https://github.com/{}.git", repo_name);
    let path = home_cache_path();
    if !path.exists() {
        std::fs::create_dir_all(path.clone())?;
    }
    let repo_path = path.join(repo_name.split('/').last().unwrap());
    if repo_path.exists() {
        Command::new("git")
            .args(&["fetch", "pull"])
            .current_dir(repo_path)
            .output()?;
    } else {
        Command::new("git")
            .args(&["clone", &url])
            .current_dir(&path)
            .output()?;
    }
    Ok(())
}
