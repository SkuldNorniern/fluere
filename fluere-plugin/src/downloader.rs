use crate::util::home_cache_path;
use git2;
use std::io;
use std::path::Path;

/// Fetch changes from a GitHub repository by `repo_name`.
pub fn fetch_from_github(repo_name: &str) -> Result<(), std::io::Error> {
    let url = format!("https://github.com/{}/.git", repo_name);
    let path = home_cache_path()?;
    let repo_path = path.join(repo_name.split('/').last().unwrap());
    let repository = git2::Repository::open(&repo_path);

    match repository {
        Ok(repo) => {
            let origin = repo.find_remote("origin");
            match origin {
                Ok(mut remote) => {
                    remote.fetch(&["refs/heads/*:refs/heads/*"], None, None)?;
                },
                Err(e) => return Err(e.into()),
            }
        },
        Err(e) => return Err(e.into()),
    }

    Ok(())
}

pub fn download_plugin_from_github(repo_name: &str) -> Result<(), std::io::Error> {
    let url = format!("https://github.com/{}", repo_name);
    let path = home_cache_path()?;
    // let cd_cmd = format!("cd {}", path.display());
    if !path.exists() {
        std::fs::create_dir_all(path.clone())?;
    }

    let repo_path = path.join(repo_name.split('/').last().unwrap());
    let repository_path = Path::new(&repo_path);
    // println!("repository_path: {:?}", repository_path);

    match git2::Repository::open(repository_path) {
        Ok(repo) => {
            let mut origin = repo.find_remote("origin").or_else(|_| {
                Err(io::Error::new(
                    io::ErrorKind::Other,
                    "Remote 'origin' does not exist",
                ))
            })?;
            origin
                .fetch(&["refs/heads/*:refs/heads/*"], None, None)
                .map_err(|e| {
                    io::Error::new(io::ErrorKind::Other, format!("fetch failed: {}", e))
                })?;
        }
        Err(_) => {
            git2::Repository::clone(&url, repository_path).map_err(|e| {
                io::Error::new(io::ErrorKind::Other, format!("clone failed: {}", e))
            })?;
        }
    };

    Ok(())
}
