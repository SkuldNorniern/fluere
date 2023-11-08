use crate::util::home_cache_path;
use git2::{Cred, FetchOptions, RemoteCallbacks, Repository};

pub fn download_plugin_from_github(repo_name: &str) -> Result<(), std::io::Error> {
    let url = format!("https://github.com/{}.git", repo_name);
    let path = home_cache_path().unwrap();
    if !path.exists() {
        std::fs::create_dir_all(path.clone())?;
    }
    let repo_path = path.join(repo_name.split('/').last().unwrap());
    if repo_path.exists() {
        let mut callbacks = RemoteCallbacks::new();
        callbacks.credentials(|_url, username_from_url, _allowed_types| {
            Cred::ssh_key(
                username_from_url.unwrap(),
                None,
                std::path::Path::new(&format!("{}/.ssh/id_rsa", std::env::var("HOME").unwrap())),
                None,
            )
        });
        let mut fetch_options = FetchOptions::new();
        fetch_options.remote_callbacks(callbacks);
        let repo = Repository::open(&repo_path)?;
        repo.find_remote("origin")?
            .fetch(&["master"], Some(&mut fetch_options), None)?;
        let fetch_head = repo.find_reference("FETCH_HEAD")?;
        let annotated = repo.reference_to_annotated_commit(&fetch_head)?;
        repo.merge(&[&annotated], None, Some(&mut fetch_options))?;
    } else {
        Repository::clone(&url, &path)?;
    }
    Ok(())
}
