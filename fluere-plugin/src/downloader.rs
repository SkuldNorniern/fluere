use git2::{
    build::CheckoutBuilder, FetchOptions, ObjectType, Repository, ResetType, StatusOptions,
};
use inksac::{Color, Style, Stylish};

use std::fmt;
use std::io;
use std::path::Path;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use crate::util::home_cache_path;

#[derive(Debug)]
pub enum DownloadError {
    Io(std::io::Error),
    Git(git2::Error),
    Other(String),
}

impl fmt::Display for DownloadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DownloadError::Io(err) => write!(f, "IO error: {}", err),
            DownloadError::Git(err) => write!(f, "Git error: {}", err),
            DownloadError::Other(err) => write!(f, "{}", err),
        }
    }
}

impl From<std::io::Error> for DownloadError {
    fn from(err: std::io::Error) -> Self {
        DownloadError::Io(err)
    }
}

impl From<git2::Error> for DownloadError {
    fn from(err: git2::Error) -> Self {
        DownloadError::Git(err)
    }
}

impl From<String> for DownloadError {
    fn from(err: String) -> Self {
        DownloadError::Other(err)
    }
}

pub fn download_plugin_from_github(repo_name: &str) -> Result<(), DownloadError> {
    let url = format!("https://github.com/{}", repo_name);
    let warn_style = Style::builder().foreground(Color::Yellow).build();
    let highlight_style = Style::builder().foreground(Color::Green).bold().build();
    let path = home_cache_path()?;
    if !path.exists() {
        std::fs::create_dir_all(&path)?;
    }

    let repo_path = path.join(repo_name.split('/').last().unwrap());
    let repository_path = Path::new(&repo_path);

    let repo = match Repository::open(repository_path) {
        Ok(repo) => repo,
        Err(_) => Repository::clone(&url, repository_path)?,
    };
    let mut remote = repo.find_remote("origin")?;
    let mut fetch_options = FetchOptions::new();
    remote.fetch(&["main"], Some(&mut fetch_options), None)?;

    let fetch_head = repo.find_reference("FETCH_HEAD")?;

    let fetch_commit = fetch_head.peel(ObjectType::Commit)?.id();
    let local_commit = repo.head()?.target().unwrap();

    if fetch_commit != local_commit {
        println!(
            "An update is available for '{}'. Do you want to update? [y/N] (auto skip in 5 seconds)",
            repo_name.styled(highlight_style)
        );
        if user_confirms()? {
            if has_local_changes(&repo)? {
                println!("{}: You have uncommitted changes. Updating will overwrite these changes. Continue? [y/N] (auto skip in 5 seconds)","Warning".styled(warn_style));
                if !user_confirms()? {
                    println!("Update skipped for {}", repo_name.styled(highlight_style));
                    return Ok(());
                }
            }

            // Resetting the HEAD to the fetched commit
            let fetch_commit_obj = repo.find_commit(fetch_commit)?;
            repo.reset(fetch_commit_obj.as_object(), ResetType::Hard, None)?;

            // Checking out the commit to update the working directory and index
            let mut checkout_builder = CheckoutBuilder::new();
            let _ = checkout_builder.force();
            repo.checkout_tree(fetch_commit_obj.as_object(), Some(&mut checkout_builder))?;
            repo.set_head_detached(fetch_commit)?;

            println!(
                "Successfully updated to the latest version for {}",
                repo_name.styled(highlight_style)
            );
        } else {
            println!("Update skipped for {}", repo_name.styled(highlight_style));
        }
    } else {
        println!("{} is up to date.", repo_name.styled(highlight_style));
    }

    Ok(())
}
fn user_confirms() -> Result<bool, DownloadError> {
    let (sender, receiver) = mpsc::channel();

    // Spawn a new thread for user input
    thread::spawn(move || {
        let mut input = String::new();
        match io::stdin().read_line(&mut input) {
            Ok(_) => {
                let _ = sender.send(input.trim().eq_ignore_ascii_case("y"));
            }
            Err(_) => {
                let _ = sender.send(false);
            }
        }
    });

    // Wait for input or timeout after 5 seconds
    match receiver.recv_timeout(Duration::from_secs(5)) {
        Ok(result) => Ok(result),
        Err(_) => {
            print!("Timeout. ");
            Ok(false)
        }
    }
}

fn has_local_changes(repo: &Repository) -> Result<bool, DownloadError> {
    let statuses = repo.statuses(Some(StatusOptions::new().include_untracked(true)))?;
    Ok(statuses.iter().any(|s| s.status() != git2::Status::CURRENT))
}
