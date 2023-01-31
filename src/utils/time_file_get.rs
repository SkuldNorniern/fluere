use chrono::Local;

pub async fn cur_time_file(name: &str, dir: &str, format: &str) -> String {
    let date = Local::now();
    let file_path = format!(
        "{}/{}_{}{}",
        dir,
        name,
        date.format("%Y-%m-%d_%H-%M-%S"),
        format
    );

    file_path
}
