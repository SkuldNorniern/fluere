use chrono::Local;
use std::borrow::Cow;

pub fn cur_time_file(name: &str, dir: &str, format: &str) -> Cow<'static, str> {
    let date = Local::now();
    let file_path = format!(
        "{}/{}_{}{}",
        dir,
        name,
        date.format("%Y-%m-%d_%H-%M-%S"),
        format
    );

    Cow::Owned(file_path)
}
