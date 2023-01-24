use chrono::Local;

pub async fn cur_time_file(name: &str, dir: &str) -> String{
    let date = Local::now();
    let file_path = format!(
            "{}/{}_{}.csv",
            dir,
            name,
            date.format("%Y-%m-%d_%H-%M-%S").to_string()
        );
    
    file_path
}