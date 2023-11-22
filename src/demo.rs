use rustpush::{APNSConnection, APNSState, IDSUser};
use serde::{Deserialize, Serialize};
use tokio::io::AsyncWriteExt;

#[derive(Serialize, Deserialize, Clone)]
struct SavedState {
    push: APNSState,
    users: Vec<IDSUser>,
}
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = clap::Command::new("demo").get_matches();
    let default_config_file_name = "config.json".to_string();
    let config_file = args
        .get_one::<String>("config")
        .unwrap_or(&default_config_file_name);
    let data = match tokio::fs::read_to_string(config_file).await {
        Ok(v) => v,
        Err(_) => {
            let mut file = tokio::fs::File::create(config_file).await.unwrap();
            file.write_all(b"{}").await.unwrap();
            "{}".to_string()
        }
    };
    let saved_state: Option<SavedState> = serde_json::from_str(&data).ok();
    let state = saved_state.map(|state| state.push.clone());

    let conn = APNSConnection::new(state).await?;
    Ok(())
}
