use std::time::Duration;

use statsig_rdp::{
    models::{StatsigOptions, StatsigUser},
    Client,
};

#[tokio::main]
async fn main() {
    let client = Client::new(
        "secret".to_string(),
        StatsigOptions {
            api_url: None,
            events_url: None,
            disable_cache: false,
            config_sync_interval: Some(Duration::from_secs(5)),
        },
    )
    .await
    .unwrap();

    let user = StatsigUser::new("1238".to_string(), "production".to_string());
    println!(
        "{:?}",
        client
            .clone()
            .check_gate("test_feature_gate_new".to_string(), user)
            .await
    );

    let user = StatsigUser::new("1239".to_string(), "production".to_string());
    println!(
        "{:?}",
        client
            .clone()
            .check_gate("test_feature_gate_new".to_string(), user)
            .await
    );

    #[derive(Debug, serde::Deserialize)]
    struct ConfigValue {
        #[allow(dead_code)]
        value: String,
    }
    let user = StatsigUser::new("1238".to_string(), "production".to_string());
    println!(
        "{:?}",
        client
            .clone()
            .get_dynamic_config::<ConfigValue>("invalid_config".to_string(), user)
            .await
    );
    let user = StatsigUser::new("1239".to_string(), "production".to_string());
    println!(
        "{:?}",
        client
            .clone()
            .get_dynamic_config::<ConfigValue>("test_dynamic_config".to_string(), user)
            .await
    );

    tokio::time::sleep(tokio::time::Duration::from_secs(40)).await;

    let user = StatsigUser::new("1238".to_string(), "production".to_string());
    println!(
        "{:?}",
        client
            .check_gate("test_feature_gate_new".to_string(), user)
            .await
    );

    tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
}
