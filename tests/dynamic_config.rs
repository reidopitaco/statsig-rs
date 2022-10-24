use std::collections::HashMap;

use anyhow::Result;

use statsig_rdp::models::StatsigUser;

use common::{create_client, ConfigValue};

pub mod common;

#[tokio::test]
async fn test_get_dynamic_config() -> Result<()> {
    let client = create_client().await;

    // This user should have value=1239
    let user = StatsigUser {
        custom: Some(HashMap::from([(
            "secondaryId".to_owned(),
            "secretid".to_string(),
        )])),
        email: Some("something@example.com".to_string()),
        ..StatsigUser::new("1239".to_string(), "production".to_string())
    };
    let val: ConfigValue = client
        .clone()
        .get_dynamic_config("test_dynamic_config".to_string(), user)
        .await
        .expect("should succeed");
    assert_eq!(val.value, "1239".to_string());

    // This user should have value=DEFAULT because it matches the first check and it's always false
    let user = StatsigUser {
        custom_ids: Some(HashMap::from([(
            "secondaryId".to_owned(),
            "secretid".to_string(),
        )])),
        email: Some("test@example.com".to_string()),
        ..StatsigUser::new("1239".to_string(), "production".to_string())
    };
    let val: ConfigValue = client
        .clone()
        .get_dynamic_config("test_dynamic_config".to_string(), user)
        .await
        .expect("should succeed");
    assert_eq!(val.value, "DEFAULT".to_string());

    // This user should have value=DEFAULT because it doesn't match previous checks
    let user = StatsigUser::new("1239".to_string(), "production".to_string());
    let val: ConfigValue = client
        .get_dynamic_config("test_dynamic_config".to_string(), user)
        .await
        .expect("should succeed");
    assert_eq!(val.value, "DEFAULT".to_string());

    Ok(())
}
