use std::sync::Arc;

use httptest::{matchers::request, responders::json_encoded, Expectation, Server};
use serde_json::json;
use statsig_rdp::{models::StatsigOptions, Client};

pub fn expect_fetch_config_specs(server: &Server) {
    server.expect(
        Expectation::matching(request::method_path(
            "GET",
            "/download_config_specs/api_key.json",
        ))
        .times(..)
        .respond_with(json_encoded(json!({
            "dynamic_configs": [
                {
                  "name": "test_dynamic_config",
                  "type": "dynamic_config",
                  "salt": "salt",
                  "enabled": true,
                  "defaultValue": {
                    "value": "DEFAULT"
                  },
                  "rules": [
                    {
                      "name": "test_reject_email_name",
                      "groupName": "test_reject_email",
                      "passPercentage": 0,
                      "conditions": [
                        {
                          "type": "user_field",
                          "targetValue": [
                            "test@example.com"
                          ],
                          "operator": "any",
                          "field": "email",
                          "additionalValues": {},
                          "isDeviceBased": false,
                          "idType": "userID"
                        }
                      ],
                      "returnValue": {
                        "value": "EMAIL"
                      },
                      "id": "id_reject_email",
                      "salt": "salt_email",
                      "isDeviceBased": false,
                      "idType": "userID"
                    },
                    {
                      "name": "test_1239_name",
                      "groupName": "test_1239",
                      "passPercentage": 100,
                      "conditions": [
                        {
                          "type": "user_field",
                          "targetValue": [
                            "1239"
                          ],
                          "operator": "any",
                          "field": "userID",
                          "additionalValues": {},
                          "isDeviceBased": false,
                          "idType": "userID"
                        },
                        {
                          "type": "user_field",
                          "targetValue": [
                            "secretid"
                          ],
                          "operator": "any",
                          "field": "secondaryId",
                          "additionalValues": {
                              "custom_field": "secondaryId"
                          },
                          "isDeviceBased": false,
                          "idType": "userID"
                        }
                      ],
                      "returnValue": {
                        "value": "1239"
                      },
                      "id": "id_1239_name",
                      "salt": "salt_1239",
                      "isDeviceBased": false,
                      "idType": "userID"
                    },
                  ],
                  "isDeviceBased": false,
                  "idType": "userID",
                  "entity": "dynamic_config"
                }
            ],
            "feature_gates": [
                {
                    "name": "test_gate",
                    "type": "feature_gate",
                    "salt": "salt",
                    "enabled": true,
                    "defaultValue": false,
                    "idType": "userID",
                    "rules": [{
                        "name": "public",
                        "groupName": "public",
                        "id": "public1",
                        "salt": "salt_rule",
                        "passPercentage": 100,
                        "idType": "userID",
                        "returnValue": true,
                        "conditions": [{
                            "type": "public",
                            "idType": "userid",
                        }],
                    }],
                }
            ],
            "has_updates": true,
            "time": 0,
        }))),
    );
}

pub fn expect_log_emission(server: &Server) {
    server.expect(
        Expectation::matching(request::method_path("POST", "/log_event"))
            .times(..)
            .respond_with(json_encoded(json!({}))),
    );
}

#[derive(Debug, serde::Deserialize)]
pub struct ConfigValue {
    pub value: String,
}

pub async fn create_client() -> Arc<Client> {
    let http_server = Server::run();
    expect_fetch_config_specs(&http_server);
    expect_log_emission(&http_server);

    Client::new(
        "api_key".to_string(),
        StatsigOptions {
            api_url: Some(format!("http://{}", http_server.addr())),
            cdn_url: Some(format!("http://{}", http_server.addr())),
            events_url: Some(format!("http://{}", http_server.addr())),
            disable_cache: false,
            config_sync_interval: None,
        },
    )
    .await
    .expect("should be able to create statsig client")
}
