use anyhow::{anyhow, Result};
use reqwest::{
    header,
    header::{HeaderMap, HeaderName, HeaderValue},
    Client, ClientBuilder, StatusCode,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use tokio::time::Duration;

use crate::{
    evaluator::models::ConfigData,
    models::{StatsigPost, StatsigUser},
};

const API_URL: &str = "https://api.statsig.com/v1";
const EVENTS_URL: &str = "https://events.statsigapi.net/v1";

/// The environment variable to change the default timeout for statsig requests.
const STATSIG_TIMEOUT_MS: &str = "STATSIG_TIMEOUT_MS";

fn create_http_connection_client(key: &str) -> Client {
    let mut headers = HeaderMap::new();
    headers.insert(header::CONNECTION, HeaderValue::from_static("keep-alive"));
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    headers.insert(
        HeaderName::from_static("statsig-api-key"),
        HeaderValue::from_str(key).expect("should be able to cast api key"),
    );
    let timeout = std::env::var(STATSIG_TIMEOUT_MS)
        .unwrap_or_else(|_| "3000".to_string())
        .parse::<u64>()
        .unwrap_or(3000);
    ClientBuilder::new()
        .pool_idle_timeout(Some(Duration::from_secs(60)))
        .tcp_keepalive(Some(Duration::from_secs(30)))
        .timeout(Duration::from_millis(timeout))
        .default_headers(headers)
        .build()
        .expect("should be able to build the http client")
}

#[derive(Clone)]
pub struct StatsigHttpClient {
    base_url: String,
    events_url: String,
    http_client: Client,
}

impl StatsigHttpClient {
    pub fn new(api_key: String, api_url: Option<String>, events_url: Option<String>) -> Self {
        let base_url = api_url.unwrap_or_else(|| API_URL.to_string());
        let events_url = events_url.unwrap_or_else(|| EVENTS_URL.to_string());
        let http_client = create_http_connection_client(&api_key);
        Self {
            base_url,
            events_url,
            http_client,
        }
    }

    pub async fn check_gate(&self, gate: String, user: StatsigUser) -> Result<bool> {
        #[derive(Deserialize, Serialize)]
        struct CheckGateResponse {
            name: String,
            value: bool,
        }

        #[derive(Serialize)]
        struct CheckGateBody {
            user: StatsigUser,
            #[serde(rename = "gateName")]
            gate_name: String,
        }

        let url = format!("{}/check_gate", self.base_url);
        let body = CheckGateBody {
            user,
            gate_name: gate,
        };

        let response = self.http_client.post(url).json(&body).send().await;
        let res = match response {
            Ok(result) => match result.status() {
                StatusCode::OK => Ok(result),
                err => Err(anyhow!("statsig error: {}", err)),
            },
            Err(err) => Err(anyhow!("failed to send request: {}", err)),
        }?;

        let parsed = match res.json::<CheckGateResponse>().await {
            Ok(parsed) => Ok(parsed),
            Err(err) => Err(anyhow!("error parsing statsig gate response: {}", err)),
        }?;

        Ok(parsed.value)
    }

    pub async fn get_dynamic_config<T: DeserializeOwned>(
        &self,
        config: String,
        user: StatsigUser,
    ) -> Result<T> {
        #[derive(Serialize)]
        struct GetConfigBody {
            user: StatsigUser,
            #[serde(rename = "configName")]
            config_name: String,
        }

        let url = format!("{}/get_config", self.base_url);
        let body = GetConfigBody {
            user,
            config_name: config,
        };

        let response = self.http_client.post(url).json(&body).send().await;
        let res = match response {
            Ok(result) => match result.status() {
                StatusCode::OK => Ok(result),
                err => Err(anyhow!("statsig error: {}", err)),
            },
            Err(err) => Err(anyhow!("failed to send request: {}", err)),
        }?;

        #[derive(Deserialize)]
        struct GetConfigResponse<E> {
            value: E,
        }

        let parsed = match res.json::<GetConfigResponse<T>>().await {
            Ok(parsed) => Ok(parsed),
            Err(err) => Err(anyhow!("error parsing: {}", err)),
        }?;

        Ok(parsed.value)
    }

    pub async fn log_event(&self, statsig_post: StatsigPost) -> Result<()> {
        let url = format!("{}/log_event", self.events_url);

        // TODO: Retry
        let response = self.http_client.post(url).json(&statsig_post).send().await;

        match response {
            Ok(result) => match result.status() {
                StatusCode::OK | StatusCode::CREATED | StatusCode::ACCEPTED => Ok(result),
                err => Err(anyhow!("statsig error: {}", err)),
            },
            Err(err) => Err(anyhow!("failed to send request: {}", err)),
        }?;

        Ok(())
    }

    pub async fn log_event_internal(&self, statsig_post: StatsigPost) -> Result<()> {
        let url = format!("{}/log_event", self.base_url);

        // TODO: Retry
        let response = self.http_client.post(url).json(&statsig_post).send().await;

        match response {
            Ok(result) => match result.status() {
                StatusCode::OK | StatusCode::CREATED | StatusCode::ACCEPTED => Ok(result),
                err => Err(anyhow!("statsig error: {}", err)),
            },
            Err(err) => Err(anyhow!("failed to send request: {}", err)),
        }?;

        Ok(())
    }

    pub async fn fetch_state_from_source(&self, last_time: u64) -> Result<ConfigData> {
        let url = format!("{}/download_config_specs", self.base_url);

        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct GetConfigBody {
            since_time: u64,
        }
        let body = GetConfigBody {
            since_time: last_time,
        };

        let response = self
            .http_client
            .post(url)
            .timeout(Duration::from_secs(10))
            .json(&body)
            .send()
            .await;
        let res = match response {
            Ok(result) => match result.status() {
                StatusCode::OK => Ok(result),
                status => {
                    println!("{:?}", result.text().await);
                    Err(anyhow!("statsig error fetching source: {}", status))
                }
            },
            Err(err) => Err(anyhow!("failed to send request to fetch state: {}", err)),
        }?;

        res.json::<ConfigData>()
            .await
            .map_err(|e| anyhow!("error parsing state response: {}", e))
    }
}

#[cfg(test)]
mod test {
    use std::collections::HashMap;

    use crate::models::{StatsigEvent, StatsigUser};

    use super::*;
    use httptest::{matchers::request, responders::json_encoded, Expectation, Server};
    use serde_json::json;

    #[tokio::test]
    async fn test_get_dynamic_config() -> Result<()> {
        let http_server = Server::run();
        http_server.expect(
            Expectation::matching(request::method_path("POST", "/get_config")).respond_with(
                json_encoded(json!({
                    "value": {
                        "merchant_id": "1234",
                        "not_parsed": 1234
                    }
                })),
            ),
        );

        #[derive(Deserialize)]
        struct ConfigTest {
            merchant_id: String,
        }

        let client = StatsigHttpClient::new(
            "something".to_string(),
            Some(format!("http://{}", http_server.addr())),
            None,
        );

        let user = StatsigUser::new("1234".to_string(), "test".to_string());
        let result: ConfigTest = client
            .get_dynamic_config("dynamic".to_string(), user)
            .await?;

        assert_eq!("1234", result.merchant_id);

        Ok(())
    }

    #[tokio::test]
    async fn test_log_event() -> Result<()> {
        let http_server = Server::run();
        http_server.expect(
            Expectation::matching(request::method_path("POST", "/log_event")).respond_with(
                json_encoded(json!({
                    "events":[{
                        "eventName":"teste",
                        "metadata":{
                        },
                        "time":"testando",
                        "user":{
                            "appVersion":null,
                            "country":null,
                            "custom":null,
                            "customIds":null,
                            "email":null,
                            "ip":null,
                            "locale":null,
                            "privateAtributes":null,
                            "statsigEnvironment":{
                                "tier":"2"
                            },
                            "userAgent":null,
                            "userId":"1"
                        },
                        "value":"10"
                    }]
                })),
            ),
        );

        let client = StatsigHttpClient::new(
            "something".to_string(),
            None,
            Some(format!("http://{}", http_server.addr())),
        );

        let statsig_post = StatsigPost {
            events: vec![StatsigEvent {
                event_name: "teste".to_string(),
                value: "10".to_string(),
                time: "testando".to_string(),
                user: StatsigUser::new("1".to_string(), "2".to_string()),
                metadata: HashMap::new(),
            }],
        };
        client.log_event(statsig_post).await?;
        Ok(())
    }
}
