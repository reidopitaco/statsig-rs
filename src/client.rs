use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::SystemTime,
};

use anyhow::{anyhow, bail, Result};
use serde::de::DeserializeOwned;
use tokio::{time, time::Duration};
use tracing::{event, Level};

use crate::{
    evaluator::{models::EvalResult, Evaluator},
    http::StatsigHttpClient,
    models::{StatsigConfig, StatsigEvent, StatsigOptions, StatsigPost, StatsigUser},
};

const GATE_EXPOSURE_EVENT: &str = "statsig::gate_exposure";
const CONFIG_EXPOSURE_EVENT: &str = "statsig::config_exposure";
const MAX_LOG_EVENTS: usize = 950;

/// Statsig client that has a local cache and syncs with the API periodically.
pub struct Client {
    disable_cache: bool,
    http_client: StatsigHttpClient,
    evaluator: Evaluator,
    event_logs: Mutex<Vec<StatsigEvent>>,
}

impl Client {
    pub async fn new(api_key: String, options: StatsigOptions) -> Result<Arc<Self>> {
        let http_client = StatsigHttpClient::new(api_key, options.api_url, options.events_url);

        let evaluator = Evaluator::new();
        if !options.disable_cache {
            let initial_data = http_client.fetch_state_from_source(0).await?;
            evaluator.refresh_configs(initial_data);
        }

        let s = Arc::new(Self {
            disable_cache: options.disable_cache,
            evaluator,
            http_client,
            event_logs: Mutex::new(vec![]),
        });

        if !options.disable_cache {
            tokio::spawn(s.clone().poll_for_changes(options.config_sync_interval));
            tokio::spawn(s.clone().background_logs_flush());
        }

        Ok(s)
    }

    pub async fn check_gate(self: Arc<Self>, gate: String, user: StatsigUser) -> Result<bool> {
        if user.user_id.is_empty() {
            bail!("statsig: missing user id");
        }

        if self.disable_cache {
            return self.http_client.check_gate(gate, user).await;
        }

        let res = self.evaluator.check_gate_internal(&user, &gate);
        if res.fetch_from_server {
            self.http_client.check_gate(gate, user).await
        } else {
            let pass = res.pass;
            self.log_gate_exposure(gate, user, res);
            Ok(pass)
        }
    }

    pub async fn get_dynamic_config<T: DeserializeOwned>(
        self: Arc<Self>,
        config: String,
        user: StatsigUser,
    ) -> Result<T> {
        if user.user_id.is_empty() {
            bail!("statsig: missing user id");
        }

        if self.disable_cache {
            return self.http_client.get_dynamic_config(config, user).await;
        }

        let mut res = self.evaluator.get_dynamic_config_internal(&user, &config);
        if res.fetch_from_server {
            self.http_client.get_dynamic_config(config, user).await
        } else {
            let val = res.config_value.take();
            self.log_config_exposure(config, user, res);
            let val = val.ok_or_else(|| anyhow!("empty config"))?;
            Ok(serde_json::from_value(val)?)
        }
    }

    /// Returns the value, together with the metadata about the group that matched the check
    pub async fn get_config<T: DeserializeOwned>(
        self: Arc<Self>,
        config: String,
        user: StatsigUser,
    ) -> Result<StatsigConfig<T>> {
        if user.user_id.is_empty() {
            bail!("statsig: missing user id");
        }

        if self.disable_cache {
            return self.http_client.get_config(config, user).await;
        }

        let res = self.evaluator.get_dynamic_config_internal(&user, &config);
        if res.fetch_from_server {
            self.http_client.get_config(config, user).await
        } else {
            let value: Option<T> = serde_json::from_value(
                res.config_value.clone().unwrap_or(serde_json::Value::Null),
            )?;

            let val = StatsigConfig {
                value,
                name: config.clone(),
                group_name: res.group_name.clone(),
                rule_id: res.rule_id.clone(),
                group: res.group.clone(),
            };

            self.log_config_exposure(config, user, res);

            Ok(val)
        }
    }

    pub async fn log_event(&self, statsig_post: &StatsigPost) -> Result<()> {
        self.http_client.log_event(statsig_post).await
    }
}

// Private methods
impl Client {
    async fn poll_for_changes(self: Arc<Self>, config_sync_interval: Option<Duration>) {
        let mut interval =
            time::interval(config_sync_interval.unwrap_or_else(|| Duration::from_secs(20)));
        let mut last_time: u64 = 0;
        loop {
            interval.tick().await;
            event!(Level::DEBUG, "Refreshing statsig configs");
            let new_state = match self.http_client.fetch_state_from_source(last_time).await {
                Ok(s) => s,
                Err(e) => {
                    event!(Level::ERROR, "Failed to fetch state: {}", e);
                    continue;
                }
            };
            if new_state.has_updates {
                event!(Level::DEBUG, "Statsig state has changed");
                last_time = new_state.time.unwrap_or_default();
                self.evaluator.refresh_configs(new_state);
            }
        }
    }

    async fn background_logs_flush(self: Arc<Self>) {
        let mut interval = time::interval(Duration::from_secs(60));
        loop {
            // TODO: Graceful shutdown, listen for signals, flush logs before exiting
            interval.tick().await;
            event!(Level::DEBUG, "Flushing logs");

            self.clone().flush_logs().await;
        }
    }

    async fn flush_logs(self: Arc<Self>) {
        let events;
        {
            let mut logs = self
                .event_logs
                .lock()
                .expect("should always be able to acquire lock");
            events = std::mem::take(&mut *logs);
        }

        if !events.is_empty() {
            match self
                .http_client
                .log_event_internal(StatsigPost { events })
                .await
            {
                Ok(_) => (),
                Err(e) => {
                    event!(Level::ERROR, "Failed to log events: {}", e);
                }
            };
        }
    }

    fn log_gate_exposure(
        self: Arc<Self>,
        gate: String,
        user: StatsigUser,
        eval_result: EvalResult,
    ) {
        let event = StatsigEvent {
            event_name: GATE_EXPOSURE_EVENT.to_string(),
            value: eval_result.pass.to_string(),
            time: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_else(|_| Duration::from_secs(0))
                .as_secs()
                .to_string(),
            user,
            metadata: HashMap::from([
                ("gate".to_string(), gate),
                ("gateValue".to_string(), eval_result.pass.to_string()),
                ("ruleID".to_string(), eval_result.id),
            ]),
        };
        let mut events = self
            .event_logs
            .lock()
            .expect("should always be able to acquire lock");
        events.push(event);
        if events.len() >= MAX_LOG_EVENTS {
            tokio::spawn(self.clone().flush_logs());
        }
    }

    fn log_config_exposure(
        self: Arc<Self>,
        config: String,
        user: StatsigUser,
        eval_result: EvalResult,
    ) {
        let event = StatsigEvent {
            event_name: CONFIG_EXPOSURE_EVENT.to_string(),
            value: eval_result.pass.to_string(),
            time: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_else(|_| Duration::from_secs(0))
                .as_secs()
                .to_string(),
            user,
            metadata: HashMap::from([
                ("config".to_string(), config),
                ("ruleID".to_string(), eval_result.id),
            ]),
        };
        let mut events = self
            .event_logs
            .lock()
            .expect("should always be able to acquire lock");
        events.push(event);
        if events.len() >= MAX_LOG_EVENTS {
            tokio::spawn(self.clone().flush_logs());
        }
    }
}
