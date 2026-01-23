use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use std::collections::HashMap;

#[derive(Serialize, Deserialize)]
pub struct StatsigConfig<T> {
    pub value: Option<T>,
    pub name: String,
    pub group_name: Option<String>,
    pub rule_id: String,
    pub group: String,
}

/// Represents the result of an experiment evaluation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatsigExperiment<T> {
    pub value: Option<T>,
    pub name: String,
    pub group_name: Option<String>,
    pub rule_id: String,
    pub group: String,
    /// Secondary exposures (gates that were evaluated as part of this experiment)
    #[serde(default)]
    pub secondary_exposures: Vec<SecondaryExposure>,
}

/// Represents a secondary exposure (e.g., a gate that was checked as part of an experiment)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecondaryExposure {
    pub gate: String,
    pub gate_value: String,
    pub rule_id: String,
}

impl SecondaryExposure {
    pub fn from_hashmap(map: &std::collections::HashMap<String, String>) -> Option<Self> {
        Some(Self {
            gate: map.get("gate")?.clone(),
            gate_value: map.get("gateValue")?.clone(),
            rule_id: map.get("ruleID")?.clone(),
        })
    }

    pub fn to_hashmap(&self) -> std::collections::HashMap<String, String> {
        std::collections::HashMap::from([
            ("gate".to_string(), self.gate.clone()),
            ("gateValue".to_string(), self.gate_value.clone()),
            ("ruleID".to_string(), self.rule_id.clone()),
        ])
    }
}

/// Request body for logging custom experiment exposures
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExperimentExposurePost {
    pub exposures: Vec<ExperimentExposure>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub statsig_metadata: Option<StatsigMetadata>,
}

/// A single experiment exposure to log
#[skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExperimentExposure {
    pub user: StatsigUser,
    pub experiment_name: String,
    pub group: String,
    pub rule_id: String,
    #[serde(default)]
    pub secondary_exposures: Vec<SecondaryExposure>,
}

/// SDK metadata for tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StatsigMetadata {
    pub sdk_type: String,
    pub sdk_version: String,
}

#[derive(Debug, PartialEq, Eq, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StatsigPost {
    pub events: Vec<StatsigEvent>,
}

#[derive(Debug, PartialEq, Clone, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StatsigEvent {
    pub event_name: String,
    pub value: String,
    pub time: String, // unix timestamp
    pub user: StatsigUser,
    pub metadata: HashMap<String, String>,
    // secondary_exposures
}

#[skip_serializing_none]
#[derive(Debug, PartialEq, Eq, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StatsigUser {
    #[serde(rename = "userID")]
    pub user_id: String,
    pub email: Option<String>,
    pub ip: Option<String>,
    pub user_agent: Option<String>,
    pub country: Option<String>,
    pub locale: Option<String>,
    pub app_version: Option<String>,
    pub custom: Option<HashMap<String, String>>,
    pub private_atributes: Option<HashMap<String, String>>,
    #[serde(rename = "customIDs")]
    pub custom_ids: Option<HashMap<String, String>>,
    pub statsig_environment: StatsigEnvironment,
}

/// Options to use when creating the client, they will override default values, if they exist.
///
/// The default value for api_url is https://api.statsig.com/v1
/// The default value for config_sync_interval is 15s
pub struct StatsigOptions {
    pub api_url: Option<String>,
    pub cdn_url: Option<String>,
    pub events_url: Option<String>,
    pub disable_cache: bool,
    pub config_sync_interval: Option<Duration>,
}

impl StatsigOptions {
    pub fn default() -> Self {
        Self {
            api_url: None,
            cdn_url: None,
            disable_cache: false,
            config_sync_interval: None,
            events_url: None,
        }
    }

    pub fn cache_disabled() -> Self {
        Self {
            api_url: None,
            cdn_url: None,
            disable_cache: true,
            config_sync_interval: None,
            events_url: None,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StatsigEnvironment {
    pub tier: String,
}

impl StatsigEnvironment {
    pub fn get_field(&self, field: &str) -> String {
        let empty = "".to_string();
        match field.to_ascii_lowercase().as_str() {
            "tier" => self.tier.clone(),
            _ => empty,
        }
    }
}

impl StatsigUser {
    pub fn new(user_id: String, tier: String) -> Self {
        StatsigUser {
            user_id,
            email: None,
            ip: None,
            user_agent: None,
            country: None,
            locale: None,
            app_version: None,
            custom: None,
            private_atributes: None,
            custom_ids: None,
            statsig_environment: StatsigEnvironment { tier },
        }
    }

    /// Fetch the id of id_type for the user, defaults to user_id.
    pub fn get_unit_id(&self, id_type: &String) -> String {
        if id_type.to_ascii_lowercase() == *"userid" {
            return self.user_id.clone();
        }
        if let Some(custom_ids) = &self.custom_ids {
            if custom_ids.contains_key(id_type) {
                return custom_ids.get(id_type).unwrap_or(&self.user_id).clone();
            }
            let lower = id_type.to_ascii_lowercase();
            if custom_ids.contains_key(&lower) {
                return custom_ids.get(&lower).unwrap_or(&self.user_id).clone();
            }
        }
        self.user_id.clone()
    }

    pub fn get_field(&self, field: &String) -> String {
        let empty = "".to_string();
        match field.to_ascii_lowercase().as_str() {
            "userid" | "user_id" => self.user_id.clone(),
            "email" => self.email.as_ref().unwrap_or(&empty).clone(),
            "ip" | "ipaddress" | "ip_address" => self.ip.as_ref().unwrap_or(&empty).clone(),
            "useragent" | "user_agent" => self.user_agent.as_ref().unwrap_or(&empty).clone(),
            "country" => self.country.as_ref().unwrap_or(&empty).clone(),
            "locale" => self.locale.as_ref().unwrap_or(&empty).clone(),
            "appversion" | "app_version" => self.app_version.as_ref().unwrap_or(&empty).clone(),
            _ => {
                let mut ret = "".to_string();
                if let Some(custom) = &self.custom {
                    if let Some(v) = custom.get(field) {
                        ret = v.clone();
                    } else if let Some(v) = custom.get(&field.to_ascii_lowercase()) {
                        ret = v.clone();
                    }
                } else if let Some(private) = &self.private_atributes {
                    if let Some(v) = private.get(field) {
                        ret = v.clone();
                    } else if let Some(v) = private.get(&field.to_ascii_lowercase()) {
                        ret = v.clone();
                    }
                }
                ret
            }
        }
    }
}

#[cfg(test)]
mod test {
    use std::collections::HashMap;

    use crate::models::StatsigEnvironment;

    use super::StatsigUser;

    #[test]
    fn test_get_unit_id_default_user() {
        let user = StatsigUser::new("user_id".to_string(), "prod".to_string());
        assert_eq!(
            user.get_unit_id(&"userid".to_string()),
            "user_id".to_string()
        );
        assert_eq!(
            user.get_unit_id(&"not_userid".to_string()),
            "user_id".to_string()
        );
    }

    #[test]
    fn test_get_unit_id_custom_ids() {
        let mut user = StatsigUser::new("user_id".to_string(), "prod".to_string());
        let mut custom_ids = HashMap::new();
        custom_ids.insert("not_userid".to_string(), "not_userid".to_string());
        custom_ids.insert("ALL_CAPS".to_string(), "ALL_CAPS".to_string());
        user.custom_ids = Some(custom_ids);
        assert_eq!(
            user.get_unit_id(&"userid".to_string()),
            "user_id".to_string()
        );
        assert_eq!(
            user.get_unit_id(&"Not_userid".to_string()),
            "not_userid".to_string()
        );
        assert_eq!(
            user.get_unit_id(&"ALL_CAPS".to_string()),
            "ALL_CAPS".to_string()
        );
        assert_eq!(
            user.get_unit_id(&"non_existing".to_string()),
            "user_id".to_string()
        );
    }

    #[test]
    fn test_get_field() {
        let user = StatsigUser {
            user_id: "userid".to_string(),
            email: Some("abc@email.com".to_string()),
            ip: Some("192.168.0.1".to_string()),
            user_agent: None,
            country: None,
            locale: None,
            app_version: None,
            custom: Some(HashMap::from([("custom1".to_string(), "val1".to_string())])),
            private_atributes: None,
            custom_ids: None,
            statsig_environment: StatsigEnvironment {
                tier: "prod".to_string(),
            },
        };
        assert_eq!("userid".to_string(), user.get_field(&"userID".to_string()));
        assert_eq!(
            "abc@email.com".to_string(),
            user.get_field(&"email".to_string())
        );
        assert_eq!("192.168.0.1".to_string(), user.get_field(&"ip".to_string()));
        assert_eq!("val1".to_string(), user.get_field(&"custom1".to_string()));
    }
}
