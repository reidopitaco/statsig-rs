use std::collections::HashMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EvalResult {
    pub pass: bool,
    pub config_value: Option<serde_json::Value>,
    pub fetch_from_server: bool,
    pub id: String,
    pub secondary_exposures: Vec<HashMap<String, String>>,
    pub group: String,
    pub group_name: Option<String>,
    pub rule_id: String,
    // pub undelegated_secondary_exposures: Option<Vec<HashMap<String, String>>>,
    // pub config_delegate: Option<String>,
    // pub explicit_parameters: Option<HashMap<String, bool>>,
}

impl Default for EvalResult {
    fn default() -> Self {
        Self::fail()
    }
}

impl EvalResult {
    pub fn pass() -> Self {
        Self::new(true, false)
    }

    pub fn fail() -> Self {
        Self::new(false, false)
    }

    pub fn fetch_from_server() -> Self {
        Self::new(false, true)
    }

    fn new(pass: bool, fetch_from_server: bool) -> Self {
        Self {
            pass,
            fetch_from_server,
            config_value: None,
            id: "default".to_owned(),
            secondary_exposures: vec![],
            group: "default".to_owned(),
            group_name: Some("default".to_owned()),
            rule_id: "default".to_owned(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ConfigData {
    pub dynamic_configs: Option<Vec<ConfigSpec>>,
    pub feature_gates: Option<Vec<ConfigSpec>>,
    pub layer_configs: Option<Vec<ConfigSpec>>,
    pub has_updates: bool,
    pub time: Option<u64>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfigSpec {
    pub name: String,
    pub r#type: ConfigSpecType,
    pub salt: String,
    pub enabled: bool,
    pub rules: Option<Vec<ConfigRule>>,
    pub default_value: serde_json::Value,
    pub id_type: Option<String>,
    // pub explicit_parameters: Option<Vec<String>>,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfigSpecType {
    DynamicConfig,
    FeatureGate,
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Default, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfigRule {
    pub name: String,
    pub id: String,
    pub salt: String,
    pub pass_percentage: f64,
    pub conditions: Vec<ConfigCondition>,
    pub return_value: serde_json::Value, // json.RawMessage
    pub id_type: String,
    pub group_name: Option<String>,
    // pub config_delegate: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfigCondition {
    pub r#type: ConditionType,
    pub operator: Option<OperatorType>,
    pub field: Option<String>,
    pub target_value: Option<serde_json::Value>,
    pub additional_values: Option<HashMap<String, String>>,
    pub id_type: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConditionType {
    Public,
    FailGate,
    PassGate,
    IpBased,
    UaBased,
    UserField,
    EnvironmentField,
    CurrentTime,
    UserBucket,
    UnitId,
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OperatorType {
    Gt,
    Gte,
    Lt,
    Lte,
    VersionGt,
    VersionGte,
    VersionLt,
    VersionLte,
    VersionEq,
    VersionNeq,
    Any,
    None,
    AnyCaseSensitive,
    NoneCaseSensitive,
    StrStartsWithAny,
    StrEndsWithAny,
    StrContainsAny,
    StrContainsNone,
    StrMatches,
    Eq,
    Neq,
    Before,
    After,
    On,
    InSegmentList,
    NotInSegmentList,
    #[serde(other)]
    Unknown,
}
