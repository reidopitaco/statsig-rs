use std::collections::HashMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EvalResult {
    pub pass: bool,
    // pub config_value: DynamicConfig,
    pub fetch_from_server: bool,
    pub id: String,
    pub secondary_exposures: Vec<HashMap<String, String>>,
    // pub undelegated_secondary_exposures: Option<Vec<HashMap<String, String>>>,
    // pub config_delegate: Option<String>,
    // pub explicit_parameters: Option<HashMap<String, bool>>,
}

impl Default for EvalResult {
    fn default() -> Self {
        Self {
            pass: false,
            fetch_from_server: false,
            id: "default".to_string(),
            secondary_exposures: vec![HashMap::new()],
            // undelegated_secondary_exposures: None,
            // config_delegate: None,
            // explicit_parameters: None,
        }
    }
}

impl EvalResult {
    pub fn pass() -> Self {
        Self::new(true, false, vec![])
    }

    #[allow(dead_code)]
    pub fn fail() -> Self {
        Self::new(false, false, vec![])
    }

    pub fn fetch_from_server() -> Self {
        Self::new(false, true, vec![])
    }

    pub fn new(
        pass: bool,
        fetch_from_server: bool,
        secondary_exposures: Vec<HashMap<String, String>>,
    ) -> Self {
        Self {
            pass,
            fetch_from_server,
            id: "default".to_string(),
            secondary_exposures,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ConfigData {
    pub dynamic_configs: Option<Vec<ConfigSpec>>,
    pub feature_gates: Option<Vec<ConfigSpec>>,
    pub layer_configs: Option<Vec<ConfigSpec>>,
    // id_lists
    // layers
    pub has_updates: bool,
    pub time: Option<u64>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfigSpec {
    pub name: String,
    pub r#type: String,
    pub salt: String,
    pub enabled: bool,
    pub rules: Option<Vec<ConfigRule>>,
    pub default_value: serde_json::Value, // json.RawMessage
    pub id_type: Option<String>,
    // pub explicit_parameters: Option<Vec<String>>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfigRule {
    pub name: String,
    pub id: String,
    pub salt: String,
    pub pass_percentage: f64,
    pub conditions: Vec<ConfigCondition>,
    pub return_value: serde_json::Value, // json.RawMessage
    pub id_type: String,
    // pub config_delegate: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfigCondition {
    pub r#type: ConditionType,
    pub operator: Option<OperatorType>,
    pub field: Option<String>,
    pub target_value: Option<serde_json::Value>,
    // pub additional_values: Option<HashMap<String, String>>, // map[string]interface{}
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
