use sha2::{Digest, Sha256};

use super::models::ConfigSpecType;

pub fn get_hash(s: String) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(s);
    let res = hasher.finalize();
    // TODO: Use from_le_bytes
    (*res.get(7).unwrap_or(&0) as u64)
        | (*res.get(6).unwrap_or(&0) as u64) << 8
        | (*res.get(5).unwrap_or(&0) as u64) << 16
        | (*res.get(4).unwrap_or(&0) as u64) << 24
        | (*res.get(3).unwrap_or(&0) as u64) << 32
        | (*res.get(2).unwrap_or(&0) as u64) << 40
        | (*res.get(1).unwrap_or(&0) as u64) << 48
        | (*res.first().unwrap_or(&0) as u64) << 56
}

pub fn get_numeric_value(v: &serde_json::Value) -> Option<f64> {
    match v {
        serde_json::Value::Null => None,
        serde_json::Value::Bool(_) => None,
        serde_json::Value::Number(n) => n.as_f64(),
        serde_json::Value::String(s) => s.parse().ok(),
        serde_json::Value::Array(_) => None,
        serde_json::Value::Object(_) => None,
    }
}

pub fn get_string(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::Null => "".to_string(),
        serde_json::Value::Bool(b) => b.to_string(),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Array(_) => "".to_string(),
        serde_json::Value::Object(_) => "".to_string(),
    }
}

pub fn get_unix_epoch(v: &serde_json::Value) -> i64 {
    let val = match v {
        serde_json::Value::Null => 0,
        serde_json::Value::Bool(_) => 0,
        serde_json::Value::Number(n) => n.as_i64().unwrap_or_default(),
        serde_json::Value::String(s) => s.parse().unwrap_or_default(),
        serde_json::Value::Array(_) => 0,
        serde_json::Value::Object(_) => 0,
    };
    if val > i32::MAX as i64 {
        // handle receiving value in milliseconds
        val / 1000
    } else {
        val
    }
}

pub fn get_config_value(
    v: &serde_json::Value,
    config_type: ConfigSpecType,
) -> Option<serde_json::Value> {
    match config_type {
        ConfigSpecType::DynamicConfig => Some(v.clone()),
        ConfigSpecType::FeatureGate => None,
        ConfigSpecType::Unknown => None,
    }
}
