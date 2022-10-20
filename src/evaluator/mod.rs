use std::collections::HashMap;

use crossbeam::sync::ShardedLock;
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::{evaluator::models::OperatorType, models::StatsigUser};

use self::models::{
    ConditionType, ConfigCondition, ConfigData, ConfigRule, ConfigSpec, EvalResult,
};

pub mod models;

fn get_hash(s: String) -> u64 {
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

pub struct Evaluator {
    #[allow(dead_code)]
    dynamic_configs: ShardedLock<HashMap<String, ConfigSpec>>,
    gates: ShardedLock<HashMap<String, ConfigSpec>>,
}

impl Evaluator {
    pub fn new() -> Self {
        Self {
            dynamic_configs: ShardedLock::new(HashMap::new()),
            gates: ShardedLock::new(HashMap::new()),
        }
    }

    pub fn refresh_configs(&self, data: ConfigData) {
        let dynamic_configs = data
            .dynamic_configs
            .unwrap_or_default()
            .into_iter()
            .map(|d| (d.name.clone(), d))
            .collect();
        let feature_gates = data
            .feature_gates
            .unwrap_or_default()
            .into_iter()
            .map(|f| (f.name.clone(), f))
            .collect();
        let mut configs = self
            .dynamic_configs
            .write()
            .expect("should not be poisoned");
        *configs = dynamic_configs;
        let mut gates = self.gates.write().expect("should not be poisoned");
        *gates = feature_gates;
    }

    pub fn check_gate_internal(&self, user: &StatsigUser, gate_name: &String) -> EvalResult {
        match self
            .gates
            .read()
            .expect("should always be able to acquire read lock")
            .get(gate_name)
        {
            Some(gate) => self.eval_spec(user, gate),
            None => EvalResult::default(),
        }
    }

    fn eval_spec(&self, user: &StatsigUser, spec: &ConfigSpec) -> EvalResult {
        if !spec.enabled {
            return EvalResult::default();
        }

        let mut exposures: Vec<HashMap<String, String>> = vec![];
        if let Some(rules) = &spec.rules {
            for rule in rules.iter() {
                let res = self.eval_rule(user, rule);
                if res.fetch_from_server {
                    return res;
                }
                res.secondary_exposures
                    .into_iter()
                    .for_each(|e| exposures.push(e));

                if res.pass {
                    // TODO: Eval delegates (??)
                    let pass = self.eval_pass_percent(user, rule, spec);
                    return EvalResult {
                        pass,
                        id: rule.id.clone(),
                        secondary_exposures: exposures,
                        ..Default::default()
                    };
                }
            }
        }

        EvalResult {
            secondary_exposures: exposures,
            ..Default::default()
        }
    }

    fn eval_pass_percent(&self, user: &StatsigUser, rule: &ConfigRule, spec: &ConfigSpec) -> bool {
        let rule_salt = if rule.salt.is_empty() {
            &rule.id
        } else {
            &rule.salt
        };
        let hash = get_hash(format!(
            "{}.{}.{}",
            spec.salt,
            rule_salt,
            user.get_unit_id(&rule.id_type)
        ));
        ((hash % 10000) as f64) < ((rule.pass_percentage) * 100.0)
    }

    fn eval_rule(&self, user: &StatsigUser, rule: &ConfigRule) -> EvalResult {
        let mut result = EvalResult {
            pass: true,
            ..Default::default()
        };
        for condition in rule.conditions.iter() {
            let res = self.eval_condition(user, condition);
            if !res.pass {
                result.pass = false;
            }
            if res.fetch_from_server {
                result.fetch_from_server = true;
            }
            res.secondary_exposures
                .into_iter()
                .for_each(|e| result.secondary_exposures.push(e));
        }
        result
    }

    fn eval_condition(&self, user: &StatsigUser, condition: &ConfigCondition) -> EvalResult {
        let empty = "".to_string();
        let value = match condition.r#type {
            ConditionType::Public => return EvalResult::pass(),
            ConditionType::FailGate | ConditionType::PassGate => {
                return EvalResult::fetch_from_server(); // TODO
            }
            ConditionType::IpBased => {
                return EvalResult::fetch_from_server(); // TODO
            }
            ConditionType::UaBased => {
                return EvalResult::fetch_from_server(); // TODO
            }
            ConditionType::UserField => user.get_field(condition.field.as_ref().unwrap_or(&empty)),
            ConditionType::EnvironmentField => {
                return EvalResult::fetch_from_server(); // TODO
            }
            ConditionType::CurrentTime => {
                return EvalResult::fetch_from_server(); // TODO
            }
            ConditionType::UserBucket => {
                return EvalResult::fetch_from_server(); // TODO
            }
            ConditionType::UnitId => user.get_unit_id(&condition.id_type),
            ConditionType::Unknown => {
                return EvalResult::fetch_from_server();
            }
        };

        let pass = match condition
            .operator
            .as_ref()
            .unwrap_or(&OperatorType::Unknown)
        {
            OperatorType::Gt => {
                return EvalResult::fetch_from_server(); // TODO
            }
            OperatorType::Gte => {
                return EvalResult::fetch_from_server(); // TODO
            }
            OperatorType::Lt => {
                return EvalResult::fetch_from_server(); // TODO
            }
            OperatorType::Lte => {
                return EvalResult::fetch_from_server(); // TODO
            }
            OperatorType::VersionGt => {
                return EvalResult::fetch_from_server(); // TODO
            }
            OperatorType::VersionGte => {
                return EvalResult::fetch_from_server(); // TODO
            }
            OperatorType::VersionLt => {
                return EvalResult::fetch_from_server(); // TODO
            }
            OperatorType::VersionLte => {
                return EvalResult::fetch_from_server(); // TODO
            }
            OperatorType::VersionEq => {
                return EvalResult::fetch_from_server(); // TODO
            }
            OperatorType::VersionNeq => {
                return EvalResult::fetch_from_server(); // TODO
            }
            // Case insensitive
            OperatorType::Any => match condition
                .target_value
                .as_ref()
                .unwrap_or(&json!(null))
                .as_array()
            {
                None => false,
                Some(arr) => arr.iter().any(|v| match v.as_str() {
                    None => false,
                    Some(s) => s.to_ascii_lowercase() == value.to_ascii_lowercase(),
                }),
            },
            // Case insensitive
            OperatorType::None => match condition
                .target_value
                .as_ref()
                .unwrap_or(&json!(null))
                .as_array()
            {
                None => false,
                Some(arr) => !arr.iter().any(|v| match v.as_str() {
                    None => false,
                    Some(s) => s.to_ascii_lowercase() == value.to_ascii_lowercase(),
                }),
            },
            OperatorType::AnyCaseSensitive => {
                match condition
                    .target_value
                    .as_ref()
                    .unwrap_or(&json!(null))
                    .as_array()
                {
                    None => false,
                    Some(arr) => arr.iter().any(|v| match v.as_str() {
                        None => false,
                        Some(s) => s == value,
                    }),
                }
            }
            OperatorType::NoneCaseSensitive => {
                match condition
                    .target_value
                    .as_ref()
                    .unwrap_or(&json!(null))
                    .as_array()
                {
                    None => false,
                    Some(arr) => !arr.iter().any(|v| match v.as_str() {
                        None => false,
                        Some(s) => s == value,
                    }),
                }
            }
            OperatorType::StrStartsWithAny => {
                return EvalResult::fetch_from_server(); // TODO
            }
            OperatorType::StrEndsWithAny => {
                return EvalResult::fetch_from_server(); // TODO
            }
            OperatorType::StrContainsAny => {
                return EvalResult::fetch_from_server(); // TODO
            }
            OperatorType::StrContainsNone => {
                return EvalResult::fetch_from_server(); // TODO
            }
            OperatorType::StrMatches => {
                return EvalResult::fetch_from_server(); // TODO
            }
            OperatorType::Eq => match condition
                .target_value
                .as_ref()
                .unwrap_or(&json!(null))
                .as_str()
            {
                None => value.is_empty(),
                Some(target) => target == value,
            },
            OperatorType::Neq => match condition
                .target_value
                .as_ref()
                .unwrap_or(&json!(null))
                .as_str()
            {
                None => !value.is_empty(),
                Some(target) => target != value,
            },
            OperatorType::Before => {
                return EvalResult::fetch_from_server(); // TODO
            }
            OperatorType::After => {
                return EvalResult::fetch_from_server(); // TODO
            }
            OperatorType::On => {
                return EvalResult::fetch_from_server(); // TODO
            }
            OperatorType::InSegmentList => {
                return EvalResult::fetch_from_server(); // TODO
            }
            OperatorType::NotInSegmentList => {
                return EvalResult::fetch_from_server(); // TODO
            }
            OperatorType::Unknown => {
                return EvalResult::fetch_from_server();
            }
        };

        EvalResult {
            pass,
            ..Default::default()
        }
    }
}

#[cfg(test)]
mod test {
    use std::collections::HashMap;

    use serde_json::json;

    use super::{
        models::{ConditionType, ConfigCondition, ConfigSpec, EvalResult, OperatorType},
        Evaluator,
    };
    use crate::{evaluator::models::ConfigData, models::StatsigUser};

    fn test_eval_condition(
        name: &str,
        user: &StatsigUser,
        condition: &ConfigCondition,
        expected: &EvalResult,
    ) -> Result<(), String> {
        let evaluator = Evaluator::new();
        let result = evaluator.eval_condition(user, condition);
        if result.pass != expected.pass || result.fetch_from_server != expected.fetch_from_server {
            Err(format!("{}: failed", name))
        } else {
            Ok(())
        }
    }

    #[test]
    fn test_eval_condition_table() -> Result<(), String> {
        let user_id = "user_id".to_string();
        let mut custom_ids = HashMap::new();
        custom_ids.insert("not_userid".to_string(), "not_userid".to_string());
        custom_ids.insert("ALL_CAPS".to_string(), "ALL_CAPS".to_string());
        let user = StatsigUser {
            custom_ids: Some(custom_ids),
            ..StatsigUser::new(user_id, "production".to_string())
        };
        [
            (
                "public",
                &user,
                &ConfigCondition {
                    r#type: ConditionType::Public,
                    operator: None,
                    field: None,
                    target_value: None,
                    id_type: "userid".to_string(),
                },
                EvalResult::pass(),
            ),
            (
                "unknown_condition",
                &user,
                &ConfigCondition {
                    r#type: ConditionType::Unknown,
                    operator: None,
                    field: None,
                    target_value: None,
                    id_type: "userid".to_string(),
                },
                EvalResult {
                    fetch_from_server: true,
                    ..Default::default()
                },
            ),
            (
                "any_pass",
                &user,
                &ConfigCondition {
                    r#type: ConditionType::UnitId,
                    operator: Some(OperatorType::Any),
                    field: Some("field".to_string()),
                    target_value: Some(json!(["not_userid".to_string(), "user_iD".to_string()])),
                    id_type: "userid".to_string(),
                },
                EvalResult::pass(),
            ),
            (
                "any_fail",
                &user,
                &ConfigCondition {
                    r#type: ConditionType::UnitId,
                    operator: Some(OperatorType::Any),
                    field: Some("field".to_string()),
                    target_value: Some(json!([
                        "not_userid".to_string(),
                        "not_user_id2".to_string()
                    ])),
                    id_type: "userid".to_string(),
                },
                EvalResult::fail(),
            ),
            (
                "none_pass",
                &user,
                &ConfigCondition {
                    r#type: ConditionType::UnitId,
                    operator: Some(OperatorType::None),
                    field: Some("field".to_string()),
                    target_value: Some(json!([
                        "not_userid".to_string(),
                        "not_user_id2".to_string()
                    ])),
                    id_type: "userid".to_string(),
                },
                EvalResult::pass(),
            ),
            (
                "none_fail",
                &user,
                &ConfigCondition {
                    r#type: ConditionType::UnitId,
                    operator: Some(OperatorType::None),
                    field: Some("field".to_string()),
                    target_value: Some(json!(["not_userid".to_string(), "user_iD".to_string()])),
                    id_type: "userid".to_string(),
                },
                EvalResult::fail(),
            ),
            (
                "eq_pass",
                &user,
                &ConfigCondition {
                    r#type: ConditionType::UnitId,
                    operator: Some(OperatorType::Eq),
                    field: Some("field".to_string()),
                    target_value: Some(json!("user_id".to_string())),
                    id_type: "userid".to_string(),
                },
                EvalResult::pass(),
            ),
            (
                "eq_fail_null",
                &user,
                &ConfigCondition {
                    r#type: ConditionType::UnitId,
                    operator: Some(OperatorType::Eq),
                    field: Some("field".to_string()),
                    target_value: None,
                    id_type: "userid".to_string(),
                },
                EvalResult::fail(),
            ),
            (
                "eq_fail_different",
                &user,
                &ConfigCondition {
                    r#type: ConditionType::UnitId,
                    operator: Some(OperatorType::Eq),
                    field: Some("field".to_string()),
                    target_value: Some(json!("notid".to_string())),
                    id_type: "userid".to_string(),
                },
                EvalResult::fail(),
            ),
            (
                "neq_pass",
                &user,
                &ConfigCondition {
                    r#type: ConditionType::UnitId,
                    operator: Some(OperatorType::Neq),
                    field: Some("field".to_string()),
                    target_value: Some(json!("notuser_id".to_string())),
                    id_type: "userid".to_string(),
                },
                EvalResult::pass(),
            ),
            (
                "neq_pass_null",
                &user,
                &ConfigCondition {
                    r#type: ConditionType::UnitId,
                    operator: Some(OperatorType::Neq),
                    field: Some("field".to_string()),
                    target_value: None,
                    id_type: "userid".to_string(),
                },
                EvalResult::pass(),
            ),
            (
                "neq_fail_equal",
                &user,
                &ConfigCondition {
                    r#type: ConditionType::UnitId,
                    operator: Some(OperatorType::Neq),
                    field: Some("field".to_string()),
                    target_value: Some(json!("user_id".to_string())),
                    id_type: "userid".to_string(),
                },
                EvalResult::fail(),
            ),
        ]
        .iter()
        .try_for_each(|(name, user, condition, expected)| {
            test_eval_condition(name, user, condition, expected)
        })?;
        Ok(())
    }

    #[test]
    fn test_check_gate_pass() {
        let gate: ConfigSpec = serde_json::from_value(json!({
            "name": "test_gate",
            "type": "feature_gate",
            "salt": "salt",
            "enabled": true,
            "defaultValue": false,
            "idType": "userID",
            "rules": [{
                "name": "public",
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
        }))
        .unwrap();
        let user = &StatsigUser::new("user_id".to_string(), "production".to_string());
        let evaluator = Evaluator::new();
        evaluator.refresh_configs(ConfigData {
            feature_gates: Some(vec![gate]),
            dynamic_configs: None,
            layer_configs: None,
            has_updates: false,
            time: None,
        });
        assert!(
            evaluator
                .check_gate_internal(user, &"test_gate".to_string())
                .pass
        );
        assert!(
            !evaluator
                .check_gate_internal(user, &"test_gate2".to_string())
                .pass
        );

        let gate: ConfigSpec = serde_json::from_value(json!({
            "name": "test_gate",
            "type": "feature_gate",
            "salt": "salt",
            "enabled": true,
            "defaultValue": false,
            "idType": "userID",
            "rules": [{
                "name": "public",
                "id": "public1",
                "salt": "salt_rule",
                "passPercentage": 0,
                "idType": "userID",
                "returnValue": true,
                "conditions": [{
                    "type": "public",
                    "idType": "userid",
                }],
            }],
        }))
        .unwrap();
        let user = &StatsigUser::new("user_id".to_string(), "production".to_string());
        // update to pass 0 and check status, it should fail now
        evaluator.refresh_configs(ConfigData {
            feature_gates: Some(vec![gate]),
            dynamic_configs: None,
            layer_configs: None,
            has_updates: false,
            time: None,
        });
        assert!(
            !evaluator
                .check_gate_internal(user, &"test_gate".to_string())
                .pass
        );
    }
    // TODO: End to end test (check gate, parse from json)
}
