use std::{
    cmp::max,
    collections::HashMap,
    time::{Duration, SystemTime},
};

use chrono::{Datelike, TimeZone, Utc};
use crossbeam::sync::ShardedLock;
use serde_json::json;

use crate::{
    evaluator::{getters::get_config_value, models::OperatorType},
    models::StatsigUser,
};

use self::getters::{get_hash, get_numeric_value, get_string, get_unix_epoch};
use self::models::{
    ConditionType, ConfigCondition, ConfigData, ConfigRule, ConfigSpec, EvalResult,
};

mod getters;
pub mod models;

fn compare_numbers(
    v1: &serde_json::Value,
    v2: &serde_json::Value,
    f: fn(f64, f64) -> bool,
) -> bool {
    let n1 = get_numeric_value(v1);
    let n2 = get_numeric_value(v2);
    if n1.is_none() || n2.is_none() {
        false
    } else {
        f(n1.unwrap_or_default(), n2.unwrap_or_default())
    }
}

fn compare_versions(v1: &serde_json::Value, v2: &serde_json::Value, f: fn(i32) -> bool) -> bool {
    let n1 = get_string(v1);
    let n2 = get_string(v2);
    if n1.is_none() || n2.is_none() {
        return false;
    }

    let mut n1 = n1.unwrap();
    let mut n2 = n2.unwrap();
    if let Some(index) = n1.find('-') {
        n1 = n1[0..index].to_string();
    }
    if let Some(index) = n2.find('-') {
        n2 = n2[0..index].to_string();
    }

    let n1_parts: Vec<&str> = n1.split('.').collect();
    let n2_parts: Vec<&str> = n2.split('.').collect();
    let mut cnt = 0;
    let mut ret = 0;
    while ret == 0 && cnt < max(n1_parts.len(), n2_parts.len()) {
        let n1_val = if cnt < n1_parts.len() {
            n1_parts[cnt].parse().unwrap_or_default()
        } else {
            0
        };
        let n2_val = if cnt < n2_parts.len() {
            n2_parts[cnt].parse().unwrap_or_default()
        } else {
            0
        };
        if n1_val < n2_val {
            ret = -1;
        }
        if n2_val < n1_val {
            ret = 1;
        }
        cnt += 1;
    }

    f(ret)
}

fn eval_pass_percent(user: &StatsigUser, rule: &ConfigRule, spec: &ConfigSpec) -> bool {
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

pub struct Evaluator {
    dynamic_configs: ShardedLock<HashMap<String, ConfigSpec>>,
    gates: ShardedLock<HashMap<String, ConfigSpec>>,
    #[allow(unused)]
    layer_configs: ShardedLock<HashMap<String, ConfigSpec>>,
}

impl Evaluator {
    pub fn new() -> Self {
        Self {
            dynamic_configs: ShardedLock::new(HashMap::new()),
            gates: ShardedLock::new(HashMap::new()),
            layer_configs: ShardedLock::new(HashMap::new()),
        }
    }

    pub fn refresh_configs(&self, data: ConfigData) {
        let new_dynamic_configs = data
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
        let layer_configs = data
            .layer_configs
            .unwrap_or_default()
            .into_iter()
            .map(|f| (f.name.clone(), f))
            .collect();

        let mut dynamic_configs = self
            .dynamic_configs
            .write()
            .expect("should not be poisoned");
        *dynamic_configs = new_dynamic_configs;
        let mut gates = self.gates.write().expect("should not be poisoned");
        *gates = feature_gates;
        let mut layers = self.layer_configs.write().expect("should not be poisoned");
        *layers = layer_configs;
    }

    pub fn check_gate_internal(&self, user: &StatsigUser, gate_name: &String) -> EvalResult {
        match self
            .gates
            .read()
            .expect("should always be able to acquire read lock")
            .get(gate_name)
        {
            Some(gate) => self.eval_spec(user, gate),
            None => EvalResult::fail(),
        }
    }

    pub fn get_dynamic_config_internal(
        &self,
        user: &StatsigUser,
        config_name: &String,
    ) -> EvalResult {
        match self
            .dynamic_configs
            .read()
            .expect("should always be able to acquire read lock")
            .get(config_name)
        {
            Some(spec) => self.eval_spec(user, spec),
            None => EvalResult::fail(),
        }
    }

    fn eval_spec(&self, user: &StatsigUser, spec: &ConfigSpec) -> EvalResult {
        if !spec.enabled {
            return EvalResult {
                id: "disabled".to_string(),
                ..EvalResult::fail()
            };
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
                    // TODO: Eval delegates
                    let pass = eval_pass_percent(user, rule, spec);
                    let (config_value, group, group_name, rule_id) = if pass {
                        (
                            get_config_value(&rule.return_value, spec.r#type),
                            rule.name.clone(),
                            rule.group_name.clone(),
                            rule.id.clone(),
                        )
                    } else {
                        (
                            get_config_value(&spec.default_value, spec.r#type),
                            "default".to_owned(),
                            "default".to_owned(),
                            "default".to_owned(),
                        )
                    };

                    return EvalResult {
                        pass,
                        id: rule.id.clone(),
                        secondary_exposures: exposures,
                        config_value,
                        group,
                        group_name,
                        rule_id,
                        ..Default::default()
                    };
                }
            }
        }

        // No rules matched, return the default value
        EvalResult {
            secondary_exposures: exposures,
            config_value: get_config_value(&spec.default_value, spec.r#type),
            ..EvalResult::fail()
        }
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
        let empty = json!(null);
        let empty_str: String = "".to_string();
        let value = match condition.r#type {
            ConditionType::Public => return EvalResult::pass(),
            ConditionType::FailGate | ConditionType::PassGate => {
                let gate_name = match condition.target_value.as_ref().unwrap_or(&empty).as_str() {
                    None => return EvalResult::fail(),
                    Some(s) => s,
                };
                let mut res = self.check_gate_internal(user, &gate_name.to_string());
                if res.fetch_from_server {
                    return EvalResult::fetch_from_server();
                }
                let new_exposure = HashMap::from([
                    ("gate".to_string(), gate_name.to_string()),
                    ("gateValue".to_string(), res.pass.to_string()),
                    ("ruleID".to_string(), res.id),
                ]);
                let mut exposures = std::mem::take(&mut res.secondary_exposures);
                exposures.push(new_exposure);
                let pass = (condition.r#type == ConditionType::PassGate && res.pass)
                    || (condition.r#type == ConditionType::FailGate && !res.pass);
                return EvalResult {
                    pass,
                    secondary_exposures: exposures,
                    ..Default::default()
                };
            }
            ConditionType::IpBased => {
                return EvalResult::fetch_from_server(); // TODO
            }
            ConditionType::UaBased => {
                return EvalResult::fetch_from_server(); // TODO
            }
            ConditionType::UserField => {
                json!(user.get_field(condition.field.as_ref().unwrap_or(&empty_str)))
            }
            ConditionType::EnvironmentField => {
                json!(user
                    .statsig_environment
                    .get_field(condition.field.as_ref().unwrap_or(&empty_str)))
            }
            ConditionType::CurrentTime => json!(SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_else(|_| Duration::from_secs(0))
                .as_secs()),
            ConditionType::UserBucket => {
                if let Some(salt) = condition
                    .additional_values
                    .as_ref()
                    .and_then(|h| h.get(&"salt".to_string()))
                {
                    json!(
                        get_hash(format!("{}.{}", salt, user.get_unit_id(&condition.id_type)))
                            % 1000
                    )
                } else {
                    json!(null)
                }
            }
            ConditionType::UnitId => json!(user.get_unit_id(&condition.id_type)),
            ConditionType::Unknown => {
                return EvalResult::fetch_from_server();
            }
        };

        let pass = match condition
            .operator
            .as_ref()
            .unwrap_or(&OperatorType::Unknown)
        {
            OperatorType::Gt => compare_numbers(
                &value,
                condition.target_value.as_ref().unwrap_or(&empty),
                |n1, n2| n1 > n2,
            ),
            OperatorType::Gte => compare_numbers(
                &value,
                condition.target_value.as_ref().unwrap_or(&empty),
                |n1, n2| n1 >= n2,
            ),
            OperatorType::Lt => compare_numbers(
                &value,
                condition.target_value.as_ref().unwrap_or(&empty),
                |n1, n2| n1 < n2,
            ),
            OperatorType::Lte => compare_numbers(
                &value,
                condition.target_value.as_ref().unwrap_or(&empty),
                |n1, n2| n1 <= n2,
            ),
            OperatorType::VersionGt => compare_versions(
                &value,
                condition.target_value.as_ref().unwrap_or(&empty),
                |cmp| cmp > 0,
            ),
            OperatorType::VersionGte => compare_versions(
                &value,
                condition.target_value.as_ref().unwrap_or(&empty),
                |cmp| cmp >= 0,
            ),
            OperatorType::VersionLt => compare_versions(
                &value,
                condition.target_value.as_ref().unwrap_or(&empty),
                |cmp| cmp < 0,
            ),
            OperatorType::VersionLte => compare_versions(
                &value,
                condition.target_value.as_ref().unwrap_or(&empty),
                |cmp| cmp <= 0,
            ),
            OperatorType::VersionEq => compare_versions(
                &value,
                condition.target_value.as_ref().unwrap_or(&empty),
                |cmp| cmp == 0,
            ),
            OperatorType::VersionNeq => compare_versions(
                &value,
                condition.target_value.as_ref().unwrap_or(&empty),
                |cmp| cmp != 0,
            ),
            // Case insensitive
            OperatorType::Any => {
                let lower_val = get_string(&value).map(|v| v.to_ascii_lowercase());
                match condition.target_value.as_ref().unwrap_or(&empty).as_array() {
                    None => false,
                    Some(arr) => arr
                        .iter()
                        .any(|v| get_string(v).map(|val| val.to_ascii_lowercase()) == lower_val),
                }
            }
            // Case insensitive
            OperatorType::None => {
                let lower_val = get_string(&value).map(|v| v.to_ascii_lowercase());
                match condition.target_value.as_ref().unwrap_or(&empty).as_array() {
                    None => true,
                    Some(arr) => !arr
                        .iter()
                        .any(|v| get_string(v).map(|val| val.to_ascii_lowercase()) == lower_val),
                }
            }
            OperatorType::AnyCaseSensitive => {
                match condition.target_value.as_ref().unwrap_or(&empty).as_array() {
                    None => false,
                    Some(arr) => arr.iter().any(|v| match get_string(v) {
                        None => false,
                        Some(s) => s == value,
                    }),
                }
            }
            OperatorType::NoneCaseSensitive => {
                match condition.target_value.as_ref().unwrap_or(&empty).as_array() {
                    None => true,
                    Some(arr) => !arr.iter().any(|v| match get_string(v) {
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
            OperatorType::Eq => match condition.target_value.as_ref().unwrap_or(&empty).as_str() {
                None => {
                    (value.is_string() && matches!(&value.as_str(), Some(""))) || value.is_null()
                }
                Some(target) => target == value,
            },
            OperatorType::Neq => match condition.target_value.as_ref().unwrap_or(&empty).as_str() {
                None => {
                    !((value.is_string() && matches!(&value.as_str(), Some(""))) || value.is_null())
                }
                Some(target) => target != value,
            },
            OperatorType::Before => {
                get_unix_epoch(&value)
                    < get_unix_epoch(condition.target_value.as_ref().unwrap_or(&empty))
            }
            OperatorType::After => {
                get_unix_epoch(&value)
                    > get_unix_epoch(condition.target_value.as_ref().unwrap_or(&empty))
            }
            OperatorType::On => {
                let d1 = Utc.timestamp(get_unix_epoch(&value), 0);
                let d2 = Utc.timestamp(
                    get_unix_epoch(condition.target_value.as_ref().unwrap_or(&empty)),
                    0,
                );
                d1.day() == d2.day() && d1.month() == d2.month() && d1.year() == d2.year()
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
    use std::{
        collections::HashMap,
        ops::{Add, Sub},
        time::{Duration, SystemTime},
    };

    use serde_json::json;

    use super::{
        models::{
            ConditionType, ConfigCondition, ConfigRule, ConfigSpec, ConfigSpecType, EvalResult,
            OperatorType,
        },
        Evaluator,
    };
    use crate::{evaluator::models::ConfigData, models::StatsigUser};

    fn test_eval_condition(
        name: &str,
        user: &StatsigUser,
        condition: &ConfigCondition,
        expected: &EvalResult,
    ) -> Result<(), String> {
        let default_configs = ConfigData {
            dynamic_configs: None,
            layer_configs: None,
            has_updates: true,
            time: None,
            feature_gates: Some(vec![
                ConfigSpec {
                    name: "user_id_match".to_string(),
                    r#type: ConfigSpecType::FeatureGate,
                    salt: "salt".to_string(),
                    enabled: true,
                    default_value: json!(null),
                    id_type: None,
                    rules: Some(vec![ConfigRule {
                        name: "user_id_match".to_string(),
                        group_name: "User id match".to_owned(),
                        id: "user_id_id".to_string(),
                        salt: "salt".to_string(),
                        pass_percentage: 100.0,
                        id_type: "userID".to_string(),
                        return_value: json!(null),
                        conditions: vec![ConfigCondition {
                            r#type: ConditionType::UnitId,
                            operator: Some(OperatorType::Eq),
                            field: Some("field".to_string()),
                            target_value: Some(json!("user_id".to_string())),
                            id_type: "userid".to_string(),
                            additional_values: None,
                        }],
                    }]),
                },
                ConfigSpec {
                    name: "user_id_not_match".to_string(),
                    r#type: ConfigSpecType::FeatureGate,
                    salt: "salt".to_string(),
                    enabled: true,
                    default_value: json!(null),
                    id_type: None,
                    rules: Some(vec![ConfigRule {
                        name: "user_id_not_match".to_string(),
                        group_name: "User id not match".to_owned(),
                        id: "user_id_not_match_id".to_string(),
                        salt: "salt".to_string(),
                        pass_percentage: 100.0,
                        id_type: "userID".to_string(),
                        return_value: json!(null),
                        conditions: vec![ConfigCondition {
                            r#type: ConditionType::UnitId,
                            operator: Some(OperatorType::Neq),
                            field: Some("field".to_string()),
                            target_value: Some(json!("user_id".to_string())),
                            id_type: "userid".to_string(),
                            additional_values: None,
                        }],
                    }]),
                },
            ]),
        };
        let evaluator = Evaluator::new();
        evaluator.refresh_configs(default_configs);
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
        let user = StatsigUser {
            custom_ids: Some(HashMap::from([
                ("not_userid".to_string(), "not_userid".to_string()),
                ("ALL_CAPS".to_string(), "ALL_CAPS".to_string()),
            ])),
            custom: Some(HashMap::from([(
                "totalDeposit".to_string(),
                "30".to_string(),
            )])),
            app_version: Some("300.10.2".to_string()),
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
                    additional_values: None,
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
                    additional_values: None,
                },
                EvalResult {
                    fetch_from_server: true,
                    ..Default::default()
                },
            ),
            (
                "user_bucket_pass",
                &user,
                &ConfigCondition {
                    r#type: ConditionType::UserBucket,
                    operator: Some(OperatorType::Gt),
                    field: None,
                    target_value: Some(json!(500)),
                    id_type: "userID".to_string(),
                    additional_values: Some(HashMap::from([(
                        "salt".to_string(),
                        "cool_salt12".to_string(),
                    )])),
                },
                EvalResult::pass(),
            ),
            (
                "user_bucket_fail",
                &user,
                &ConfigCondition {
                    r#type: ConditionType::UserBucket,
                    operator: Some(OperatorType::Lte),
                    field: None,
                    target_value: Some(json!(500)),
                    id_type: "userID".to_string(),
                    additional_values: Some(HashMap::from([(
                        "salt".to_string(),
                        "cool_salt12".to_string(),
                    )])),
                },
                EvalResult::fail(),
            ),
            (
                "gt_pass",
                &user,
                &ConfigCondition {
                    r#type: ConditionType::UserField,
                    operator: Some(OperatorType::Gt),
                    field: Some("totalDeposit".to_string()),
                    target_value: Some(json!("15".to_string())),
                    id_type: "userid".to_string(),
                    additional_values: None,
                },
                EvalResult::pass(),
            ),
            (
                "gt_fail",
                &user,
                &ConfigCondition {
                    r#type: ConditionType::UserField,
                    operator: Some(OperatorType::Gt),
                    field: Some("totalDeposit".to_string()),
                    target_value: Some(json!("40".to_string())),
                    id_type: "userid".to_string(),
                    additional_values: None,
                },
                EvalResult::fail(),
            ),
            (
                "gt_fail_empty_field",
                &user,
                &ConfigCondition {
                    r#type: ConditionType::UserField,
                    operator: Some(OperatorType::Gt),
                    field: Some("somethingElse".to_string()),
                    target_value: Some(json!("-5".to_string())),
                    id_type: "userid".to_string(),
                    additional_values: None,
                },
                EvalResult::fail(),
            ),
            (
                "gte_pass",
                &user,
                &ConfigCondition {
                    r#type: ConditionType::UserField,
                    operator: Some(OperatorType::Gte),
                    field: Some("totalDeposit".to_string()),
                    target_value: Some(json!("30".to_string())),
                    id_type: "userid".to_string(),
                    additional_values: None,
                },
                EvalResult::pass(),
            ),
            (
                "gte_fail",
                &user,
                &ConfigCondition {
                    r#type: ConditionType::UserField,
                    operator: Some(OperatorType::Gte),
                    field: Some("totalDeposit".to_string()),
                    target_value: Some(json!("40".to_string())),
                    id_type: "userid".to_string(),
                    additional_values: None,
                },
                EvalResult::fail(),
            ),
            (
                "lt_pass",
                &user,
                &ConfigCondition {
                    r#type: ConditionType::UserField,
                    operator: Some(OperatorType::Lt),
                    field: Some("totalDeposit".to_string()),
                    target_value: Some(json!("40".to_string())),
                    id_type: "userid".to_string(),
                    additional_values: None,
                },
                EvalResult::pass(),
            ),
            (
                "lt_fail",
                &user,
                &ConfigCondition {
                    r#type: ConditionType::UserField,
                    operator: Some(OperatorType::Lt),
                    field: Some("totalDeposit".to_string()),
                    target_value: Some(json!("20".to_string())),
                    id_type: "userid".to_string(),
                    additional_values: None,
                },
                EvalResult::fail(),
            ),
            (
                "lte_pass",
                &user,
                &ConfigCondition {
                    r#type: ConditionType::UserField,
                    operator: Some(OperatorType::Lte),
                    field: Some("totalDeposit".to_string()),
                    target_value: Some(json!("30".to_string())),
                    id_type: "userid".to_string(),
                    additional_values: None,
                },
                EvalResult::pass(),
            ),
            (
                "lte_fail",
                &user,
                &ConfigCondition {
                    r#type: ConditionType::UserField,
                    operator: Some(OperatorType::Lte),
                    field: Some("totalDeposit".to_string()),
                    target_value: Some(json!("20".to_string())),
                    id_type: "userid".to_string(),
                    additional_values: None,
                },
                EvalResult::fail(),
            ),
            (
                "environment_pass",
                &user,
                &ConfigCondition {
                    r#type: ConditionType::EnvironmentField,
                    operator: Some(OperatorType::Any),
                    field: Some("tier".to_string()),
                    target_value: Some(json!(["production".to_string(), "staging".to_string()])),
                    id_type: "userid".to_string(),
                    additional_values: None,
                },
                EvalResult::pass(),
            ),
            (
                "environment_fail",
                &user,
                &ConfigCondition {
                    r#type: ConditionType::EnvironmentField,
                    operator: Some(OperatorType::Any),
                    field: Some("tier".to_string()),
                    target_value: Some(json!(["staging".to_string()])),
                    id_type: "userid".to_string(),
                    additional_values: None,
                },
                EvalResult::fail(),
            ),
            (
                "version_gt_pass",
                &user,
                &ConfigCondition {
                    r#type: ConditionType::UserField,
                    operator: Some(OperatorType::VersionGt),
                    field: Some("appVersion".to_string()),
                    target_value: Some(json!("300.9.1".to_string())),
                    id_type: "userid".to_string(),
                    additional_values: None,
                },
                EvalResult::pass(),
            ),
            (
                "version_gt_fail",
                &user,
                &ConfigCondition {
                    r#type: ConditionType::UserField,
                    operator: Some(OperatorType::VersionGt),
                    field: Some("appVersion".to_string()),
                    target_value: Some(json!("300.10.2".to_string())),
                    id_type: "userid".to_string(),
                    additional_values: None,
                },
                EvalResult::fail(),
            ),
            (
                "version_gte_pass",
                &user,
                &ConfigCondition {
                    r#type: ConditionType::UserField,
                    operator: Some(OperatorType::VersionGte),
                    field: Some("appVersion".to_string()),
                    target_value: Some(json!("300.10.1".to_string())),
                    id_type: "userid".to_string(),
                    additional_values: None,
                },
                EvalResult::pass(),
            ),
            (
                "version_gte_pass",
                &user,
                &ConfigCondition {
                    r#type: ConditionType::UserField,
                    operator: Some(OperatorType::VersionGte),
                    field: Some("appVersion".to_string()),
                    target_value: Some(json!("300.10.2".to_string())),
                    id_type: "userid".to_string(),
                    additional_values: None,
                },
                EvalResult::pass(),
            ),
            (
                "version_gte_fail",
                &user,
                &ConfigCondition {
                    r#type: ConditionType::UserField,
                    operator: Some(OperatorType::VersionGte),
                    field: Some("appVersion".to_string()),
                    target_value: Some(json!("300.11.0".to_string())),
                    id_type: "userid".to_string(),
                    additional_values: None,
                },
                EvalResult::fail(),
            ),
            (
                "version_lt_pass",
                &user,
                &ConfigCondition {
                    r#type: ConditionType::UserField,
                    operator: Some(OperatorType::VersionLt),
                    field: Some("appVersion".to_string()),
                    target_value: Some(json!("300.10.3".to_string())),
                    id_type: "userid".to_string(),
                    additional_values: None,
                },
                EvalResult::pass(),
            ),
            (
                "version_lt_fail",
                &user,
                &ConfigCondition {
                    r#type: ConditionType::UserField,
                    operator: Some(OperatorType::VersionLt),
                    field: Some("appVersion".to_string()),
                    target_value: Some(json!("200.10.2".to_string())),
                    id_type: "userid".to_string(),
                    additional_values: None,
                },
                EvalResult::fail(),
            ),
            (
                "version_lte_pass",
                &user,
                &ConfigCondition {
                    r#type: ConditionType::UserField,
                    operator: Some(OperatorType::VersionLte),
                    field: Some("appVersion".to_string()),
                    target_value: Some(json!("300.10.3".to_string())),
                    id_type: "userid".to_string(),
                    additional_values: None,
                },
                EvalResult::pass(),
            ),
            (
                "version_lte_pass",
                &user,
                &ConfigCondition {
                    r#type: ConditionType::UserField,
                    operator: Some(OperatorType::VersionLte),
                    field: Some("appVersion".to_string()),
                    target_value: Some(json!("300.10.2".to_string())),
                    id_type: "userid".to_string(),
                    additional_values: None,
                },
                EvalResult::pass(),
            ),
            (
                "version_lte_fail",
                &user,
                &ConfigCondition {
                    r#type: ConditionType::UserField,
                    operator: Some(OperatorType::VersionLte),
                    field: Some("appVersion".to_string()),
                    target_value: Some(json!("300.10.1".to_string())),
                    id_type: "userid".to_string(),
                    additional_values: None,
                },
                EvalResult::fail(),
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
                    additional_values: None,
                },
                EvalResult::pass(),
            ),
            (
                "any_pass_number",
                &user,
                &ConfigCondition {
                    r#type: ConditionType::UserField,
                    operator: Some(OperatorType::Any),
                    field: Some("totalDeposit".to_string()),
                    target_value: Some(json!([15, 30])),
                    id_type: "userid".to_string(),
                    additional_values: None,
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
                    additional_values: None,
                },
                EvalResult::fail(),
            ),
            (
                "none_pass",
                &user,
                &ConfigCondition {
                    r#type: ConditionType::UnitId,
                    operator: Some(OperatorType::None),
                    field: None,
                    target_value: Some(json!([
                        "not_userid".to_string(),
                        "not_user_id2".to_string()
                    ])),
                    id_type: "userid".to_string(),
                    additional_values: None,
                },
                EvalResult::pass(),
            ),
            (
                "none_fail",
                &user,
                &ConfigCondition {
                    r#type: ConditionType::UnitId,
                    operator: Some(OperatorType::None),
                    field: None,
                    target_value: Some(json!(["not_userid".to_string(), "user_iD".to_string()])),
                    id_type: "userid".to_string(),
                    additional_values: None,
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
                    additional_values: None,
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
                    additional_values: None,
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
                    additional_values: None,
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
                    additional_values: None,
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
                    additional_values: None,
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
                    additional_values: None,
                },
                EvalResult::fail(),
            ),
            (
                "before_pass",
                &user,
                &ConfigCondition {
                    r#type: ConditionType::CurrentTime,
                    operator: Some(OperatorType::Before),
                    field: Some("field".to_string()),
                    target_value: Some(json!(
                        SystemTime::now()
                            .add(Duration::from_secs(300))
                            .duration_since(SystemTime::UNIX_EPOCH)
                            .unwrap()
                            .as_secs()
                            * 1000
                    )),
                    id_type: "userid".to_string(),
                    additional_values: None,
                },
                EvalResult::pass(),
            ),
            (
                "before_fail",
                &user,
                &ConfigCondition {
                    r#type: ConditionType::CurrentTime,
                    operator: Some(OperatorType::Before),
                    field: Some("field".to_string()),
                    target_value: Some(json!(
                        SystemTime::now()
                            .sub(Duration::from_secs(300))
                            .duration_since(SystemTime::UNIX_EPOCH)
                            .unwrap()
                            .as_secs()
                            * 1000
                    )),
                    id_type: "userid".to_string(),
                    additional_values: None,
                },
                EvalResult::fail(),
            ),
            (
                "after_pass",
                &user,
                &ConfigCondition {
                    r#type: ConditionType::CurrentTime,
                    operator: Some(OperatorType::After),
                    field: Some("field".to_string()),
                    target_value: Some(json!(
                        SystemTime::now()
                            .sub(Duration::from_secs(300))
                            .duration_since(SystemTime::UNIX_EPOCH)
                            .unwrap()
                            .as_secs()
                            * 1000
                    )),
                    id_type: "userid".to_string(),
                    additional_values: None,
                },
                EvalResult::pass(),
            ),
            (
                "after_fail",
                &user,
                &ConfigCondition {
                    r#type: ConditionType::CurrentTime,
                    operator: Some(OperatorType::After),
                    field: Some("field".to_string()),
                    target_value: Some(json!(
                        SystemTime::now()
                            .add(Duration::from_secs(300))
                            .duration_since(SystemTime::UNIX_EPOCH)
                            .unwrap()
                            .as_secs()
                            * 1000
                    )),
                    id_type: "userid".to_string(),
                    additional_values: None,
                },
                EvalResult::fail(),
            ),
            (
                "on_pass",
                &user,
                &ConfigCondition {
                    r#type: ConditionType::CurrentTime,
                    operator: Some(OperatorType::On),
                    field: Some("field".to_string()),
                    target_value: Some(json!(
                        SystemTime::now()
                            .duration_since(SystemTime::UNIX_EPOCH)
                            .unwrap()
                            .as_secs()
                            * 1000
                    )),
                    id_type: "userid".to_string(),
                    additional_values: None,
                },
                EvalResult::pass(),
            ),
            (
                "on_fail",
                &user,
                &ConfigCondition {
                    r#type: ConditionType::CurrentTime,
                    operator: Some(OperatorType::On),
                    field: Some("field".to_string()),
                    target_value: Some(json!(
                        SystemTime::now()
                            .add(Duration::from_secs(36 * 60 * 60))
                            .duration_since(SystemTime::UNIX_EPOCH)
                            .unwrap()
                            .as_secs()
                            * 1000
                    )),
                    id_type: "userid".to_string(),
                    additional_values: None,
                },
                EvalResult::fail(),
            ),
            (
                "pass_gate_pass",
                &user,
                &ConfigCondition {
                    r#type: ConditionType::PassGate,
                    operator: None,
                    field: Some("field".to_string()),
                    target_value: Some(json!("user_id_match".to_string())),
                    id_type: "userid".to_string(),
                    additional_values: None,
                },
                EvalResult::pass(),
            ),
            (
                "pass_gate_fail",
                &user,
                &ConfigCondition {
                    r#type: ConditionType::PassGate,
                    operator: None,
                    field: Some("field".to_string()),
                    target_value: Some(json!("user_id_not_match".to_string())),
                    id_type: "userid".to_string(),
                    additional_values: None,
                },
                EvalResult::fail(),
            ),
            (
                "pass_gate_fail_gate_does_not_exist",
                &user,
                &ConfigCondition {
                    r#type: ConditionType::PassGate,
                    operator: None,
                    field: Some("field".to_string()),
                    target_value: Some(json!("invalid_gate".to_string())),
                    id_type: "userid".to_string(),
                    additional_values: None,
                },
                EvalResult::fail(),
            ),
            (
                "fail_gate_pass",
                &user,
                &ConfigCondition {
                    r#type: ConditionType::FailGate,
                    operator: None,
                    field: Some("field".to_string()),
                    target_value: Some(json!("user_id_not_match".to_string())),
                    id_type: "userid".to_string(),
                    additional_values: None,
                },
                EvalResult::pass(),
            ),
            (
                "fail_gate_fail",
                &user,
                &ConfigCondition {
                    r#type: ConditionType::FailGate,
                    operator: None,
                    field: Some("field".to_string()),
                    target_value: Some(json!("user_id_match".to_string())),
                    id_type: "userid".to_string(),
                    additional_values: None,
                },
                EvalResult::fail(),
            ),
            (
                "fail_gate_fail_empty_target",
                &user,
                &ConfigCondition {
                    r#type: ConditionType::FailGate,
                    operator: None,
                    field: Some("field".to_string()),
                    target_value: None,
                    id_type: "userid".to_string(),
                    additional_values: None,
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
                "groupName": "public",
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
}
