use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SigmaRuleData {
    pub sigma_rule_yml_content: String,
    pub destination_type: String,
    pub field_map: Option<String>,
    pub add_alerting: Option<String>,
    pub add_fields: Option<String>,
    pub replace_fields: Option<String>,
    pub keep_fields: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BatchSigmaRuleData {
    pub sigma_rules: Vec<SigmaRuleData>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
    pub code: u32,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct SingleConvertResponse {
    pub target: String,
    pub data: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct BatchConvertResponse {
    pub rules: Vec<SingleConvertResponse>,
}
