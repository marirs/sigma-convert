use crate::{error::Error, utils::load_as_field_mappings, Result};
use rocket::serde::json::serde_json::to_string_pretty;
use rocket::{
    response::status::Created,
    serde::json::{self, Json},
};
use rocket_okapi::okapi::schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sigma_convert::from_sigma;

#[derive(Default, Debug, Clone, Serialize, Deserialize, PartialEq, JsonSchema)]
pub struct Data {
    pub sigma_rule_yml_content: String,
    pub destination_type: String,
    pub field_map: Option<String>,
    pub add_alerting: Option<String>,
    pub add_fields: Option<String>,
    pub replace_fields: Option<String>,
    pub keep_fields: Option<String>,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize, PartialEq, JsonSchema)]
pub struct BatchData {
    pub sigma_rules: Vec<Data>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct SingleConvertResponse {
    target: String,
    data: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct BatchConvertResponse {
    rules: Vec<SingleConvertResponse>,
}

#[openapi(tag = "Convert")]
#[post("/convert", data = "<data>")]
pub fn single_convert(
    data: std::result::Result<Json<Data>, json::Error<'_>>,
) -> Result<Created<String>> {
    // let x = json!(data);
    //serde_json::from_value::<Data>(json!(data)).unwrap_or_default()
    let data = data?;
    let (target, data) = conversion(data.into_inner())?;

    Ok(Created::new("").body(to_string_pretty(&SingleConvertResponse { target, data }).unwrap()))
}

#[openapi(tag = "Batch Convert")]
#[post("/batch-convert", data = "<data>")]
pub fn batch_convert(
    data: std::result::Result<Json<BatchData>, json::Error<'_>>,
) -> Result<Created<String>> {
    let data = data?;
    let res = batch_conversion(data.into_inner())?
        .into_iter()
        .map(|(target, data)| SingleConvertResponse { target, data })
        .collect::<Vec<_>>();
    let body = BatchConvertResponse { rules: res };
    Ok(Created::new("").body(to_string_pretty(&body).unwrap()))
}

fn batch_conversion(data: BatchData) -> Result<Vec<(String, String)>> {
    let mut results = vec![];
    for rule in data.sigma_rules.into_iter() {
        match conversion(rule.clone()) {
            Ok(result) => results.push(result),
            Err(e) => {
                let data = (rule.destination_type.clone(), format!("Could not convert this rule due to {:?}.", e));
                results.push(data);
            }
        }
    }
    Ok(results)
}

fn conversion(data: Data) -> Result<(String, String)> {
    let data = data.clone();
    let mappings = data.field_map.map(|map| load_as_field_mappings(&map));
    return match from_sigma(
        &data.sigma_rule_yml_content,
        &data.destination_type.to_lowercase(),
        mappings,
        data.add_alerting,
        data.add_fields,
        data.replace_fields,
        data.keep_fields,
    )
    .map(|x| (data.destination_type.clone(), x)){
        Ok(x) => Ok(x),
        Err(err) => {
            match err{
                sigma_convert::prelude::Error::SerdeError(err) => {
                    Ok((data.destination_type.clone(), format!("Formatting Error: The rule is wrongly formatted at the following section: \n{}", err.to_string())))
                },
                _=> Err(Error::BadRequest(err.to_string()))
            }
        }
    }
}
