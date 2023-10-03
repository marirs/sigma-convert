use crate::error::Error::{ApiEndpointUnavailable, Generic, GlooNetError, SerdeError};
use crate::error::Result;
use crate::models::{
    BatchConvertResponse, BatchSigmaRuleData, ErrorResponse, SigmaRuleData, SingleConvertResponse,
};
use gloo_net::http::Request;
use std::env::var;
use yew::Callback;

pub fn single_convert(
    sigma_rule: SigmaRuleData,
    callback: Callback<Result<SingleConvertResponse>>,
) {
    let url = "/convert";
    wasm_bindgen_futures::spawn_local(async move {
        let converted_rule = match Request::post(url).json(&sigma_rule) {
            Ok(req) => match req.send().await {
                Ok(res) => match res.text().await {
                    Ok(t) => match serde_json::from_str::<SingleConvertResponse>(t.as_str()) {
                        Ok(t) => Ok(t),
                        Err(t) => Err(Generic(format!("{}", t))),
                    },
                    Err(e) => Err(GlooNetError(e)),
                },
                Err(e) => Err(ApiEndpointUnavailable(e.to_string())),
            },
            Err(e) => Err(SerdeError(e.to_string())),
        };
        callback.emit(converted_rule);
    });
}

pub fn batch_convert(
    sigma_rules: Vec<SigmaRuleData>,
    callback: Callback<Result<Vec<SingleConvertResponse>>>,
) {
    let url = "/batch-convert";
    wasm_bindgen_futures::spawn_local(async move {
        let batch_data = BatchSigmaRuleData { sigma_rules };
        let converted_rule = match Request::post(url).json(&batch_data) {
            Ok(req) => match req.send().await {
                Ok(res) => {
                    let res_text = res.text().await.unwrap();
                    match serde_json::from_str::<BatchConvertResponse>(res_text.as_str()) {
                        Ok(t) => Ok(t.rules),
                        Err(_) => {
                            let err_text =
                                serde_json::from_str::<ErrorResponse>(res_text.as_str()).unwrap();
                            Err(Generic(err_text.error))
                        }
                    }
                }
                Err(e) => Err(ApiEndpointUnavailable(e.to_string())),
            },
            Err(e) => Err(SerdeError(e.to_string())),
        };
        callback.emit(converted_rule);
    });
}

pub fn get_backends(callback: Callback<Result<Vec<String>>>) {
    let url = "/backends";
    wasm_bindgen_futures::spawn_local(async move {
        let backends = match Request::get(url).send().await {
            Ok(res) => {
                let res_text = res.text().await.unwrap();
                match serde_json::from_str::<Vec<String>>(res_text.as_str()) {
                    Ok(t) => Ok(t),
                    Err(_) => {
                        let err_text =
                            serde_json::from_str::<ErrorResponse>(res_text.as_str()).unwrap();
                        Err(Generic(err_text.error))
                    }
                }
            }
            Err(e) => Err(ApiEndpointUnavailable(e.to_string())),
        };
        callback.emit(backends);
    });
}
