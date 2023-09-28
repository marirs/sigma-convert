#![allow(dead_code)]
pub mod converter;

use rocket::response::status;
use rocket::serde::json::Json;
use rocket::{http::Status, serde::json::Value};
use serde::Serialize;

use crate::error::Error;

fn generic_response<T: Serialize>(result: std::result::Result<T, Error>) -> (Status, Value) {
    match result {
        Ok(data) => json_response!(data),
        Err(e) => json_response!(e.to_status().code, e.to_string()),
    }
}

/// Catches all OPTION requests in order to get the CORS related Fairing triggered.
#[openapi(skip)]
#[options("/<_..>")]
pub fn all_options() {
    /* Intentionally left empty */
}

#[openapi(skip)]
#[get("/backends")]
pub fn implemented_backends() -> status::Custom<Json<Vec<String>>> {
    status::Custom(Status::Ok, Json(sigma_convert::Backends::get_all()))
}
