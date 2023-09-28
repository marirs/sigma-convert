#![allow(dead_code)]
use std::result;

pub type Result<T> = result::Result<T, Error>;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("{0}")]
    BadRequest(String),
    #[error("{0}")]
    GlooNetError(gloo_net::Error),
    #[error("The api endpoint {0} is unavailable.")]
    ApiEndpointUnavailable(String),
    #[error("Sorry, there was an internal server error. Please try again later.")]
    InternalServerError,
    #[error("{0}")]
    SerdeError(String),
    #[error("{0}")]
    Generic(String),
}
