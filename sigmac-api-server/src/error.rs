use rocket::{
    http::Status,
    request::Request,
    response::{self, Responder},
    serde::json::Json,
};
use rocket_okapi::{
    gen::OpenApiGenerator, okapi::openapi3::Responses, response::OpenApiResponderInner,
};
use serde::ser::{Serialize, SerializeStruct, Serializer};

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Launch failed: {0}")]
    RocketError(#[from] Box<rocket::Error>),
    #[error("Format error: {0}")]
    FormatError(String),
    #[error("Not found")]
    NotFound,
    #[error("Unknown route")]
    UnknownRoute,
    #[error("{0}")]
    BadRequest(String),
    #[error("{0}")]
    InvalidResult(String),
    #[error("Internal error")]
    InternalError,
    #[error("User conflict")]
    UserConflict,
    #[error("Too many requests")]
    TooManyRequests,
    #[error("Configuration Error")]
    ConfigurationError(String),
    #[error("Config file not found")]
    ConfigFileNotFound,
    #[error("Error getting ssl certificates")]
    SslCertificateError,
    #[error("{0}")]
    Config(#[from] config::ConfigError),
    #[error("{0}")]
    Io(#[from] std::io::Error),
    #[error("Unknown Error")]
    Unknown,
}

impl Error {
    pub fn to_status(&self) -> Status {
        match *self {
            Self::BadRequest(_) | Self::InvalidResult(_) | Self::UserConflict => Status::BadRequest,
            Self::NotFound | Self::UnknownRoute => Status::NotFound,
            Self::TooManyRequests => Status::TooManyRequests,
            _ => Status::InternalServerError,
        }
    }
}

impl From<rocket::serde::json::Error<'_>> for Error {
    fn from(e: rocket::serde::json::Error<'_>) -> Self {
        Error::FormatError(format!("{:?}", e))
    }
}

impl Serialize for Error {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("Error", 2)?;
        state.serialize_field("error", &self.to_string())?;
        state.serialize_field("code", &self.to_status().code)?;

        state.end()
    }
}

impl<'r> Responder<'r, 'static> for Error {
    fn respond_to(self, request: &'r Request<'_>) -> response::Result<'static> {
        let status = self.to_status();

        response::Response::build_from(Json(self).respond_to(request)?)
            .status(status)
            .ok()
    }
}

impl OpenApiResponderInner for Error {
    fn responses(_generator: &mut OpenApiGenerator) -> rocket_okapi::Result<Responses> {
        Ok(Responses::default())
    }
}
