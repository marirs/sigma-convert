#[macro_use]
extern crate rocket;
#[macro_use]
extern crate rocket_okapi;
#[macro_use]
pub(crate) mod macros;

/// All server related
pub mod server;

/// All guards/ssl generation/etc...
pub mod secure;

/// All the Routes/endpoints
mod controllers;

/// Utility functions
mod utils;

/// App related Errors
pub mod error;
pub type Result<T> = std::result::Result<T, error::Error>;
