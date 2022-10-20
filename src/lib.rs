//! Implements the statsig client
//!
//! To change the default request timeout set the STATSIG_TIMEOUT_MS
//! environment variable to the desired timeout value.
//!
//! Reference: https://docs.statsig.com/http-api
mod client;
mod evaluator;
mod http;

pub mod models;
pub use crate::client::Client;
