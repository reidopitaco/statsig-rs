//! Implements the statsig client
//!
//! To change the default request timeout set the STATSIG_TIMEOUT_MS
//! environment variable to the desired timeout value.
//!
//! Reference: https://docs.statsig.com/http-api
//!
//! ## Experiments and Holdouts
//!
//! For proper holdout tracking, use `get_experiment` instead of `get_dynamic_config`:
//!
//! ```ignore
//! let experiment = client.get_experiment::<MyConfig>("experiment_name", user).await?;
//! ```
//!
//! The `get_experiment` method uses the `/log_custom_exposure` endpoint which properly
//! tracks holdout exposures, while `get_dynamic_config` uses the legacy exposure logging
//! that doesn't support holdouts.
mod client;
mod evaluator;
mod http;

pub mod models;
pub use crate::client::Client;
