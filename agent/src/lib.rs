//! Native direct-WebSocket integration for the vendored yoagent runtime.
//!
//! This crate keeps yoagent's agent loop and message/tool conversion while
//! routing provider calls through Identity's machine-token endpoint and the
//! existing LLM Gateway WebSocket. It does not expose a loopback HTTP server.

mod config;
mod gateway_provider;
mod proxy;

pub use config::{CredentialEnvelope, GatewayConfig, GatewayConfigError};
pub use gateway_provider::{GatewayProvider, GatewayProviderError};
