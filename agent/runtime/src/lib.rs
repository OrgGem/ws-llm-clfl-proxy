//! Retained YoAgent runtime used by the native Gateway client.
//!
//! This crate keeps the upstream agent loop, session/context machinery, hooks,
//! and opt-in Uteke memory integration. Model transport and credentials live
//! in the adjacent application crate; the provider module here contains only
//! shared protocol types and the OpenAI-compatible request/stream converter.

pub mod agent_loop;
pub mod config;
pub mod context;
pub mod core;
pub mod extension;
pub mod provider;
pub mod retry;
pub mod rt;
pub mod session;
pub mod shared_state;
pub mod tool_source;
pub mod tools;
pub mod types;

#[cfg(feature = "memory")]
pub mod memory_integration;

pub use agent_loop::{agent_loop, agent_loop_continue, PrepareContextFn};
pub use context::{CompactionStrategy, DefaultCompaction};
pub use core::{Agent, StructuredPromptError};
pub use extension::{Extension, ExtensionMode, RunHooks};
pub use retry::RetryConfig;
pub use session::{Session, SessionEntry, SessionError};
pub use shared_state::SharedState;
pub use tool_source::ToolSource;
pub use types::*;
