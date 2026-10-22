//! Shared OpenAI-compatible Chat Completions types and conversion.
//!
//! This module does not create network clients. The adjacent CLI owns token
//! exchange and Gateway WebSocket transport; the runtime provides request
//! conversion, bounded SSE parsing, tool arguments, and test providers.

pub mod mock;
pub mod model;
pub mod openai_compat;
pub mod tool_args;
pub mod traits;
pub mod turn_hook;

pub use mock::MockProvider;
pub use model::{
    ApiProtocol, ContextTier, CostConfig, MaxTokensField, ModelConfig, OpenAiCompat,
    ReasoningEffortCeiling, ThinkingFormat,
};
pub use tool_args::{parse_tool_arguments, unparsed_tool_arguments, UNPARSED_ARGUMENTS_KEY};
pub use traits::*;
pub use turn_hook::TurnHookProvider;
