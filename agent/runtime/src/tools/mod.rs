//! Safe artifact-sharing tool helpers used by the agent runtime.
//!
//! The CLI does not install these tools by default. Applications may opt in to
//! [`SharedStateTool`] when a run needs to pass a bounded artifact by reference.

pub mod shared_state_tool;

pub use shared_state_tool::SharedStateTool;
