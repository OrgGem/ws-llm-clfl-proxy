//! OpenAI Chat Completions compatible provider.
//!
//! One implementation covers OpenAI, xAI, Groq, Cerebras, OpenRouter,
//! Mistral, DeepSeek, MiniMax, HuggingFace, Kimi, and any other provider
//! that implements the OpenAI Chat Completions API.
//!
//! Behavioral differences are handled via `OpenAiCompat` flags in ModelConfig.

use super::model::{MaxTokensField, ModelConfig, OpenAiCompat, ThinkingFormat};
use super::traits::*;
use crate::types::*;
use serde::Deserialize;
use tokio::sync::mpsc;
use tracing::warn;

/// Largest raw UTF-8 segment accepted by the native Gateway parser.
pub const MAX_OPENAI_GATEWAY_SEGMENT_BYTES: usize = 32 * 1024;
/// Largest individual SSE line/event-data and JSON frame accepted by the native parser.
pub const MAX_OPENAI_SSE_EVENT_BYTES: usize = 1024 * 1024;
/// Maximum bytes of generated text, reasoning, refusal, and tool arguments accumulated per response.
pub const MAX_OPENAI_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
/// Maximum number of indexed tool calls accepted in one response.
pub const MAX_OPENAI_TOOL_CALLS: usize = 128;
const MAX_OPENAI_DELTA_BYTES: usize = 64 * 1024;

/// Completion behavior for the transport-independent OpenAI stream parser.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenAiStreamPolicy {
    /// Gateway streams must be well-formed, bounded, and end with both a
    /// choice finish reason and the OpenAI `[DONE]` marker.
    GatewayStrict,
}

/// Result of feeding one UTF-8-safe raw SSE segment into the parser.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PushResult {
    Continue,
    Done,
}

/// A transport-independent Chat Completions stream parser.
///
/// The Gateway client feeds upstream SSE text through [`push_data`](Self::push_data),
/// which incrementally parses line and event boundaries. The existing HTTP
/// provider feeds already-decoded SSE event data through the same conversion
/// logic, keeping tool, reasoning, refusal, and usage handling in one place.
pub struct OpenAiStreamParser {
    model: String,
    provider: String,
    compat: OpenAiCompat,
    tx: mpsc::UnboundedSender<StreamEvent>,
    policy: OpenAiStreamPolicy,
    content: Vec<Content>,
    usage: Usage,
    stop_reason: StopReason,
    saw_finish_reason: bool,
    saw_done: bool,
    tool_call_buffers: Vec<ToolCallBuffer>,
    refusal: Option<String>,
    response_bytes: usize,
    line: String,
    event_data: String,
    event_has_data: bool,
    previous_was_cr: bool,
    finalized: bool,
}

impl OpenAiStreamParser {
    /// Create a parser from the same model configuration used by the HTTP
    /// provider. The provider API key is never copied or retained.
    pub fn new(
        config: &StreamConfig,
        tx: mpsc::UnboundedSender<StreamEvent>,
        policy: OpenAiStreamPolicy,
    ) -> Result<Self, ProviderError> {
        let model_config = config.model_config.as_ref().ok_or_else(|| {
            ProviderError::Other("ModelConfig required for OpenAI provider".into())
        })?;
        let parser = Self {
            model: config.model.clone(),
            provider: model_config.provider.clone(),
            compat: model_config.compat.as_ref().cloned().unwrap_or_default(),
            tx,
            policy,
            content: Vec::new(),
            usage: Usage::default(),
            stop_reason: StopReason::Stop,
            saw_finish_reason: false,
            saw_done: false,
            tool_call_buffers: Vec::new(),
            refusal: None,
            response_bytes: 0,
            line: String::new(),
            event_data: String::new(),
            event_has_data: false,
            previous_was_cr: false,
            finalized: false,
        };
        let _ = parser.tx.send(StreamEvent::Start);
        Ok(parser)
    }

    /// Feed an upstream raw SSE text segment. Segment boundaries may occur
    /// anywhere between Unicode code points, SSE lines, or events, but each
    /// input string must itself be valid UTF-8.
    pub fn push_data(&mut self, segment: &str) -> Result<PushResult, ProviderError> {
        if self.finalized {
            return Err(self.invalid_stream("stream data arrived after finalization"));
        }
        if segment.len() > MAX_OPENAI_GATEWAY_SEGMENT_BYTES {
            return Err(self.invalid_stream("Gateway SSE segment exceeds the parser limit"));
        }

        for ch in segment.chars() {
            if self.previous_was_cr {
                self.previous_was_cr = false;
                if ch == '\n' {
                    continue;
                }
            }
            match ch {
                '\r' => {
                    self.process_line()?;
                    self.previous_was_cr = true;
                }
                '\n' => self.process_line()?,
                _ => {
                    self.line.push(ch);
                    if self.line.len() > MAX_OPENAI_SSE_EVENT_BYTES {
                        return Err(self.invalid_stream("SSE line exceeds the parser limit"));
                    }
                }
            }
        }

        Ok(if self.saw_done {
            PushResult::Done
        } else {
            PushResult::Continue
        })
    }

    /// Finish the parsed stream and emit one `StreamEvent::Done`.
    ///
    /// In strict Gateway mode this succeeds only after a finish reason and an
    /// explicit `[DONE]` event were received. The caller must additionally
    /// validate the Gateway `response.end` terminal sequence before calling
    /// this method.
    pub fn finish(&mut self) -> Result<Message, ProviderError> {
        if self.finalized {
            return Err(self.invalid_stream("stream was already finalized"));
        }
        if self.policy == OpenAiStreamPolicy::GatewayStrict {
            if !self.line.is_empty() || self.event_has_data {
                return Err(self.invalid_stream("upstream ended inside an SSE event"));
            }
            if !self.saw_finish_reason {
                return Err(self.invalid_stream("upstream ended without a finish reason"));
            }
            if !self.saw_done {
                return Err(self.invalid_stream("upstream ended before the [DONE] marker"));
            }
        }

        self.finalized = true;
        for buf in &self.tool_call_buffers {
            let args = super::tool_args::parse_tool_arguments(&buf.arguments);
            self.content.push(Content::ToolCall {
                provider_metadata: None,
                id: buf.id.clone(),
                name: buf.name.clone(),
                arguments: args,
            });
            let _ = self.tx.send(StreamEvent::ToolCallEnd {
                content_index: self.content.len() - 1,
            });
        }

        // Tool calls make this a ToolUse turn unless length or refusal is the
        // more specific terminal reason.
        if self.refusal.is_some() {
            self.stop_reason = StopReason::Refusal;
        }
        if !self.tool_call_buffers.is_empty()
            && !matches!(self.stop_reason, StopReason::Length | StopReason::Refusal)
        {
            self.stop_reason = StopReason::ToolUse;
        }
        let error_message = match self.refusal.as_deref() {
            Some("") => Some("Request declined by the model (refusal)".to_string()),
            Some(text) => Some(format!("Request declined by the model (refusal): {text}")),
            None => (self.stop_reason == StopReason::Refusal).then(|| {
                "Response stopped by the content filter (finish_reason: content_filter)".to_string()
            }),
        };
        let message = Message::Assistant {
            content: std::mem::take(&mut self.content),
            stop_reason: self.stop_reason.clone(),
            model: self.model.clone(),
            provider: self.provider.clone(),
            usage: self.usage.clone(),
            timestamp: now_ms(),
            error_message,
        };
        let _ = self.tx.send(StreamEvent::Done {
            message: message.clone(),
        });
        Ok(message)
    }

    fn process_line(&mut self) -> Result<(), ProviderError> {
        let line = std::mem::take(&mut self.line);
        if line.is_empty() {
            if self.event_has_data {
                let data = std::mem::take(&mut self.event_data);
                self.event_has_data = false;
                self.process_event_data(&data)?;
            }
            return Ok(());
        }
        if line.starts_with(':') {
            return Ok(());
        }
        let (field, value) = line
            .split_once(':')
            .map_or((line.as_str(), ""), |(field, value)| (field, value));
        if field == "data" {
            if self.saw_done {
                return Err(self.invalid_stream("SSE data arrived after [DONE]"));
            }
            if self.event_has_data {
                self.event_data.push('\n');
            }
            let value = value.strip_prefix(' ').unwrap_or(value);
            self.event_data.push_str(value);
            self.event_has_data = true;
            if self.event_data.len() > MAX_OPENAI_SSE_EVENT_BYTES {
                return Err(self.invalid_stream("SSE event exceeds the parser limit"));
            }
        }
        Ok(())
    }

    fn process_event_data(&mut self, data: &str) -> Result<(), ProviderError> {
        if self.finalized {
            return Err(self.invalid_stream("stream data arrived after finalization"));
        }
        if self.saw_done {
            return Err(self.invalid_stream("SSE data arrived after [DONE]"));
        }
        if data == "[DONE]" {
            self.saw_done = true;
            return Ok(());
        }
        if data.len() > MAX_OPENAI_SSE_EVENT_BYTES {
            return Err(self.invalid_stream("OpenAI stream chunk exceeds the parser limit"));
        }

        let chunk: OpenAiChunk = serde_json::from_str(data)
            .map_err(|_| self.invalid_stream("invalid OpenAI-compatible stream chunk"))?;
        if chunk.error.is_some() {
            // Never include provider body/error text in the Gateway client
            // error or a log line; it can contain secrets and prompt echoes.
            return Err(self.invalid_stream("provider stream returned an error event"));
        }
        if chunk.choices.is_empty() && chunk.usage.is_none() {
            return Err(self.invalid_stream("OpenAI stream chunk has no choices or usage"));
        }
        if let Some(usage) = &chunk.usage {
            self.usage = usage_from_openai(usage);
        }
        if self.saw_finish_reason && !chunk.choices.is_empty() {
            return Err(self.invalid_stream("OpenAI choices arrived after the finish reason"));
        }

        for choice in &chunk.choices {
            let delta = &choice.delta;
            let reasoning = match self.compat.thinking_format {
                ThinkingFormat::Xai => delta.reasoning.as_deref(),
                _ => delta.reasoning_content.as_deref(),
            };
            if let Some(reasoning_text) = reasoning {
                self.record_output(reasoning_text)?;
                let idx = match self
                    .content
                    .iter()
                    .position(|c| matches!(c, Content::Thinking { .. }))
                {
                    Some(index) => index,
                    None => {
                        self.content.push(Content::thinking(String::new()));
                        self.content.len() - 1
                    }
                };
                if let Some(Content::Thinking { thinking, .. }) = self.content.get_mut(idx) {
                    thinking.push_str(reasoning_text);
                }
                let _ = self.tx.send(StreamEvent::ThinkingDelta {
                    content_index: idx,
                    delta: reasoning_text.to_string(),
                });
            }

            if let Some(refusal) = &delta.refusal {
                self.refusal
                    .get_or_insert_with(String::new)
                    .push_str(refusal);
            }
            for text in [&delta.content, &delta.refusal].into_iter().flatten() {
                self.record_output(text)?;
                let idx = match self
                    .content
                    .iter()
                    .position(|c| matches!(c, Content::Text { .. }))
                {
                    Some(index) => index,
                    None => {
                        self.content.push(Content::Text {
                            text: String::new(),
                        });
                        self.content.len() - 1
                    }
                };
                if let Some(Content::Text { text: accumulated }) = self.content.get_mut(idx) {
                    accumulated.push_str(text);
                }
                let _ = self.tx.send(StreamEvent::TextDelta {
                    content_index: idx,
                    delta: text.clone(),
                });
            }

            if let Some(tool_calls) = &delta.tool_calls {
                for tool_call in tool_calls {
                    let index = tool_call.index as usize;
                    if self.policy == OpenAiStreamPolicy::GatewayStrict
                        && index >= MAX_OPENAI_TOOL_CALLS
                    {
                        return Err(self.invalid_stream("tool call index exceeds the parser limit"));
                    }
                    if let Some(id) = &tool_call.id {
                        if self.policy == OpenAiStreamPolicy::GatewayStrict
                            && id.len() > MAX_OPENAI_DELTA_BYTES
                        {
                            return Err(
                                self.invalid_stream("tool call id exceeds the parser limit")
                            );
                        }
                        self.record_output(id)?;
                    }
                    if let Some(function) = &tool_call.function {
                        if let Some(name) = &function.name {
                            if self.policy == OpenAiStreamPolicy::GatewayStrict
                                && name.len() > MAX_OPENAI_DELTA_BYTES
                            {
                                return Err(
                                    self.invalid_stream("tool name exceeds the parser limit")
                                );
                            }
                            self.record_output(name)?;
                        }
                        if let Some(arguments) = &function.arguments {
                            self.record_output(arguments)?;
                        }
                    }
                    while self.tool_call_buffers.len() <= index {
                        self.tool_call_buffers.push(ToolCallBuffer::default());
                    }
                    let buffer = &mut self.tool_call_buffers[index];
                    if let Some(id) = &tool_call.id {
                        buffer.id.clone_from(id);
                    }
                    if let Some(function) = &tool_call.function {
                        if let Some(name) = &function.name {
                            buffer.name.clone_from(name);
                            let _ = self.tx.send(StreamEvent::ToolCallStart {
                                content_index: self.content.len() + index,
                                id: buffer.id.clone(),
                                name: name.clone(),
                            });
                        }
                        if let Some(arguments) = &function.arguments {
                            buffer.arguments.push_str(arguments);
                            let _ = self.tx.send(StreamEvent::ToolCallDelta {
                                content_index: self.content.len() + index,
                                delta: arguments.clone(),
                            });
                        }
                    }
                }
            }

            if let Some(reason) = &choice.finish_reason {
                self.saw_finish_reason = true;
                self.stop_reason = match reason.as_str() {
                    "stop" => StopReason::Stop,
                    "length" => StopReason::Length,
                    "tool_calls" => StopReason::ToolUse,
                    "content_filter" => StopReason::Refusal,
                    "error" => {
                        return Err(self.invalid_stream("provider stream ended with an error"));
                    }
                    _ => return Err(self.invalid_stream("unsupported OpenAI finish reason")),
                };
            }
        }
        Ok(())
    }

    fn record_output(&mut self, value: &str) -> Result<(), ProviderError> {
        if self.policy != OpenAiStreamPolicy::GatewayStrict {
            return Ok(());
        }
        if value.len() > MAX_OPENAI_DELTA_BYTES {
            return Err(self.invalid_stream("OpenAI delta exceeds the parser limit"));
        }
        let Some(next_size) = self
            .response_bytes
            .checked_add(value.len())
            .filter(|size| *size <= MAX_OPENAI_RESPONSE_BYTES)
        else {
            return Err(self.invalid_stream("OpenAI response exceeds the parser limit"));
        };
        self.response_bytes = next_size;
        Ok(())
    }

    fn invalid_stream(&self, safe_message: &str) -> ProviderError {
        ProviderError::Other(safe_message.to_string())
    }
}

/// Build the existing OpenAI-compatible Chat Completions payload for the
/// native Gateway transport. The Gateway injects the authorized upstream
/// model and `stream` flag after identity authorization, so those fields are
/// removed here. All messages, tools, cache hints, and model-specific request
/// conversions are otherwise identical to the HTTP provider.
pub fn build_chat_payload(config: &StreamConfig) -> Result<serde_json::Value, ProviderError> {
    let model_config = config
        .model_config
        .as_ref()
        .ok_or_else(|| ProviderError::Other("ModelConfig required for OpenAI provider".into()))?;
    let compat = model_config.compat.as_ref().cloned().unwrap_or_default();
    let mut payload = build_request_body(config, model_config, &compat);
    if let Some(object) = payload.as_object_mut() {
        object.remove("model");
        object.remove("stream");
    }
    Ok(payload)
}

#[derive(Default)]
struct ToolCallBuffer {
    id: String,
    name: String,
    arguments: String,
}

fn tool_result_text(content: &[Content]) -> String {
    content
        .iter()
        .filter_map(|item| match item {
            Content::Text { text } => Some(text.as_str()),
            Content::Thinking { thinking, .. } => Some(thinking.as_str()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn build_request_body(
    config: &StreamConfig,
    model_config: &ModelConfig,
    compat: &OpenAiCompat,
) -> serde_json::Value {
    let mut messages: Vec<serde_json::Value> = Vec::new();

    // System prompt
    if !config.system_prompt.is_empty() {
        let role = if compat.supports_developer_role {
            "developer"
        } else {
            "system"
        };
        messages.push(serde_json::json!({
            "role": role,
            "content": config.system_prompt,
        }));
    }

    // DeepSeek thinking mode with tools: every earlier assistant turn's
    // reasoning must go back as `reasoning_content`, or the request is a 400.
    // Without tools DeepSeek ignores it, so it is only sent when it matters.
    let replay_reasoning = compat.replays_reasoning_content && !config.tools.is_empty();

    for msg in &config.messages {
        if !matches!(msg, Message::ToolResult { .. } | Message::Assistant { .. }) {
            maybe_insert_assistant_after_tool_results(&mut messages, compat);
        }

        match msg {
            Message::User { content, .. } => {
                messages.push(serde_json::json!({
                    "role": "user",
                    "content": content_to_openai(content),
                }));
            }
            Message::Assistant { content, .. } => {
                let mut parts: Vec<serde_json::Value> = Vec::new();
                let mut tool_calls: Vec<serde_json::Value> = Vec::new();
                let mut reasoning = String::new();

                for c in content {
                    match c {
                        Content::Thinking { thinking, .. } if replay_reasoning => {
                            reasoning.push_str(thinking);
                        }
                        Content::Text { text } if text.is_empty() => {}
                        Content::Text { text } => {
                            parts.push(serde_json::json!({"type": "text", "text": text}));
                        }
                        Content::ToolCall {
                            id,
                            name,
                            arguments,
                            ..
                        } => {
                            tool_calls.push(serde_json::json!({
                                "id": id,
                                "type": "function",
                                "function": {"name": name, "arguments": arguments.to_string()},
                            }));
                        }
                        _ => {}
                    }
                }

                let mut msg_obj = serde_json::json!({"role": "assistant"});
                if !parts.is_empty() {
                    msg_obj["content"] = serde_json::json!(parts);
                }
                if !reasoning.is_empty() {
                    msg_obj["reasoning_content"] = serde_json::json!(reasoning);
                }
                if !tool_calls.is_empty() {
                    msg_obj["tool_calls"] = serde_json::json!(tool_calls);
                }
                messages.push(msg_obj);
            }
            Message::ToolResult {
                tool_call_id,
                tool_name,
                content,
                ..
            } => {
                let content_val = if content.iter().any(|c| matches!(c, Content::Image { .. })) {
                    // Images present: use array format for multimodal tool results
                    content_to_openai(content)
                } else {
                    // Text-only: every text block in one plain string, for maximum compat
                    let text = tool_result_text(content);
                    serde_json::json!(text)
                };

                let mut msg_obj = serde_json::json!({
                    "role": "tool",
                    "tool_call_id": tool_call_id,
                    "content": content_val,
                });
                if compat.requires_tool_result_name {
                    msg_obj["name"] = serde_json::json!(tool_name);
                }
                messages.push(msg_obj);
            }
        }
    }
    maybe_insert_assistant_after_tool_results(&mut messages, compat);

    let max_tokens_val = config.max_tokens.unwrap_or(model_config.max_tokens);
    let mut body = serde_json::json!({
        "model": config.model,
        "stream": true,
        "stream_options": {"include_usage": true},
        "messages": messages,
    });

    match compat.max_tokens_field {
        MaxTokensField::MaxCompletionTokens => {
            body["max_completion_tokens"] = serde_json::json!(max_tokens_val);
        }
        MaxTokensField::MaxTokens => {
            body["max_tokens"] = serde_json::json!(max_tokens_val);
        }
    }

    if compat.supports_thinking_control {
        let thinking_type = if config.thinking_level == ThinkingLevel::Off {
            "disabled"
        } else {
            "enabled"
        };
        body["thinking"] = serde_json::json!({ "type": thinking_type });
    }

    if !config.tools.is_empty() {
        let tools: Vec<serde_json::Value> = config
            .tools
            .iter()
            .map(|t| {
                serde_json::json!({
                    "type": "function",
                    "function": {
                        "name": t.name,
                        "description": t.description,
                        "parameters": t.parameters,
                    }
                })
            })
            .collect();
        body["tools"] = serde_json::json!(tools);
    }

    // Prompt caching. OpenAI caches prefixes automatically once they exceed
    // ~1024 tokens, so there are no breakpoints to place — `prompt_cache_key`
    // only routes requests from one conversation toward the same cache. Gated
    // on the compat flag because the field is OpenAI's: a strict compat server
    // that validates unknown keys would reject the request outright, and the
    // providers that cache automatically were never reading it anyway.
    if compat.supports_prompt_cache_key {
        if let Some(key) = config.cache_session_key() {
            body["prompt_cache_key"] = serde_json::json!(key);
        }
    } else if config.cache_config.session_key.is_some() && config.cache_config.hints_enabled() {
        // A *derived* key going unsent is a missed optimization and stays
        // quiet. An *explicitly configured* one going unsent is a user
        // instruction being discarded — someone isolating tenants gets exactly
        // the sharing they were preventing. Matches the convention stated on
        // `StreamConfig::output_schema` and honoured by five providers.
        warn!(
            "CacheConfig::session_key is set, but provider '{}' does not accept \
             prompt_cache_key; the key is ignored and requests will not be routed \
             by session",
            model_config.provider
        );
    }

    // Structured outputs: native json_schema response format.
    if let Some(schema) = &config.output_schema {
        body["response_format"] = serde_json::json!({
            "type": "json_schema",
            "json_schema": {
                "name": schema.name,
                "schema": schema.schema,
                "strict": true,
            },
        });
    }

    if compat.supports_reasoning_effort {
        let effort = if compat.supports_thinking_control {
            // DeepSeek: `Off` is already `thinking: disabled` above.
            (config.thinking_level != ThinkingLevel::Off)
                .then(|| deepseek_reasoning_effort(config.thinking_level))
        } else {
            compat.openai_reasoning_effort(&config.model, config.thinking_level)
        };
        if let Some(effort) = effort {
            body["reasoning_effort"] = serde_json::json!(effort);
        }
    }

    if let Some(temp) = config.temperature {
        body["temperature"] = serde_json::json!(temp);
    }

    body
}

/// `reasoning_effort` on the DeepSeek ladder, for a thinking-enabled request.
///
/// DeepSeek-style providers ([`OpenAiCompat::supports_thinking_control`])
/// take `low`/`high`/`max`
/// (<https://api-docs.deepseek.com/guides/thinking_mode>; `Off` is expressed
/// as `thinking: disabled`, not as an effort value). `XHigh` is sent as
/// `high`, matching DeepSeek's own documented mapping of a requested `xhigh`,
/// so it never silently selects the most expensive rung; only `Max` sends
/// `max`. [`OpenAiCompat::max_reasoning_effort`] is not consulted here.
///
/// Every other provider goes through
/// [`OpenAiCompat::openai_reasoning_effort`], which caps `XHigh`/`Max` at the
/// declared [`OpenAiCompat::max_reasoning_effort`] (default `high`, since most
/// providers reject an unknown string rather than rounding it).
fn deepseek_reasoning_effort(level: ThinkingLevel) -> &'static str {
    match level {
        ThinkingLevel::Minimal | ThinkingLevel::Low => "low",
        ThinkingLevel::Medium => "medium",
        ThinkingLevel::High | ThinkingLevel::XHigh => "high",
        ThinkingLevel::Max => "max",
        ThinkingLevel::Off => unreachable!(),
    }
}

fn maybe_insert_assistant_after_tool_results(
    messages: &mut Vec<serde_json::Value>,
    compat: &OpenAiCompat,
) {
    if !compat.requires_assistant_after_tool_result {
        return;
    }

    let last_is_tool = messages
        .last()
        .and_then(|m| m.get("role"))
        .and_then(|role| role.as_str())
        == Some("tool");
    if last_is_tool {
        messages.push(serde_json::json!({
            "role": "assistant",
            "content": "",
        }));
    }
}

fn content_to_openai(content: &[Content]) -> serde_json::Value {
    if content.len() == 1 {
        if let Content::Text { text } = &content[0] {
            if !text.is_empty() {
                return serde_json::json!(text);
            }
        }
    }
    let parts: Vec<serde_json::Value> = content
        .iter()
        .filter(|c| !matches!(c, Content::Text { text } if text.is_empty()))
        .filter_map(|c| match c {
            Content::Text { text } => Some(serde_json::json!({"type": "text", "text": text})),
            Content::Image { data, mime_type } => Some(serde_json::json!({
                "type": "image_url",
                "image_url": {"url": format!("data:{};base64,{}", mime_type, data)},
            })),
            _ => None,
        })
        .collect();
    serde_json::json!(parts)
}

// OpenAI streaming response types
#[derive(Deserialize)]
struct OpenAiChunk {
    /// A mid-stream failure (OpenRouter and other gateways send
    /// `{"error":{…}}`, sometimes alongside `finish_reason: "error"`).
    #[serde(default)]
    error: Option<serde_json::Value>,
    #[serde(default)]
    choices: Vec<OpenAiChoice>,
    #[serde(default)]
    usage: Option<OpenAiUsage>,
}

#[derive(Deserialize)]
struct OpenAiChoice {
    delta: OpenAiDelta,
    #[serde(default)]
    finish_reason: Option<String>,
}

#[derive(Deserialize, Default)]
struct OpenAiDelta {
    #[serde(default)]
    content: Option<String>,
    #[serde(default)]
    reasoning_content: Option<String>,
    #[serde(default)]
    reasoning: Option<String>,
    /// A model refusal, streamed in place of `content` (openai-python
    /// `ChoiceDelta.refusal`), followed by `finish_reason: "stop"`.
    #[serde(default)]
    refusal: Option<String>,
    #[serde(default)]
    tool_calls: Option<Vec<OpenAiToolCallDelta>>,
}

#[derive(Deserialize)]
struct OpenAiToolCallDelta {
    #[serde(default)]
    index: u32,
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    function: Option<OpenAiFunctionDelta>,
}

#[derive(Deserialize)]
struct OpenAiFunctionDelta {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    arguments: Option<String>,
}

/// A token count that some servers send as explicit `null`.
///
/// `#[serde(default)]` covers only a *missing* key; `null` in a `u64` field
/// fails the whole payload — on Chat Completions the chunk carrying the usage
/// (often with the `finish_reason`), on Responses the terminal event.
///
/// Read as 0, which undercounts: the turn's cost comes out too low. So the
/// first `null` in the process is logged at `warn` (once, not per chunk — a
/// server that does this does it on every response).
pub(crate) fn null_as_zero<'de, D: serde::Deserializer<'de>>(d: D) -> Result<u64, D::Error> {
    match Option::<u64>::deserialize(d)? {
        Some(n) => Ok(n),
        None => {
            warn_null_usage_count();
            Ok(0)
        }
    }
}

/// Whether [`null_as_zero`] has read a `null`, so tests can observe the
/// warning path without a process-global subscriber.
static NULL_USAGE_SEEN: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

fn warn_null_usage_count() {
    if !NULL_USAGE_SEEN.swap(true, std::sync::atomic::Ordering::Relaxed) {
        warn!(
            "a usage token count arrived as null and was read as 0; token counts and cost \
             for such responses are undercounted. Logged once per process."
        );
    }
}

#[derive(Deserialize)]
struct OpenAiUsage {
    #[serde(default, deserialize_with = "null_as_zero")]
    prompt_tokens: u64,
    #[serde(default, deserialize_with = "null_as_zero")]
    completion_tokens: u64,
    #[serde(default, deserialize_with = "null_as_zero")]
    total_tokens: u64,
    #[serde(default)]
    prompt_tokens_details: Option<OpenAiPromptTokensDetails>,
    #[serde(default)]
    completion_tokens_details: Option<OpenAiCompletionTokensDetails>,
    #[serde(default)]
    prompt_cache_hit_tokens: Option<u64>,
    #[serde(default)]
    prompt_cache_miss_tokens: Option<u64>,
}

#[derive(Deserialize)]
struct OpenAiPromptTokensDetails {
    #[serde(default, deserialize_with = "null_as_zero")]
    cached_tokens: u64,
    /// Prompt tokens written to the cache on this request (openai-python
    /// `PromptTokensDetails.cache_write_tokens`). Billed at a premium on
    /// GPT-5.6 and later.
    #[serde(default, deserialize_with = "null_as_zero")]
    cache_write_tokens: u64,
}

#[derive(Deserialize)]
struct OpenAiCompletionTokensDetails {
    #[serde(default, deserialize_with = "null_as_zero")]
    reasoning_tokens: u64,
}

/// Maps a streamed usage chunk onto [`Usage`].
///
/// `prompt_tokens` includes both cached and cache-written tokens — OpenAI's
/// prompt-caching guide computes ordinary input as
/// `input_tokens - cached_tokens - cache_write_tokens`
/// (<https://developers.openai.com/api/docs/guides/prompt-caching>) — so `input`
/// excludes both, matching how the other providers split `Usage`. DeepSeek
/// reports the split directly as `prompt_cache_hit_tokens` /
/// `prompt_cache_miss_tokens`, which take precedence.
///
/// Reasoning tokens bill as output. OpenAI counts them inside
/// `completion_tokens` (`completion_tokens_details.reasoning_tokens` is a
/// breakdown); a provider may instead report them beside it, so that
/// `total_tokens = prompt_tokens + completion_tokens + reasoning_tokens`. They
/// are added to `output` only when `total_tokens` shows exactly that, so a
/// provider that includes them is never double-counted.
fn usage_from_openai(u: &OpenAiUsage) -> Usage {
    let details = u.prompt_tokens_details.as_ref();
    let cache_read = u
        .prompt_cache_hit_tokens
        .or_else(|| details.map(|d| d.cached_tokens))
        .unwrap_or(0);
    let cache_write = details.map(|d| d.cache_write_tokens).unwrap_or(0);
    Usage {
        input: u.prompt_cache_miss_tokens.unwrap_or_else(|| {
            u.prompt_tokens
                .saturating_sub(cache_read)
                .saturating_sub(cache_write)
        }),
        output: u.completion_tokens + reasoning_outside_completion(u),
        cache_read,
        cache_write,
        total_tokens: u.total_tokens,
    }
}

/// Reasoning tokens reported beside `completion_tokens` rather than inside it
/// (see [`usage_from_openai`]); 0 when they are inside, or not reported.
fn reasoning_outside_completion(u: &OpenAiUsage) -> u64 {
    let reasoning = u
        .completion_tokens_details
        .as_ref()
        .map_or(0, |d| d.reasoning_tokens);
    if reasoning > 0 && u.total_tokens == u.prompt_tokens + u.completion_tokens + reasoning {
        reasoning
    } else {
        0
    }
}

#[cfg(test)]
mod gateway_parser_tests {
    use super::*;

    fn config() -> StreamConfig {
        let model_config = ModelConfig::openai("gpt-4o", "GPT-4o");
        let mut config = StreamConfig::new("gpt-4o", "must-not-be-forwarded");
        config.system_prompt = "Be helpful".into();
        config.messages = vec![Message::user("hello")];
        config.model_config = Some(model_config);
        config
    }

    fn push_chars(
        parser: &mut OpenAiStreamParser,
        input: &str,
    ) -> Result<PushResult, ProviderError> {
        let mut last = PushResult::Continue;
        for ch in input.chars() {
            let mut encoded = [0; 4];
            last = parser.push_data(ch.encode_utf8(&mut encoded))?;
        }
        Ok(last)
    }

    #[test]
    fn gateway_payload_reuses_http_conversion_but_omits_gateway_owned_fields() {
        let mut config = config();
        config.tools.push(ToolDefinition {
            name: "search".into(),
            description: "Search the web".into(),
            parameters: serde_json::json!({"type":"object"}),
        });

        let payload = build_chat_payload(&config).expect("payload");
        assert!(payload.get("model").is_none());
        assert!(payload.get("stream").is_none());
        assert_eq!(payload["messages"][0]["role"], "developer");
        assert_eq!(payload["messages"][1]["content"], "hello");
        assert_eq!(payload["tools"][0]["function"]["name"], "search");
        assert!(payload.to_string().find("must-not-be-forwarded").is_none());
    }

    #[test]
    fn gateway_parser_handles_fragmented_sse_unicode_tools_usage_and_done() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let mut parser =
            OpenAiStreamParser::new(&config(), tx, OpenAiStreamPolicy::GatewayStrict).unwrap();
        let wire = concat!(
            "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"Hello 🌍\"}}]}\r\n\r\n",
            "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"call_1\",\"function\":{\"name\":\"search\",\"arguments\":\"{\\\"q\\\":\"}}]}}]}\n\n",
            "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"\\\"rust\\\"}\"}}]},\"finish_reason\":\"tool_calls\"}]}\n\n",
            "data: {\"choices\":[],\"usage\":{\"prompt_tokens\":2,\"completion_tokens\":3,\"total_tokens\":5}}\n\n",
            "data: [DONE]\n\n",
        );

        for result in wire.chars().map(|ch| {
            let mut encoded = [0; 4];
            ch.encode_utf8(&mut encoded).to_owned()
        }) {
            parser.push_data(&result).expect("fragment should parse");
        }
        let Message::Assistant { usage, .. } = parser.finish().expect("finished message") else {
            panic!("parser must return assistant message");
        };
        assert_eq!(usage.output, 3);
        let mut events = Vec::new();
        while let Ok(event) = rx.try_recv() {
            events.push(event);
        }
        assert!(matches!(events.first(), Some(StreamEvent::Start)));
        assert!(events.iter().any(|event| matches!(
            event,
            StreamEvent::TextDelta { delta, .. } if delta == "Hello 🌍"
        )));
        assert!(events.iter().any(|event| matches!(
            event,
            StreamEvent::ToolCallDelta { delta, .. } if delta == "{\"q\":" || delta == "\"rust\"}"
        )));
        assert_eq!(
            events
                .iter()
                .filter(|event| matches!(event, StreamEvent::Done { .. }))
                .count(),
            1
        );
    }

    #[test]
    fn gateway_parser_rejects_invalid_json_without_echoing_provider_data() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let mut parser =
            OpenAiStreamParser::new(&config(), tx, OpenAiStreamPolicy::GatewayStrict).unwrap();
        let err = parser
            .push_data("data: {\"secret-provider-text\":\"sensitive\"\n\n")
            .unwrap_err();
        assert!(!err.to_string().contains("sensitive"));
        assert!(!err.to_string().contains("secret-provider-text"));

        let (tx, _rx) = mpsc::unbounded_channel();
        let mut parser =
            OpenAiStreamParser::new(&config(), tx, OpenAiStreamPolicy::GatewayStrict).unwrap();
        let err = push_chars(
            &mut parser,
            "data: {\"error\":{\"message\":\"private provider details\"}}\n\n",
        )
        .unwrap_err();
        assert!(!err.to_string().contains("private provider details"));
    }

    #[test]
    fn gateway_parser_requires_finish_reason_and_done() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let mut no_finish =
            OpenAiStreamParser::new(&config(), tx, OpenAiStreamPolicy::GatewayStrict).unwrap();
        assert_eq!(
            push_chars(&mut no_finish, "data: [DONE]\n\n").unwrap(),
            PushResult::Done
        );
        assert!(no_finish.finish().is_err());

        let (tx, _rx) = mpsc::unbounded_channel();
        let mut no_done =
            OpenAiStreamParser::new(&config(), tx, OpenAiStreamPolicy::GatewayStrict).unwrap();
        push_chars(
            &mut no_done,
            "data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n",
        )
        .unwrap();
        assert!(no_done.finish().is_err());
    }

    #[test]
    fn gateway_parser_bounds_tool_indexes_and_delta_sizes() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let mut parser =
            OpenAiStreamParser::new(&config(), tx, OpenAiStreamPolicy::GatewayStrict).unwrap();
        let tool_index_frame = format!(
            "data: {{\"choices\":[{{\"delta\":{{\"tool_calls\":[{{\"index\":{MAX_OPENAI_TOOL_CALLS},\"function\":{{\"arguments\":\"{{}}\"}}}}]}}}}]}}\n\n"
        );
        assert!(push_chars(&mut parser, &tool_index_frame).is_err());

        let (tx, _rx) = mpsc::unbounded_channel();
        let mut parser =
            OpenAiStreamParser::new(&config(), tx, OpenAiStreamPolicy::GatewayStrict).unwrap();
        let oversized = "x".repeat(MAX_OPENAI_DELTA_BYTES + 1);
        let frame = format!(
            "data: {{\"choices\":[{{\"delta\":{{\"content\":{}}}}}]}}\n\n",
            serde_json::to_string(&oversized).unwrap()
        );
        for segment in frame.as_bytes().chunks(MAX_OPENAI_GATEWAY_SEGMENT_BYTES) {
            let segment = std::str::from_utf8(segment).expect("ASCII only");
            if let Err(error) = parser.push_data(segment) {
                assert!(error.to_string().contains("parser limit"));
                return;
            }
        }
        panic!("oversized delta should be rejected");
    }

    #[test]
    fn gateway_parser_bounds_total_accumulated_response() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let mut parser =
            OpenAiStreamParser::new(&config(), tx, OpenAiStreamPolicy::GatewayStrict).unwrap();
        // Exercise the aggregate limit without allocating a 16 MiB fixture.
        parser.response_bytes = MAX_OPENAI_RESPONSE_BYTES;
        let err = push_chars(
            &mut parser,
            "data: {\"choices\":[{\"delta\":{\"content\":\"x\"}}]}\n\n",
        )
        .unwrap_err();
        assert!(err
            .to_string()
            .contains("response exceeds the parser limit"));
    }
}
