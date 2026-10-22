//! Model settings and OpenAI-compatible request quirks.
//!
//! This retained runtime intentionally has no provider preset catalog. The
//! application supplies one authorized model alias and the direct Gateway
//! transport. `CostConfig` remains available for hosts that attach their own
//! accounting rates.

use crate::types::ThinkingLevel;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Protocol metadata carried with a model. This runtime currently dispatches
/// only OpenAI-compatible Chat Completions over the Gateway.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ApiProtocol {
    AnthropicMessages,
    OpenAiCompletions,
    OpenAiResponses,
    AzureOpenAiResponses,
    GoogleGenerativeAi,
    GoogleVertex,
    BedrockConverseStream,
}

impl std::fmt::Display for ApiProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Self::AnthropicMessages => "anthropic_messages",
            Self::OpenAiCompletions => "openai_completions",
            Self::OpenAiResponses => "openai_responses",
            Self::AzureOpenAiResponses => "azure_openai_responses",
            Self::GoogleGenerativeAi => "google_generative_ai",
            Self::GoogleVertex => "google_vertex",
            Self::BedrockConverseStream => "bedrock_converse_stream",
        };
        f.write_str(name)
    }
}

/// Caller-supplied per-million-token rates used by session accounting.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[non_exhaustive]
pub struct CostConfig {
    pub input_per_million: f64,
    pub output_per_million: f64,
    #[serde(default)]
    pub cache_read_per_million: f64,
    #[serde(default)]
    pub cache_write_per_million: f64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub context_tiers: Vec<ContextTier>,
}

/// Optional price band selected above a prompt-size threshold.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ContextTier {
    pub above_prompt_tokens: u64,
    pub input_per_million: f64,
    pub output_per_million: f64,
    #[serde(default)]
    pub cache_read_per_million: f64,
    #[serde(default)]
    pub cache_write_per_million: f64,
}

impl ContextTier {
    pub fn new(above_prompt_tokens: u64, input_per_million: f64, output_per_million: f64) -> Self {
        Self {
            above_prompt_tokens,
            input_per_million,
            output_per_million,
            cache_read_per_million: 0.0,
            cache_write_per_million: 0.0,
        }
    }

    pub fn with_cache_read(mut self, per_million: f64) -> Self {
        self.cache_read_per_million = per_million;
        self
    }

    pub fn with_cache_write(mut self, per_million: f64) -> Self {
        self.cache_write_per_million = per_million;
        self
    }

    pub fn is_configured(&self) -> bool {
        self.input_per_million != 0.0
            || self.output_per_million != 0.0
            || self.cache_read_per_million != 0.0
            || self.cache_write_per_million != 0.0
    }
}

impl CostConfig {
    pub fn new(input_per_million: f64, output_per_million: f64) -> Self {
        Self {
            input_per_million,
            output_per_million,
            ..Self::default()
        }
    }

    pub fn with_cache_read(mut self, per_million: f64) -> Self {
        self.cache_read_per_million = per_million;
        self
    }

    pub fn with_cache_write(mut self, per_million: f64) -> Self {
        self.cache_write_per_million = per_million;
        self
    }

    pub fn with_context_tier(mut self, tier: ContextTier) -> Self {
        self.context_tiers.push(tier);
        self.context_tiers.sort_by_key(|t| t.above_prompt_tokens);
        self
    }

    pub fn is_configured(&self) -> bool {
        self.input_per_million != 0.0
            || self.output_per_million != 0.0
            || self.cache_read_per_million != 0.0
            || self.cache_write_per_million != 0.0
            || self.context_tiers.iter().any(ContextTier::is_configured)
    }

    pub fn cost_usd(&self, usage: &crate::types::Usage) -> f64 {
        let prompt_tokens = usage.input + usage.cache_read + usage.cache_write;
        let tier = self
            .context_tiers
            .iter()
            .rfind(|tier| prompt_tokens > tier.above_prompt_tokens);
        let (input, output, cache_read, cache_write) = tier.map_or(
            (
                self.input_per_million,
                self.output_per_million,
                self.cache_read_per_million,
                self.cache_write_per_million,
            ),
            |tier| {
                (
                    tier.input_per_million,
                    tier.output_per_million,
                    tier.cache_read_per_million,
                    tier.cache_write_per_million,
                )
            },
        );
        let cache_read = if cache_read == 0.0 { input } else { cache_read };
        let cache_write = if cache_write == 0.0 {
            input
        } else {
            cache_write
        };
        (usage.input as f64 * input
            + usage.output as f64 * output
            + usage.cache_read as f64 * cache_read
            + usage.cache_write as f64 * cache_write)
            / 1_000_000.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum MaxTokensField {
    #[default]
    MaxTokens,
    MaxCompletionTokens,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ThinkingFormat {
    #[default]
    OpenAi,
    Xai,
    Qwen,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize,
)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum ReasoningEffortCeiling {
    #[default]
    High,
    XHigh,
    Max,
}

/// Compatibility toggles for the OpenAI Chat Completions request converter.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
#[non_exhaustive]
pub struct OpenAiCompat {
    pub supports_store: bool,
    pub supports_developer_role: bool,
    pub supports_reasoning_effort: bool,
    pub supports_thinking_control: bool,
    pub supports_usage_in_streaming: bool,
    pub max_tokens_field: MaxTokensField,
    pub requires_tool_result_name: bool,
    pub requires_assistant_after_tool_result: bool,
    pub thinking_format: ThinkingFormat,
    pub supports_prompt_cache_key: bool,
    pub replays_reasoning_content: bool,
    pub encrypted_reasoning: bool,
    pub max_reasoning_effort: ReasoningEffortCeiling,
}

impl Default for OpenAiCompat {
    fn default() -> Self {
        Self {
            supports_store: false,
            supports_developer_role: false,
            supports_reasoning_effort: false,
            supports_thinking_control: false,
            supports_usage_in_streaming: true,
            max_tokens_field: MaxTokensField::MaxTokens,
            requires_tool_result_name: false,
            requires_assistant_after_tool_result: false,
            thinking_format: ThinkingFormat::OpenAi,
            supports_prompt_cache_key: false,
            replays_reasoning_content: false,
            encrypted_reasoning: false,
            max_reasoning_effort: ReasoningEffortCeiling::High,
        }
    }
}

impl OpenAiCompat {
    pub fn openai() -> Self {
        Self {
            supports_store: true,
            supports_developer_role: true,
            supports_reasoning_effort: true,
            max_tokens_field: MaxTokensField::MaxCompletionTokens,
            supports_prompt_cache_key: true,
            ..Self::default()
        }
    }

    pub fn meta() -> Self {
        Self {
            supports_reasoning_effort: true,
            max_tokens_field: MaxTokensField::MaxCompletionTokens,
            ..Self::default()
        }
    }

    pub fn xai() -> Self {
        Self {
            supports_reasoning_effort: true,
            thinking_format: ThinkingFormat::Xai,
            max_reasoning_effort: ReasoningEffortCeiling::XHigh,
            ..Self::default()
        }
    }

    pub fn groq() -> Self {
        Self::default()
    }
    pub fn cerebras() -> Self {
        Self::default()
    }
    pub fn openrouter() -> Self {
        Self::default()
    }
    pub fn mistral() -> Self {
        Self::default()
    }

    pub fn deepseek() -> Self {
        Self {
            supports_reasoning_effort: true,
            supports_thinking_control: true,
            max_tokens_field: MaxTokensField::MaxTokens,
            replays_reasoning_content: true,
            ..Self::default()
        }
    }

    pub fn zai() -> Self {
        Self::default()
    }
    pub fn minimax() -> Self {
        Self::default()
    }

    pub fn qwen() -> Self {
        Self {
            thinking_format: ThinkingFormat::Qwen,
            ..Self::default()
        }
    }

    pub fn ollama() -> Self {
        Self {
            requires_assistant_after_tool_result: true,
            ..Self::default()
        }
    }

    pub(crate) fn openai_reasoning_effort(
        &self,
        _model: &str,
        level: ThinkingLevel,
    ) -> Option<&'static str> {
        use ReasoningEffortCeiling as Ceiling;
        match level {
            ThinkingLevel::Off => None,
            ThinkingLevel::Minimal | ThinkingLevel::Low => Some("low"),
            ThinkingLevel::Medium => Some("medium"),
            ThinkingLevel::High => Some("high"),
            ThinkingLevel::XHigh if self.max_reasoning_effort >= Ceiling::XHigh => Some("xhigh"),
            ThinkingLevel::XHigh => Some("high"),
            ThinkingLevel::Max => Some(match self.max_reasoning_effort {
                Ceiling::Max => "max",
                Ceiling::XHigh => "xhigh",
                Ceiling::High => "high",
            }),
        }
    }
}

/// Model metadata consumed by the retained loop and Chat Completions converter.
#[derive(Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ModelConfig {
    pub id: String,
    pub name: String,
    pub api: ApiProtocol,
    pub provider: String,
    pub base_url: String,
    pub reasoning: bool,
    pub context_window: u32,
    pub max_tokens: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cost: Option<CostConfig>,
    #[serde(default)]
    pub headers: HashMap<String, String>,
    #[serde(default)]
    pub compat: Option<OpenAiCompat>,
}

impl std::fmt::Debug for ModelConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let header_names: Vec<_> = self.headers.keys().collect();
        f.debug_struct("ModelConfig")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("api", &self.api)
            .field("provider", &self.provider)
            .field("base_url", &self.base_url)
            .field("reasoning", &self.reasoning)
            .field("context_window", &self.context_window)
            .field("max_tokens", &self.max_tokens)
            .field("header_names", &header_names)
            .finish_non_exhaustive()
    }
}

impl ModelConfig {
    pub fn mock() -> Self {
        Self::custom(
            ApiProtocol::OpenAiCompletions,
            "mock",
            "http://mock.invalid",
            "mock",
            "Mock",
        )
    }

    pub fn custom(
        api: ApiProtocol,
        provider: impl Into<String>,
        base_url: impl Into<String>,
        model_id: impl Into<String>,
        name: impl Into<String>,
    ) -> Self {
        Self {
            id: model_id.into(),
            name: name.into(),
            api,
            provider: provider.into(),
            base_url: base_url.into(),
            reasoning: false,
            context_window: 128_000,
            max_tokens: 4096,
            cost: None,
            headers: HashMap::new(),
            compat: None,
        }
    }

    pub fn openai(id: impl Into<String>, name: impl Into<String>) -> Self {
        let id = id.into();
        let mut model = Self::custom(
            ApiProtocol::OpenAiCompletions,
            "openai",
            "https://api.openai.com/v1",
            id,
            name,
        );
        model.compat = Some(OpenAiCompat::openai());
        model.max_tokens = 16_384;
        model
    }

    pub fn openai_compat(
        base_url: impl Into<String>,
        model_id: impl Into<String>,
        provider: impl Into<String>,
        compat: OpenAiCompat,
    ) -> Self {
        let id = model_id.into();
        let mut model = Self::custom(
            ApiProtocol::OpenAiCompletions,
            provider,
            base_url,
            id.clone(),
            id,
        );
        model.compat = Some(compat);
        model
    }

    pub fn minimax(id: impl Into<String>, name: impl Into<String>) -> Self {
        let mut model = Self::openai_compat(
            "https://api.minimax.io/v1",
            id,
            "minimax",
            OpenAiCompat::minimax(),
        );
        model.name = name.into();
        model
    }

    pub fn local(base_url: impl Into<String>, model_id: impl Into<String>) -> Self {
        Self::openai_compat(base_url, model_id, "local", OpenAiCompat::default())
    }

    pub fn with_encrypted_reasoning(mut self, on: bool) -> Self {
        self.compat
            .get_or_insert_with(OpenAiCompat::default)
            .encrypted_reasoning = on;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cost_accounting_includes_cached_tokens_and_context_tiers() {
        let config = CostConfig::new(2.0, 8.0)
            .with_cache_read(0.5)
            .with_context_tier(ContextTier::new(100_000, 4.0, 12.0));
        let usage = crate::types::Usage {
            input: 50_000,
            output: 0,
            cache_read: 50_001,
            cache_write: 0,
            total_tokens: 100_001,
        };
        assert!((config.cost_usd(&usage) - 0.400004).abs() < 1e-9);
    }

    #[test]
    fn model_debug_never_prints_header_values() {
        let mut model = ModelConfig::openai("gpt-test", "test");
        model
            .headers
            .insert("authorization".into(), "secret-value".into());
        assert!(!format!("{model:?}").contains("secret-value"));
    }
}
