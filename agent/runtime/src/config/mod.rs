//! Configuration shared by the optional local memory integration.
//!
//! LLM endpoint and credential configuration belongs to the native CLI. This
//! module only describes the independent embedding and database settings used
//! by Uteke memory.

/// Memory embedding backend and local store configuration.
#[derive(serde::Deserialize, Clone)]
#[serde(default, deny_unknown_fields)]
pub struct MemoryConfig {
    /// Embedding backend: `onnx`, `openai`, or `ollama`.
    pub backend: String,
    /// Embedding model; empty selects the backend default.
    pub model: String,
    /// Custom embedding endpoint; empty selects the backend default.
    pub base_url: String,
    /// Dedicated embedding API key. This is separate from Gateway credentials.
    pub api_key: String,
    /// Force embedding dimensions; zero selects the backend default.
    pub dims: usize,
    /// Optional embedding endpoint path override.
    pub endpoint_path: String,
    /// Base directory for the profile-isolated memory database.
    pub db_path: String,
}

impl MemoryConfig {
    /// Resolve the database path, isolating indexes by backend/model/dimension.
    pub fn resolved_db_path(&self) -> std::path::PathBuf {
        let base = if self.db_path.is_empty() {
            "memory"
        } else {
            &self.db_path
        };
        if base.ends_with(".sqlite") {
            return std::path::PathBuf::from(base);
        }
        let model = if self.model.is_empty() {
            match self.backend.to_ascii_lowercase().as_str() {
                "openai" => "text-embedding-3-small",
                "ollama" => "nomic-embed-text",
                _ => "default",
            }
        } else {
            self.model.as_str()
        };
        let dims = if self.dims > 0 {
            self.dims.to_string()
        } else {
            "auto".to_owned()
        };
        std::path::PathBuf::from(base)
            .join(&self.backend)
            .join(model)
            .join(dims)
            .join("db.sqlite")
    }
}

impl Default for MemoryConfig {
    fn default() -> Self {
        Self {
            backend: "onnx".to_owned(),
            model: String::new(),
            base_url: String::new(),
            api_key: String::new(),
            dims: 0,
            endpoint_path: String::new(),
            db_path: "memory".to_owned(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::MemoryConfig;

    #[test]
    fn profile_path_separates_embedding_models_and_dimensions() {
        let config = MemoryConfig {
            backend: "openai".into(),
            model: "text-embedding-3-small".into(),
            dims: 1536,
            ..MemoryConfig::default()
        };
        assert_eq!(
            config.resolved_db_path(),
            std::path::PathBuf::from("memory/openai/text-embedding-3-small/1536/db.sqlite")
        );
    }

    #[test]
    fn legacy_explicit_sqlite_path_is_preserved() {
        let config = MemoryConfig {
            db_path: "state/memory.sqlite".into(),
            ..MemoryConfig::default()
        };
        assert_eq!(
            config.resolved_db_path(),
            std::path::PathBuf::from("state/memory.sqlite")
        );
    }
}
