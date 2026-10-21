use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::path::Path;
use thiserror::Error;
use url::Url;
use zeroize::Zeroize;

const MAX_ENV_BYTES: u64 = 64 * 1024;
const MAX_ENVELOPE_BYTES: u64 = 32 * 1024;
const MAX_CONFIG_VALUE_BYTES: usize = 8192;
const MAX_CREDENTIAL_PLAINTEXT_BYTES: usize = 8192;

const ENV_KEYS: &[&str] = &[
    "WS_PROXY_CONFIG_SOURCE",
    "WS_PROXY_IDENTITY_URL",
    "WS_PROXY_GATEWAY_URL",
    "WS_PROXY_CLIENT_ID",
    "WS_PROXY_CLIENT_SECRET",
    "WS_PROXY_ENVELOPE_FILE",
    "WS_PROXY_MODEL_ALIAS",
    "WS_PROXY_PROVIDER",
    "WS_PROXY_PROTOCOL",
    // Accepted for compatibility with the template's shared env file; native
    // Gateway clients do not use the loopback adapter's local bearer token.
    "WS_PROXY_LOCAL_BEARER_TOKEN",
];

#[derive(Debug, Error, PartialEq, Eq)]
pub enum GatewayConfigError {
    #[error("protected environment file is unreadable, too large, or not owner-only")]
    EnvironmentFile,
    #[error("environment file contains an unsupported or malformed setting")]
    EnvironmentSyntax,
    #[error("missing required setting {0}")]
    Missing(&'static str),
    #[error("Gateway settings are invalid")]
    Invalid,
    #[error("credential envelope is unreadable or invalid")]
    EnvelopeFile,
}

/// Sensitive client credentials have no Debug representation and are wiped
/// when their owner is dropped. They are never persisted by this crate.
pub struct SecretString(String);

impl SecretString {
    pub(crate) fn new(value: String) -> Self {
        Self(value)
    }

    pub(crate) fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[redacted]")
    }
}

impl Drop for SecretString {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Clone, Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialEnvelope {
    pub v: u8,
    pub alg: String,
    #[serde(rename = "credentialId")]
    pub credential_id: String,
    #[serde(rename = "userId")]
    pub user_id: String,
    #[serde(rename = "projectId")]
    pub project_id: String,
    pub provider: String,
    pub kid: String,
    pub exp: u64,
    pub nonce: String,
    pub ciphertext: String,
}

impl fmt::Debug for CredentialEnvelope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CredentialEnvelope([redacted])")
    }
}

impl Drop for CredentialEnvelope {
    fn drop(&mut self) {
        self.alg.zeroize();
        self.credential_id.zeroize();
        self.user_id.zeroize();
        self.project_id.zeroize();
        self.provider.zeroize();
        self.kid.zeroize();
        self.nonce.zeroize();
        self.ciphertext.zeroize();
        self.exp.zeroize();
        self.v.zeroize();
    }
}

impl CredentialEnvelope {
    fn validate(&self, provider: &str) -> Result<(), GatewayConfigError> {
        if self.v != 1
            || self.alg != "A256GCM"
            || self.provider != provider
            || !valid_identifier(&self.credential_id)
            || !valid_identifier(&self.user_id)
            || !valid_identifier(&self.project_id)
            || !valid_identifier(&self.provider)
            || !valid_key_id(&self.kid)
            || self.exp <= unix_now()
            || !canonical_base64url(&self.nonce, Some(12))
            || !canonical_base64url(&self.ciphertext, None)
        {
            return Err(GatewayConfigError::Invalid);
        }
        let ciphertext_len = URL_SAFE_NO_PAD
            .decode(&self.ciphertext)
            .map_err(|_| GatewayConfigError::Invalid)?
            .len();
        if !(16..=MAX_CREDENTIAL_PLAINTEXT_BYTES + 16).contains(&ciphertext_len) {
            return Err(GatewayConfigError::Invalid);
        }
        Ok(())
    }
}

/// Runtime settings for one confidential machine client and one authorized
/// model alias. It intentionally has no API-key field: provider credentials
/// remain encrypted inside `envelope`.
pub struct GatewayConfig {
    pub identity_url: Url,
    pub gateway_url: Url,
    pub client_id: String,
    pub(crate) client_secret: SecretString,
    pub envelope: CredentialEnvelope,
    pub provider_id: String,
    pub model_alias: String,
}

impl fmt::Debug for GatewayConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GatewayConfig")
            .field("identity_url", &self.identity_url)
            .field("gateway_url", &self.gateway_url)
            .field("client_id", &self.client_id)
            .field("client_secret", &"[redacted]")
            .field("envelope", &self.envelope)
            .field("provider_id", &self.provider_id)
            .field("model_alias", &self.model_alias)
            .finish()
    }
}

impl GatewayConfig {
    /// Reads already-loaded `WS_PROXY_*` settings from the current process.
    pub fn from_env() -> Result<Self, GatewayConfigError> {
        Self::from_lookup(|name| std::env::var(name).ok())
    }

    /// Reads a protected dotenv file without evaluating it or mutating process
    /// environment. Inherited process values take precedence over file values.
    pub fn from_env_file(path: impl AsRef<Path>) -> Result<Self, GatewayConfigError> {
        let mut values = read_env_file(path.as_ref())?;
        let result = Self::from_lookup(|name| {
            std::env::var(name)
                .ok()
                .or_else(|| values.get(name).cloned())
        });
        zeroize_env_secrets(&mut values);
        result
    }

    fn from_lookup(
        mut lookup: impl FnMut(&str) -> Option<String>,
    ) -> Result<Self, GatewayConfigError> {
        if lookup("WS_PROXY_CONFIG_SOURCE").as_deref() != Some("env") {
            return Err(GatewayConfigError::Missing("WS_PROXY_CONFIG_SOURCE=env"));
        }
        let identity_url = parse_identity_url(required(&mut lookup, "WS_PROXY_IDENTITY_URL")?)?;
        let gateway_url = parse_gateway_url(required(&mut lookup, "WS_PROXY_GATEWAY_URL")?)?;
        let client_id = bounded_required(&mut lookup, "WS_PROXY_CLIENT_ID", 256)?;
        let client_secret = SecretString::new(required(&mut lookup, "WS_PROXY_CLIENT_SECRET")?);
        if client_secret.expose().len() > 512
            || client_secret.expose().chars().any(char::is_control)
        {
            return Err(GatewayConfigError::Invalid);
        }
        let envelope_path = required(&mut lookup, "WS_PROXY_ENVELOPE_FILE")?;
        let provider_id = bounded_required(&mut lookup, "WS_PROXY_PROVIDER", 64)?;
        let model_alias = bounded_required(&mut lookup, "WS_PROXY_MODEL_ALIAS", 128)?;
        let protocol = required(&mut lookup, "WS_PROXY_PROTOCOL")?;
        if protocol != "openai"
            || !valid_provider_id(&provider_id)
            || !valid_model_alias(&model_alias)
        {
            return Err(GatewayConfigError::Invalid);
        }
        let envelope = read_envelope(Path::new(&envelope_path))?;
        envelope.validate(&provider_id)?;
        Ok(Self {
            identity_url,
            gateway_url,
            client_id,
            client_secret,
            envelope,
            provider_id,
            model_alias,
        })
    }

    /// Creates the yoagent metadata for this alias. The base URL is inert:
    /// GatewayProvider never makes a direct provider HTTP request.
    pub fn model_config(&self) -> yoagent::provider::ModelConfig {
        yoagent::provider::ModelConfig::openai_compat(
            "https://api.openai.com/v1",
            self.model_alias.clone(),
            self.provider_id.clone(),
            yoagent::provider::OpenAiCompat::openai(),
        )
    }
}

fn read_env_file(path: &Path) -> Result<BTreeMap<String, String>, GatewayConfigError> {
    let mut contents = read_protected_file(path, MAX_ENV_BYTES)
        .map_err(|_| GatewayConfigError::EnvironmentFile)?;
    let mut values = BTreeMap::new();
    let parse_result = (|| {
        for entry in dotenvy::from_read_iter(contents.as_bytes()) {
            let (key, mut value) = entry.map_err(|_| GatewayConfigError::EnvironmentSyntax)?;
            if !ENV_KEYS.contains(&key.as_str()) || values.contains_key(&key) {
                value.zeroize();
                return Err(GatewayConfigError::EnvironmentSyntax);
            }
            values.insert(key, value);
        }
        Ok(())
    })();
    contents.zeroize();
    if let Err(error) = parse_result {
        zeroize_env_secrets(&mut values);
        return Err(error);
    }
    Ok(values)
}

fn zeroize_env_secrets(values: &mut BTreeMap<String, String>) {
    for name in ["WS_PROXY_CLIENT_SECRET", "WS_PROXY_LOCAL_BEARER_TOKEN"] {
        if let Some(value) = values.get_mut(name) {
            value.zeroize();
        }
    }
}

fn read_envelope(path: &Path) -> Result<CredentialEnvelope, GatewayConfigError> {
    let mut contents = read_protected_file(path, MAX_ENVELOPE_BYTES)
        .map_err(|_| GatewayConfigError::EnvelopeFile)?;
    let parsed = serde_json::from_str(&contents).map_err(|_| GatewayConfigError::EnvelopeFile);
    contents.zeroize();
    parsed
}

fn read_protected_file(path: &Path, limit: u64) -> std::io::Result<String> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let file = options.open(path)?;
    validate_protected_file(&file, limit)?;
    let mut bytes = Vec::new();
    if let Err(error) = file.take(limit + 1).read_to_end(&mut bytes) {
        bytes.zeroize();
        return Err(error);
    }
    if bytes.len() as u64 > limit {
        bytes.zeroize();
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "file exceeds limit",
        ));
    }
    match String::from_utf8(bytes) {
        Ok(contents) => Ok(contents),
        Err(error) => {
            let mut bytes = error.into_bytes();
            bytes.zeroize();
            Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "file is not UTF-8",
            ))
        }
    }
}

fn validate_protected_file(file: &File, limit: u64) -> std::io::Result<()> {
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > limit {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid file",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.mode() & 0o777 != 0o600 || metadata.uid() != unsafe { libc::geteuid() } {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "private file required",
            ));
        }
    }
    Ok(())
}

fn required(
    lookup: &mut impl FnMut(&str) -> Option<String>,
    name: &'static str,
) -> Result<String, GatewayConfigError> {
    let value = lookup(name).ok_or(GatewayConfigError::Missing(name))?;
    if value.is_empty() || value.len() > MAX_CONFIG_VALUE_BYTES {
        return Err(GatewayConfigError::Invalid);
    }
    Ok(value)
}

fn bounded_required(
    lookup: &mut impl FnMut(&str) -> Option<String>,
    name: &'static str,
    maximum: usize,
) -> Result<String, GatewayConfigError> {
    let value = required(lookup, name)?;
    if value.len() > maximum || value.chars().any(char::is_control) {
        return Err(GatewayConfigError::Invalid);
    }
    Ok(value)
}

fn parse_identity_url(value: String) -> Result<Url, GatewayConfigError> {
    let url = Url::parse(&value).map_err(|_| GatewayConfigError::Invalid)?;
    let local_http = url.scheme() == "http" && is_loopback(&url);
    if (url.scheme() != "https" && !local_http)
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(GatewayConfigError::Invalid);
    }
    Ok(url)
}

fn parse_gateway_url(value: String) -> Result<Url, GatewayConfigError> {
    let url = Url::parse(&value).map_err(|_| GatewayConfigError::Invalid)?;
    let local_ws = url.scheme() == "ws" && is_loopback(&url);
    if (url.scheme() != "wss" && !local_ws)
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/v1/socket"
    {
        return Err(GatewayConfigError::Invalid);
    }
    Ok(url)
}

fn is_loopback(url: &Url) -> bool {
    match url.host_str() {
        Some("localhost") => true,
        Some(host) => {
            let unbracketed = host
                .strip_prefix('[')
                .and_then(|host| host.strip_suffix(']'))
                .unwrap_or(host);
            unbracketed
                .parse::<std::net::IpAddr>()
                .map(|ip| ip.is_loopback())
                .unwrap_or(false)
        }
        None => false,
    }
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
}

fn valid_key_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
}

fn valid_provider_id(value: &str) -> bool {
    (1..=64).contains(&value.len())
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"_-".contains(&byte))
}

fn valid_model_alias(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && !value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
}

fn canonical_base64url(value: &str, exact_len: Option<usize>) -> bool {
    match URL_SAFE_NO_PAD.decode(value) {
        Ok(bytes) => {
            if exact_len.is_some_and(|len| bytes.len() != len) {
                return false;
            }
            URL_SAFE_NO_PAD.encode(bytes) == value
        }
        Err(_) => false,
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};
    use tempfile::TempDir;

    fn write_private(path: &Path, bytes: &[u8]) {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(path).expect("create protected fixture");
        std::io::Write::write_all(&mut file, bytes).expect("write protected fixture");
    }

    fn envelope_value(provider: &str) -> serde_json::Value {
        json!({
            "v": 1,
            "alg": "A256GCM",
            "kid": "key-2026-01",
            "credentialId": "cred_test_1",
            "userId": "user_test_1",
            "projectId": "project_test_1",
            "provider": provider,
            "exp": SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() + 3600,
            "nonce": URL_SAFE_NO_PAD.encode([0u8; 12]),
            "ciphertext": URL_SAFE_NO_PAD.encode([0u8; 32]),
        })
    }

    fn write_envelope(dir: &TempDir, provider: &str) -> std::path::PathBuf {
        let path = dir.path().join("envelope.json");
        write_private(
            &path,
            serde_json::to_string(&envelope_value(provider))
                .unwrap()
                .as_bytes(),
        );
        path
    }

    fn config_map(envelope_path: &Path) -> BTreeMap<String, String> {
        [
            ("WS_PROXY_CONFIG_SOURCE", "env"),
            ("WS_PROXY_IDENTITY_URL", "http://127.0.0.1:8787"),
            ("WS_PROXY_GATEWAY_URL", "ws://[::1]:8788/v1/socket"),
            ("WS_PROXY_CLIENT_ID", "client-1"),
            ("WS_PROXY_CLIENT_SECRET", "client-secret-do-not-print"),
            ("WS_PROXY_ENVELOPE_FILE", envelope_path.to_str().unwrap()),
            ("WS_PROXY_MODEL_ALIAS", "coding-fast"),
            ("WS_PROXY_PROVIDER", "openai"),
            ("WS_PROXY_PROTOCOL", "openai"),
        ]
        .into_iter()
        .map(|(key, value)| (key.to_owned(), value.to_owned()))
        .collect()
    }

    fn from_map(values: BTreeMap<String, String>) -> Result<GatewayConfig, GatewayConfigError> {
        GatewayConfig::from_lookup(|key| values.get(key).cloned())
    }

    #[test]
    fn parses_loopback_configuration_and_keeps_secret_out_of_debug() {
        let dir = tempfile::tempdir().unwrap();
        let envelope = write_envelope(&dir, "openai");
        let config = from_map(config_map(&envelope)).unwrap();
        assert_eq!(config.gateway_url.as_str(), "ws://[::1]:8788/v1/socket");
        assert_eq!(config.model_config().id, "coding-fast");
        let debug = format!("{config:?}");
        assert!(!debug.contains("client-secret-do-not-print"));
        assert!(!debug.contains("AAAAAAAAAAAAAAAAAAAAAA"));
        assert!(debug.contains("[redacted]"));
    }

    #[test]
    fn rejects_unprotected_symlink_and_non_loopback_cleartext_urls() {
        let dir = tempfile::tempdir().unwrap();
        let real = write_envelope(&dir, "openai");
        let link = dir.path().join("envelope-link.json");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let mut values = config_map(&real);
        values.insert(
            "WS_PROXY_ENVELOPE_FILE".into(),
            link.to_string_lossy().into_owned(),
        );
        assert_eq!(
            from_map(values).unwrap_err(),
            GatewayConfigError::EnvelopeFile
        );

        let mut values = config_map(&real);
        values.insert(
            "WS_PROXY_GATEWAY_URL".into(),
            "ws://gateway.example/v1/socket".into(),
        );
        assert_eq!(from_map(values).unwrap_err(), GatewayConfigError::Invalid);
        let mut values = config_map(&real);
        values.insert(
            "WS_PROXY_IDENTITY_URL".into(),
            "http://identity.example".into(),
        );
        assert_eq!(from_map(values).unwrap_err(), GatewayConfigError::Invalid);
    }

    #[test]
    fn envelope_provider_and_expiry_must_match_configuration() {
        let dir = tempfile::tempdir().unwrap();
        let envelope = write_envelope(&dir, "anthropic");
        assert_eq!(
            from_map(config_map(&envelope)).unwrap_err(),
            GatewayConfigError::Invalid
        );

        let expired_path = dir.path().join("expired.json");
        let mut expired = envelope_value("openai");
        expired["exp"] = serde_json::json!(unix_now().saturating_sub(1));
        write_private(
            &expired_path,
            serde_json::to_string(&expired).unwrap().as_bytes(),
        );
        assert_eq!(
            from_map(config_map(&expired_path)).unwrap_err(),
            GatewayConfigError::Invalid
        );
    }

    #[test]
    fn dotenv_reader_rejects_duplicate_and_unrelated_environment_entries() {
        let dir = tempfile::tempdir().unwrap();
        let duplicate = dir.path().join("duplicate.env");
        write_private(
            &duplicate,
            b"WS_PROXY_PROVIDER=openai\nWS_PROXY_PROVIDER=openai\n",
        );
        assert_eq!(
            read_env_file(&duplicate).unwrap_err(),
            GatewayConfigError::EnvironmentSyntax
        );

        let unrelated = dir.path().join("unrelated.env");
        write_private(&unrelated, b"NODE_OPTIONS=--inspect\n");
        assert_eq!(
            read_env_file(&unrelated).unwrap_err(),
            GatewayConfigError::EnvironmentSyntax
        );
    }

    #[cfg(unix)]
    #[test]
    fn protected_file_requires_exact_owner_only_mode() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("loose.env");
        write_private(&path, b"WS_PROXY_PROVIDER=openai\n");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        assert!(read_env_file(&path).is_err());
    }
}
