use crate::config::{GatewayConfig, SecretString};
use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use futures_util::{SinkExt, StreamExt, TryStreamExt};
use serde::Deserialize;
use serde_json::{json, Value};
use std::fmt;
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::sync::Mutex;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::tungstenite::Message as WsMessage;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;
use yoagent::provider::openai_compat::{
    build_chat_payload, OpenAiStreamParser, OpenAiStreamPolicy, PushResult,
};
use yoagent::provider::{ApiProtocol, ProviderError, StreamConfig, StreamEvent, StreamProvider};
use yoagent::Message;
use zeroize::Zeroize;

const MAX_GATEWAY_FRAME_BYTES: usize = 1_048_576;
const MAX_REQUEST_FRAME_BYTES: usize = 1_048_576;
const MAX_CONTROL_FRAME_BYTES: usize = 4_096;
const MAX_RESPONSE_FRAME_BYTES: usize = 262_144;
const MAX_PAYLOAD_BYTES: usize = 1_048_576;
const MAX_CHUNK_BYTES: usize = 32_768;
const MAX_RESPONSE_BYTES: usize = 16_777_216;
const MAX_RESPONSE_CHUNKS: u64 = 4_096;
const MAX_STREAM_EVENTS: usize = 16_384;
const ACK_WINDOW: u64 = 8;
const TOKEN_RESPONSE_LIMIT: usize = 16 * 1024;
const TOKEN_EXPIRY_SKEW: Duration = Duration::from_secs(30);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(300);

type GatewaySocket = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

#[derive(Debug, Error)]
pub enum GatewayProviderError {
    #[error("could not initialize the Gateway Identity client")]
    HttpClient,
}

struct CachedToken {
    value: SecretString,
    usable_until: Instant,
}

/// A direct native WebSocket provider for yoagent. It performs machine OAuth
/// with Identity, then sends only the short-lived access token in the WSS
/// Authorization header and the encrypted credential envelope in request.start.
pub struct GatewayProvider {
    config: Arc<GatewayConfig>,
    http: reqwest::Client,
    token: Mutex<Option<CachedToken>>,
}

impl fmt::Debug for GatewayProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GatewayProvider")
            .field("provider_id", &self.config.provider_id)
            .field("model_alias", &self.config.model_alias)
            .field("identity_url", &self.config.identity_url)
            .field("gateway_url", &self.config.gateway_url)
            .finish_non_exhaustive()
    }
}

impl GatewayProvider {
    pub fn new(config: GatewayConfig) -> Result<Self, GatewayProviderError> {
        let http = reqwest::Client::builder()
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(CONNECT_TIMEOUT)
            // Identity credentials must never follow a redirect to another host.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| GatewayProviderError::HttpClient)?;
        Ok(Self {
            config: Arc::new(config),
            http,
            token: Mutex::new(None),
        })
    }

    async fn access_token(
        &self,
        cancel: &CancellationToken,
    ) -> Result<SecretString, ProviderError> {
        let mut cache = self.token.lock().await;
        if let Some(cached) = cache.as_ref() {
            if Instant::now() + TOKEN_EXPIRY_SKEW < cached.usable_until {
                return Ok(SecretString::new(cached.value.expose().to_owned()));
            }
        }
        if cancel.is_cancelled() {
            return Err(ProviderError::Cancelled);
        }

        let token_url = self
            .config
            .identity_url
            .join("/oauth/token")
            .map_err(|_| ProviderError::Auth("Identity URL is invalid".into()))?;
        let mut basic =
            basic_client_auth(&self.config.client_id, self.config.client_secret.expose());
        let mut authorization = reqwest::header::HeaderValue::from_str(&basic)
            .map_err(|_| ProviderError::Auth("Identity authorization header is invalid".into()))?;
        basic.zeroize();
        authorization.set_sensitive(true);
        let response = tokio::select! {
            _ = cancel.cancelled() => return Err(ProviderError::Cancelled),
            result = self.http.post(token_url)
                .header(reqwest::header::AUTHORIZATION, authorization)
                .form(&[("grant_type", "client_credentials")])
                .send() => result.map_err(|_| ProviderError::Network("Identity token request failed".into()))?,
        };
        if !response.status().is_success() {
            return Err(identity_http_error(response.status().as_u16()));
        }
        let mut body = read_bounded_body(response, TOKEN_RESPONSE_LIMIT, cancel).await?;
        let token_result: Result<TokenResponse, _> = serde_json::from_slice(&body);
        body.zeroize();
        let mut token = token_result.map_err(|_| {
            ProviderError::Auth("Identity returned an invalid token response".into())
        })?;
        if token.token_type != "Bearer"
            || token.access_token.is_empty()
            || token.access_token.len() > 8_192
            || token
                .access_token
                .bytes()
                .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
            || !(1..=3_600).contains(&token.expires_in)
        {
            return Err(ProviderError::Auth(
                "Identity returned an invalid token response".into(),
            ));
        }
        let value = SecretString::new(std::mem::take(&mut token.access_token));
        let usable_until = Instant::now() + Duration::from_secs(token.expires_in);
        let cached_value = SecretString::new(value.expose().to_owned());
        *cache = Some(CachedToken {
            value: cached_value,
            usable_until,
        });
        Ok(value)
    }

    async fn stream_gateway(
        &self,
        config: StreamConfig,
        tx: tokio::sync::mpsc::UnboundedSender<StreamEvent>,
        cancel: CancellationToken,
    ) -> Result<Message, ProviderError> {
        let model_config = config.model_config.as_ref().ok_or_else(|| {
            ProviderError::Other("Gateway provider requires a model configuration".into())
        })?;
        if config.model != self.config.model_alias
            || model_config.id != self.config.model_alias
            || model_config.provider != self.config.provider_id
            || model_config.api != ApiProtocol::OpenAiCompletions
        {
            return Err(ProviderError::Other(
                "Gateway model configuration does not match the authorized alias".into(),
            ));
        }
        if cancel.is_cancelled() {
            return Err(ProviderError::Cancelled);
        }

        let payload = build_chat_payload(&config)?;
        let payload_obj = payload.as_object().ok_or_else(|| {
            ProviderError::Other("OpenAI request builder returned invalid data".into())
        })?;
        if payload_obj.contains_key("model") || payload_obj.contains_key("stream") {
            return Err(ProviderError::Other(
                "OpenAI payload contains Gateway-owned fields".into(),
            ));
        }
        let payload_bytes = serde_json::to_vec(&payload)
            .map_err(|_| ProviderError::Other("OpenAI payload could not be serialized".into()))?;

        let access_token = self.access_token(&cancel).await?;
        let mut socket = self.connect(&access_token, &cancel).await?;
        let ready = self.read_session_ready(&mut socket, &cancel).await?;
        // This lower bound cannot reject a request that Gateway would accept;
        // only Gateway knows the actual server-mapped upstream model length.
        if payload_bytes.len() > ready.max_payload_bytes as usize {
            return Err(ProviderError::Other(
                "Request exceeds the Gateway payload limit".into(),
            ));
        }

        let request_id = Uuid::new_v4().to_string();
        if tx.is_closed() {
            return Err(ProviderError::Cancelled);
        }
        let start = json!({
            "event": "request.start",
            "requestId": request_id,
            "api": "chat.completions",
            "provider": self.config.provider_id,
            "model": self.config.model_alias,
            "envelope": self.config.envelope,
            "payload": payload,
        });
        let start_bytes = serde_json::to_vec(&start)
            .map_err(|_| ProviderError::Other("Gateway request could not be serialized".into()))?;
        if start_bytes.len() > MAX_REQUEST_FRAME_BYTES {
            return Err(ProviderError::Other(
                "Gateway request exceeds the frame limit".into(),
            ));
        }
        send_text(&mut socket, start_bytes, &cancel).await?;

        // The vendored parser uses yoagent's unbounded sender API. Keep that
        // internal queue scoped to one Gateway chunk, enforce a lifetime event
        // cap, and forward accepted events before ACKing the corresponding
        // chunk. This bounds queued local work even if a peer sends many tiny
        // SSE deltas.
        let (parser_tx, mut parser_events) = tokio::sync::mpsc::unbounded_channel();
        let mut parser =
            OpenAiStreamParser::new(&config, parser_tx, OpenAiStreamPolicy::GatewayStrict)?;
        let mut emitted_events = 0usize;
        if let Err(error) = forward_parser_events(&mut parser_events, &tx, &mut emitted_events) {
            send_cancel(&mut socket, &request_id).await;
            return Err(error);
        }
        // Token expiry prevents new starts but does not cancel a request that
        // Gateway already authorized. Bound this one request by the negotiated
        // hard socket lifetime and the Gateway request deadline.
        let session_lifetime = Duration::from_secs(ready.max_session_seconds as u64);
        let deadline = tokio::time::Instant::now() + session_lifetime.min(REQUEST_TIMEOUT);
        let mut expected_seq = 0u64;
        let mut total_response_bytes = 0usize;
        let mut chunks = 0u64;

        loop {
            if tx.is_closed() {
                send_cancel(&mut socket, &request_id).await;
                return Err(ProviderError::Cancelled);
            }
            let message = tokio::select! {
                _ = cancel.cancelled() => {
                    send_cancel(&mut socket, &request_id).await;
                    return Err(ProviderError::Cancelled);
                }
                _ = tokio::time::sleep_until(deadline) => {
                    send_cancel(&mut socket, &request_id).await;
                    return Err(ProviderError::Network("Gateway request exceeded its session lifetime".into()));
                }
                message = socket.next() => message,
            };
            match message {
                Some(Ok(WsMessage::Text(text))) => {
                    let text = text.to_string();
                    let frame = match parse_server_frame(&text, false) {
                        Ok(frame) => frame,
                        Err(error) => {
                            send_cancel(&mut socket, &request_id).await;
                            return Err(error);
                        }
                    };
                    match frame {
                        ServerFrame::Chunk {
                            request_id: frame_id,
                            seq,
                            data,
                        } => {
                            if frame_id != request_id || seq != expected_seq {
                                send_cancel(&mut socket, &request_id).await;
                                return Err(protocol_error());
                            }
                            if data.is_empty() || data.len() > MAX_CHUNK_BYTES {
                                send_cancel(&mut socket, &request_id).await;
                                return Err(protocol_error());
                            }
                            total_response_bytes = total_response_bytes
                                .checked_add(data.len())
                                .filter(|bytes| *bytes <= MAX_RESPONSE_BYTES)
                                .ok_or_else(protocol_error)?;
                            chunks += 1;
                            if chunks > MAX_RESPONSE_CHUNKS {
                                send_cancel(&mut socket, &request_id).await;
                                return Err(protocol_error());
                            }
                            let parser_result = parser.push_data(&data).map_err(map_parser_error);
                            let parser_result = match parser_result {
                                Ok(result) => result,
                                Err(error) => {
                                    send_cancel(&mut socket, &request_id).await;
                                    return Err(error);
                                }
                            };
                            match parser_result {
                                PushResult::Continue | PushResult::Done => {}
                            }
                            if let Err(error) =
                                forward_parser_events(&mut parser_events, &tx, &mut emitted_events)
                            {
                                send_cancel(&mut socket, &request_id).await;
                                return Err(error);
                            }
                            if tx.is_closed() {
                                send_cancel(&mut socket, &request_id).await;
                                return Err(ProviderError::Cancelled);
                            }
                            send_text(
                                &mut socket,
                                serde_json::to_vec(&json!({
                                    "event": "request.start",
                                    "op": "ack",
                                    "requestId": request_id,
                                    "ackSeq": seq,
                                }))
                                .map_err(|_| protocol_error())?,
                                &cancel,
                            )
                            .await?;
                            expected_seq =
                                expected_seq.checked_add(1).ok_or_else(protocol_error)?;
                        }
                        ServerFrame::End {
                            request_id: frame_id,
                            last_seq,
                        } => {
                            if frame_id != request_id || last_seq != expected_seq as i64 - 1 {
                                return Err(protocol_error());
                            }
                            let message = parser.finish().map_err(map_parser_error)?;
                            forward_parser_events(&mut parser_events, &tx, &mut emitted_events)?;
                            return Ok(message);
                        }
                        ServerFrame::Error {
                            request_id: frame_id,
                            last_seq,
                            code,
                        } => {
                            if frame_id != request_id || last_seq != expected_seq as i64 - 1 {
                                return Err(protocol_error());
                            }
                            return Err(map_gateway_error(&code));
                        }
                        ServerFrame::Draining => {
                            // The current request remains valid while the
                            // Gateway drains this socket; only future starts
                            // would be prohibited (this connection has one).
                        }
                        ServerFrame::Ready(_) => return Err(protocol_error()),
                    }
                }
                Some(Ok(WsMessage::Ping(bytes))) => {
                    socket
                        .send(WsMessage::Pong(bytes))
                        .await
                        .map_err(|_| gateway_network_error())?;
                }
                Some(Ok(WsMessage::Pong(_))) => {}
                Some(Ok(WsMessage::Close(_))) | None => return Err(gateway_network_error()),
                Some(Ok(WsMessage::Binary(_))) | Some(Ok(WsMessage::Frame(_))) => {
                    return Err(protocol_error())
                }
                Some(Err(_)) => return Err(gateway_network_error()),
            }
        }
    }

    async fn connect(
        &self,
        token: &SecretString,
        cancel: &CancellationToken,
    ) -> Result<GatewaySocket, ProviderError> {
        let mut request = self
            .config
            .gateway_url
            .as_str()
            .into_client_request()
            .map_err(|_| ProviderError::Auth("Gateway URL is invalid".into()))?;
        let mut auth = format!("Bearer {}", token.expose());
        let mut authorization = tokio_tungstenite::tungstenite::http::HeaderValue::from_str(&auth)
            .map_err(|_| ProviderError::Auth("Gateway authorization header is invalid".into()))?;
        auth.zeroize();
        authorization.set_sensitive(true);
        request.headers_mut().insert("authorization", authorization);
        request.headers_mut().insert(
            "sec-websocket-protocol",
            "llm-proxy.v1".parse().map_err(|_| protocol_error())?,
        );
        let mut ws_config = WebSocketConfig::default();
        ws_config.max_message_size = Some(MAX_GATEWAY_FRAME_BYTES);
        ws_config.max_frame_size = Some(MAX_GATEWAY_FRAME_BYTES);
        let connected = tokio::select! {
            _ = cancel.cancelled() => return Err(ProviderError::Cancelled),
            result = crate::proxy::connect(request, ws_config) => result.map_err(|_| gateway_network_error())?,
        };
        let (socket, response) = connected;
        if response
            .headers()
            .get("sec-websocket-protocol")
            .and_then(|value| value.to_str().ok())
            != Some("llm-proxy.v1")
        {
            return Err(protocol_error());
        }
        Ok(socket)
    }

    async fn read_session_ready(
        &self,
        socket: &mut GatewaySocket,
        cancel: &CancellationToken,
    ) -> Result<SessionReady, ProviderError> {
        let deadline = tokio::time::Instant::now() + CONNECT_TIMEOUT;
        loop {
            let frame = tokio::select! {
                _ = cancel.cancelled() => return Err(ProviderError::Cancelled),
                _ = tokio::time::sleep_until(deadline) => return Err(ProviderError::Network("Gateway session setup timed out".into())),
                frame = socket.next() => frame,
            };
            match frame {
                Some(Ok(WsMessage::Text(text))) => {
                    let text = text.to_string();
                    match parse_server_frame(&text, true)? {
                        ServerFrame::Ready(ready) if ready.is_valid() => return Ok(ready),
                        _ => return Err(protocol_error()),
                    }
                }
                Some(Ok(WsMessage::Ping(bytes))) => {
                    socket
                        .send(WsMessage::Pong(bytes))
                        .await
                        .map_err(|_| gateway_network_error())?;
                }
                Some(Ok(WsMessage::Pong(_))) => {}
                Some(Ok(WsMessage::Close(_))) | None | Some(Err(_)) => {
                    return Err(gateway_network_error())
                }
                Some(Ok(WsMessage::Binary(_))) | Some(Ok(WsMessage::Frame(_))) => {
                    return Err(protocol_error())
                }
            }
        }
    }
}

#[async_trait]
impl StreamProvider for GatewayProvider {
    fn protocol(&self) -> Option<ApiProtocol> {
        Some(ApiProtocol::OpenAiCompletions)
    }

    async fn stream(
        &self,
        config: StreamConfig,
        tx: tokio::sync::mpsc::UnboundedSender<StreamEvent>,
        cancel: CancellationToken,
    ) -> Result<Message, ProviderError> {
        self.stream_gateway(config, tx, cancel).await
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TokenResponse {
    access_token: String,
    token_type: String,
    expires_in: u64,
}

impl Drop for TokenResponse {
    fn drop(&mut self) {
        self.access_token.zeroize();
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SessionReady {
    event: String,
    protocol: u8,
    #[serde(rename = "connectionId")]
    connection_id: String,
    #[serde(rename = "maxInFlight")]
    max_in_flight: u8,
    #[serde(rename = "maxPayloadBytes")]
    max_payload_bytes: u32,
    #[serde(rename = "maxSessionSeconds")]
    max_session_seconds: u16,
    #[serde(rename = "maxChunkBytes")]
    max_chunk_bytes: u32,
    #[serde(rename = "ackWindow")]
    ack_window: u8,
    #[serde(rename = "maxRequestFrameBytes")]
    max_request_frame_bytes: u32,
    #[serde(rename = "maxResponseFrameBytes")]
    max_response_frame_bytes: u32,
    #[serde(rename = "tokenExpiresAt")]
    token_expires_at: u64,
}

impl SessionReady {
    fn is_valid(&self) -> bool {
        self.event == "session.ready"
            && self.protocol == 1
            && !self.connection_id.is_empty()
            && self.connection_id.len() <= 128
            && (1..=8).contains(&self.max_in_flight)
            && (1..=MAX_PAYLOAD_BYTES as u32).contains(&self.max_payload_bytes)
            && (30..=300).contains(&self.max_session_seconds)
            && self.max_chunk_bytes as usize == MAX_CHUNK_BYTES
            && self.ack_window as u64 == ACK_WINDOW
            && self.max_request_frame_bytes as usize == MAX_REQUEST_FRAME_BYTES
            && self.max_response_frame_bytes as usize == MAX_RESPONSE_FRAME_BYTES
            && self.token_expires_at > unix_now()
            && self.token_expires_at <= unix_now() + 3_600
    }
}

enum ServerFrame {
    Ready(SessionReady),
    Chunk {
        request_id: String,
        seq: u64,
        data: String,
    },
    End {
        request_id: String,
        last_seq: i64,
    },
    Error {
        request_id: String,
        last_seq: i64,
        code: String,
    },
    Draining,
}

fn parse_server_frame(text: &str, handshake: bool) -> Result<ServerFrame, ProviderError> {
    if text.len() > MAX_GATEWAY_FRAME_BYTES {
        return Err(protocol_error());
    }
    let value: Value = serde_json::from_str(text).map_err(|_| protocol_error())?;
    let event = value
        .get("event")
        .and_then(Value::as_str)
        .ok_or_else(protocol_error)?;
    let control = event != "response.chunk";
    if control && text.len() > MAX_CONTROL_FRAME_BYTES {
        return Err(protocol_error());
    }
    if event == "response.chunk" && text.len() > MAX_RESPONSE_FRAME_BYTES {
        return Err(protocol_error());
    }
    if handshake != (event == "session.ready") {
        return Err(protocol_error());
    }
    match event {
        "session.ready" => serde_json::from_value(value)
            .map(ServerFrame::Ready)
            .map_err(|_| protocol_error()),
        "response.chunk" => {
            let chunk: ResponseChunk =
                serde_json::from_value(value).map_err(|_| protocol_error())?;
            if chunk.event != "response.chunk" {
                return Err(protocol_error());
            }
            Ok(ServerFrame::Chunk {
                request_id: chunk.request_id,
                seq: chunk.seq,
                data: chunk.data,
            })
        }
        "response.end" => {
            let end: ResponseEnd = serde_json::from_value(value).map_err(|_| protocol_error())?;
            if end.event != "response.end" {
                return Err(protocol_error());
            }
            let _usage = end.usage;
            Ok(ServerFrame::End {
                request_id: end.request_id,
                last_seq: end.last_seq,
            })
        }
        "response.error" => {
            let error: ResponseError =
                serde_json::from_value(value).map_err(|_| protocol_error())?;
            if error.event != "response.error" || error.message.len() > 512 {
                return Err(protocol_error());
            }
            let _upstream_started = error.upstream_started;
            let _retryable = error.retryable;
            Ok(ServerFrame::Error {
                request_id: error.request_id,
                last_seq: error.last_seq,
                code: error.code,
            })
        }
        "session.draining" => {
            let draining: SessionDraining =
                serde_json::from_value(value).map_err(|_| protocol_error())?;
            if draining.event != "session.draining"
                || !matches!(
                    draining.reason.as_str(),
                    "token_expiring" | "server_shutdown" | "policy"
                )
                || draining
                    .reconnect_after_ms
                    .is_some_and(|delay| delay > 60_000)
            {
                return Err(protocol_error());
            }
            Ok(ServerFrame::Draining)
        }
        _ => Err(protocol_error()),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResponseChunk {
    event: String,
    #[serde(rename = "requestId")]
    request_id: String,
    seq: u64,
    data: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResponseEnd {
    event: String,
    #[serde(rename = "requestId")]
    request_id: String,
    #[serde(rename = "lastSeq")]
    last_seq: i64,
    #[serde(default)]
    usage: Option<Value>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResponseError {
    event: String,
    #[serde(rename = "requestId")]
    request_id: String,
    #[serde(rename = "lastSeq")]
    last_seq: i64,
    code: String,
    message: String,
    #[serde(rename = "upstreamStarted")]
    upstream_started: bool,
    retryable: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SessionDraining {
    event: String,
    reason: String,
    #[serde(rename = "reconnectAfterMs")]
    reconnect_after_ms: Option<u64>,
}

fn forward_parser_events(
    parser_events: &mut tokio::sync::mpsc::UnboundedReceiver<StreamEvent>,
    output: &tokio::sync::mpsc::UnboundedSender<StreamEvent>,
    emitted: &mut usize,
) -> Result<(), ProviderError> {
    while let Ok(event) = parser_events.try_recv() {
        *emitted = emitted
            .checked_add(1)
            .filter(|count| *count <= MAX_STREAM_EVENTS)
            .ok_or_else(|| {
                ProviderError::Other("Gateway response exceeded the local event limit".into())
            })?;
        if output.send(event).is_err() {
            return Err(ProviderError::Cancelled);
        }
    }
    Ok(())
}

fn basic_client_auth(client_id: &str, client_secret: &str) -> String {
    let user = percent_encode(client_id);
    let password = percent_encode(client_secret);
    format!(
        "Basic {}",
        STANDARD.encode(format!("{user}:{password}").as_bytes())
    )
}

fn percent_encode(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || b"-_.!~*'()".contains(&byte) {
            encoded.push(byte as char);
        } else {
            use std::fmt::Write as _;
            let _ = write!(encoded, "%{byte:02X}");
        }
    }
    encoded
}

async fn read_bounded_body(
    response: reqwest::Response,
    limit: usize,
    cancel: &CancellationToken,
) -> Result<Vec<u8>, ProviderError> {
    if response
        .content_length()
        .is_some_and(|length| length as usize > limit)
    {
        return Err(ProviderError::Auth(
            "Identity token response exceeded the size limit".into(),
        ));
    }
    let mut stream = response.bytes_stream();
    let mut bytes = Vec::new();
    loop {
        let next = tokio::select! {
            _ = cancel.cancelled() => return Err(ProviderError::Cancelled),
            result = stream.try_next() => result.map_err(|_| ProviderError::Network("Identity token response was interrupted".into()))?,
        };
        match next {
            Some(chunk) => {
                if bytes
                    .len()
                    .checked_add(chunk.len())
                    .filter(|total| *total <= limit)
                    .is_none()
                {
                    return Err(ProviderError::Auth(
                        "Identity token response exceeded the size limit".into(),
                    ));
                }
                bytes.extend_from_slice(&chunk);
            }
            None => return Ok(bytes),
        }
    }
}

async fn send_text(
    socket: &mut GatewaySocket,
    bytes: Vec<u8>,
    cancel: &CancellationToken,
) -> Result<(), ProviderError> {
    if bytes.len() > MAX_REQUEST_FRAME_BYTES {
        return Err(ProviderError::Other(
            "Gateway request exceeds the frame limit".into(),
        ));
    }
    let text = String::from_utf8(bytes).map_err(|_| protocol_error())?;
    tokio::select! {
        _ = cancel.cancelled() => Err(ProviderError::Cancelled),
        result = socket.send(WsMessage::Text(text.into())) => result.map_err(|_| gateway_network_error()),
    }
}

async fn send_cancel(socket: &mut GatewaySocket, request_id: &str) {
    let bytes = serde_json::to_vec(&json!({ "event": "request.cancel", "requestId": request_id }));
    if let Ok(bytes) = bytes {
        if let Ok(text) = String::from_utf8(bytes) {
            let _ = socket.send(WsMessage::Text(text.into())).await;
        }
    }
}

fn identity_http_error(status: u16) -> ProviderError {
    match status {
        401 | 403 => ProviderError::Auth("Identity rejected the machine client".into()),
        429 => ProviderError::RateLimited {
            retry_after_ms: None,
        },
        500..=599 => ProviderError::Network("Identity token service is unavailable".into()),
        _ => ProviderError::Api("Identity rejected the machine token request".into()),
    }
}

fn map_gateway_error(code: &str) -> ProviderError {
    match code {
        "unauthorized" | "forbidden" | "credential_invalid" | "session_expired" => {
            ProviderError::Auth("Gateway authorization or credential check failed".into())
        }
        "upstream_rate_limited" | "overloaded" => ProviderError::RateLimited {
            retry_after_ms: None,
        },
        "cancelled" => ProviderError::Cancelled,
        "upstream_timeout" => ProviderError::Network("Gateway request timed out".into()),
        "invalid_request" | "provider_disallowed" | "model_disallowed" => {
            ProviderError::Api("Gateway rejected the model request".into())
        }
        _ => ProviderError::Api("Gateway could not complete the model request".into()),
    }
}

fn map_parser_error(error: ProviderError) -> ProviderError {
    // Vendored parser errors are fixed, allowlisted descriptions. Do not pass
    // arbitrary input or provider-returned bodies through this boundary.
    match error {
        ProviderError::Other(_) | ProviderError::Api(_) => {
            ProviderError::Api("Gateway returned an invalid OpenAI stream".into())
        }
        other => other,
    }
}

fn protocol_error() -> ProviderError {
    ProviderError::Other("Gateway sent an invalid protocol frame".into())
}

fn gateway_network_error() -> ProviderError {
    ProviderError::Network("Gateway connection ended before a terminal response".into())
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
    use crate::config::CredentialEnvelope;
    use serde_json::json;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::net::TcpListener;
    use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};
    use url::Url;
    use wiremock::matchers::{body_string_contains, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const CLIENT_ID: &str = "native-client";
    const CLIENT_SECRET: &str = "native-secret:with spaces";
    const MACHINE_TOKEN: &str = "machine-token-fixture";

    fn test_config(identity: Url, gateway: Url) -> GatewayConfig {
        GatewayConfig {
            identity_url: identity,
            gateway_url: gateway,
            client_id: CLIENT_ID.into(),
            client_secret: SecretString::new(CLIENT_SECRET.into()),
            envelope: CredentialEnvelope {
                v: 1,
                alg: "A256GCM".into(),
                kid: "test-key".into(),
                credential_id: "cred_fixture".into(),
                user_id: "user_fixture".into(),
                project_id: "project_fixture".into(),
                provider: "openai".into(),
                exp: unix_now() + 3600,
                nonce: "AAAAAAAAAAAAAAAA".into(),
                ciphertext: "AAAAAAAAAAAAAAAAAAAAAA".into(),
            },
            provider_id: "openai".into(),
            model_alias: "coding-fast".into(),
        }
    }

    async fn identity_mock() -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/oauth/token"))
            .and(header(
                "authorization",
                basic_client_auth(CLIENT_ID, CLIENT_SECRET),
            ))
            .and(body_string_contains("grant_type=client_credentials"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": MACHINE_TOKEN,
                "token_type": "Bearer",
                "expires_in": 300
            })))
            .expect(1)
            .mount(&server)
            .await;
        server
    }

    async fn test_listener() -> (TcpListener, Url) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        (
            listener,
            Url::parse(&format!("ws://{address}/v1/socket")).unwrap(),
        )
    }

    fn test_stream_config(config: &GatewayConfig) -> StreamConfig {
        let mut stream = StreamConfig::new(config.model_alias.clone(), "placeholder-is-not-a-key");
        stream
            .messages
            .push(Message::user("use the authorized tools"));
        stream.model_config = Some(config.model_config());
        stream
    }

    #[allow(clippy::result_large_err)]
    async fn accept_gateway(
        listener: TcpListener,
        handshakes: Arc<AtomicUsize>,
    ) -> tokio_tungstenite::WebSocketStream<tokio::net::TcpStream> {
        let (stream, _) = listener.accept().await.expect("accept Gateway client");
        tokio_tungstenite::accept_hdr_async(
            stream,
            move |request: &Request, mut response: Response| {
                assert_eq!(request.uri().path(), "/v1/socket");
                assert_eq!(
                    request.headers().get("authorization").unwrap(),
                    &format!("Bearer {MACHINE_TOKEN}")
                );
                assert_eq!(
                    request.headers().get("sec-websocket-protocol").unwrap(),
                    "llm-proxy.v1"
                );
                handshakes.fetch_add(1, Ordering::SeqCst);
                response
                    .headers_mut()
                    .insert("sec-websocket-protocol", "llm-proxy.v1".parse().unwrap());
                Ok(response)
            },
        )
        .await
        .expect("complete Gateway WebSocket handshake")
    }

    fn ready_frame() -> Value {
        json!({
            "event": "session.ready",
            "protocol": 1,
            "connectionId": "conn_fixture",
            "maxInFlight": 1,
            "maxPayloadBytes": 1_048_576,
            "maxSessionSeconds": 300,
            "maxChunkBytes": MAX_CHUNK_BYTES,
            "ackWindow": ACK_WINDOW,
            "maxRequestFrameBytes": MAX_REQUEST_FRAME_BYTES,
            "maxResponseFrameBytes": MAX_RESPONSE_FRAME_BYTES,
            "tokenExpiresAt": unix_now() + 600,
        })
    }

    async fn send_json(
        socket: &mut tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>,
        value: Value,
    ) {
        socket
            .send(WsMessage::Text(value.to_string().into()))
            .await
            .expect("send Gateway frame");
    }

    async fn receive_json(
        socket: &mut tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>,
    ) -> Value {
        let message = tokio::time::timeout(Duration::from_secs(2), socket.next())
            .await
            .expect("Gateway client frame timeout")
            .expect("Gateway client closed")
            .expect("read Gateway client frame");
        match message {
            WsMessage::Text(text) => serde_json::from_str(&text).expect("valid client JSON frame"),
            other => panic!("unexpected Gateway client frame: {other:?}"),
        }
    }

    async fn receive_start(
        socket: &mut tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>,
    ) -> Value {
        let start = receive_json(socket).await;
        assert_eq!(start["event"], "request.start");
        assert_eq!(start["api"], "chat.completions");
        assert_eq!(start["provider"], "openai");
        assert_eq!(start["model"], "coding-fast");
        assert!(start["envelope"]["ciphertext"].is_string());
        assert!(start["payload"]["model"].is_null());
        assert!(start["payload"]["stream"].is_null());
        assert_eq!(
            start["payload"]["messages"][0]["content"],
            "use the authorized tools"
        );
        start
    }

    async fn send_chunk_and_check_ack(
        socket: &mut tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>,
        request_id: &str,
        seq: u64,
        data: &str,
    ) {
        send_json(
            socket,
            json!({
                "event": "response.chunk",
                "requestId": request_id,
                "seq": seq,
                "data": data,
            }),
        )
        .await;
        let ack = receive_json(socket).await;
        assert_eq!(ack["event"], "request.start");
        assert_eq!(ack["op"], "ack");
        assert_eq!(ack["requestId"], request_id);
        assert_eq!(ack["ackSeq"], seq);
    }

    #[tokio::test]
    async fn direct_gateway_stream_uses_machine_oauth_ack_and_reconstructs_tool_call() {
        let identity = identity_mock().await;
        let (listener, gateway_url) = test_listener().await;
        let handshakes = Arc::new(AtomicUsize::new(0));
        let server = tokio::spawn({
            let handshakes = handshakes.clone();
            async move {
                let mut socket = accept_gateway(listener, handshakes).await;
                send_json(&mut socket, ready_frame()).await;
                let start = receive_start(&mut socket).await;
                let request_id = start["requestId"].as_str().unwrap();
                let events = [
                    json!({
                        "id": "fixture",
                        "choices": [{ "index": 0, "delta": { "content": "hello " }, "finish_reason": null }],
                    }),
                    json!({
                        "id": "fixture",
                        "choices": [{ "index": 0, "delta": { "tool_calls": [{
                            "index": 0,
                            "id": "call_1",
                            "type": "function",
                            "function": { "name": "lookup", "arguments": "{\"q\":\"x\"}" },
                        }] }, "finish_reason": null }],
                    }),
                    json!({
                        "id": "fixture",
                        "choices": [{ "index": 0, "delta": {}, "finish_reason": "tool_calls" }],
                    }),
                ];
                let mut sse = events
                    .iter()
                    .map(|event| format!("data: {event}\n\n"))
                    .collect::<String>();
                sse.push_str("data: [DONE]\n\n");
                let split_at = 19;
                let fragments = [
                    &sse[..split_at],
                    &sse[split_at..64],
                    &sse[64..sse.len() / 2],
                    &sse[sse.len() / 2..],
                ];
                for (seq, fragment) in fragments.iter().enumerate() {
                    send_chunk_and_check_ack(&mut socket, request_id, seq as u64, fragment).await;
                }
                send_json(
                    &mut socket,
                    json!({
                        "event": "response.end",
                        "requestId": request_id,
                        "lastSeq": fragments.len() as i64 - 1,
                    }),
                )
                .await;
            }
        });
        let config = test_config(Url::parse(&identity.uri()).unwrap(), gateway_url);
        let provider = GatewayProvider::new(config).unwrap();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let result = tokio::time::timeout(
            Duration::from_secs(5),
            provider.stream(
                test_stream_config(&provider.config),
                tx,
                CancellationToken::new(),
            ),
        )
        .await
        .expect("bounded complete stream")
        .expect("successful complete stream");
        server.await.unwrap();
        identity.verify().await;
        assert_eq!(
            handshakes.load(Ordering::SeqCst),
            1,
            "one Gateway connection, no retry"
        );

        let serialized = serde_json::to_string(&result).unwrap();
        assert!(serialized.contains("hello "));
        assert!(serialized.contains("toolCall"));
        assert!(serialized.contains("call_1"));
        assert!(serialized.contains("lookup"));
        let mut done_events = 0;
        while let Ok(event) = rx.try_recv() {
            done_events += usize::from(matches!(event, StreamEvent::Done { .. }));
        }
        assert_eq!(done_events, 1);
    }

    #[tokio::test]
    async fn gateway_end_without_openai_done_is_not_success() {
        let identity = identity_mock().await;
        let (listener, gateway_url) = test_listener().await;
        let handshakes = Arc::new(AtomicUsize::new(0));
        let server = tokio::spawn({
            let handshakes = handshakes.clone();
            async move {
                let mut socket = accept_gateway(listener, handshakes).await;
                send_json(&mut socket, ready_frame()).await;
                let start = receive_start(&mut socket).await;
                let request_id = start["requestId"].as_str().unwrap();
                let incomplete = "data: {\"id\":\"fixture\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"partial\"},\"finish_reason\":\"stop\"}]}\n\n";
                send_chunk_and_check_ack(&mut socket, request_id, 0, incomplete).await;
                send_json(
                    &mut socket,
                    json!({
                        "event": "response.end",
                        "requestId": request_id,
                        "lastSeq": 0,
                    }),
                )
                .await;
            }
        });
        let config = test_config(Url::parse(&identity.uri()).unwrap(), gateway_url);
        let provider = GatewayProvider::new(config).unwrap();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let result = tokio::time::timeout(
            Duration::from_secs(5),
            provider.stream(
                test_stream_config(&provider.config),
                tx,
                CancellationToken::new(),
            ),
        )
        .await
        .expect("bounded incomplete stream");
        assert!(result.is_err());
        let mut done_events = 0;
        while let Ok(event) = rx.try_recv() {
            done_events += usize::from(matches!(event, StreamEvent::Done { .. }));
        }
        assert_eq!(done_events, 0);
        server.await.unwrap();
        identity.verify().await;
    }

    #[tokio::test]
    async fn websocket_close_before_terminal_is_reported_as_interruption() {
        let identity = identity_mock().await;
        let (listener, gateway_url) = test_listener().await;
        let handshakes = Arc::new(AtomicUsize::new(0));
        let server = tokio::spawn({
            let handshakes = handshakes.clone();
            async move {
                let mut socket = accept_gateway(listener, handshakes).await;
                send_json(&mut socket, ready_frame()).await;
                let _start = receive_start(&mut socket).await;
                socket.close(None).await.expect("close before terminal");
            }
        });
        let config = test_config(Url::parse(&identity.uri()).unwrap(), gateway_url);
        let provider = GatewayProvider::new(config).unwrap();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let result = tokio::time::timeout(
            Duration::from_secs(5),
            provider.stream(
                test_stream_config(&provider.config),
                tx,
                CancellationToken::new(),
            ),
        )
        .await
        .expect("bounded interrupted stream");
        assert!(matches!(result, Err(ProviderError::Network(_))));
        let mut done_events = 0;
        while let Ok(event) = rx.try_recv() {
            done_events += usize::from(matches!(event, StreamEvent::Done { .. }));
        }
        assert_eq!(done_events, 0);
        server.await.unwrap();
        identity.verify().await;
        assert_eq!(handshakes.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn gateway_error_is_sanitized_and_not_retried() {
        let identity = identity_mock().await;
        let (listener, gateway_url) = test_listener().await;
        let handshakes = Arc::new(AtomicUsize::new(0));
        let server = tokio::spawn({
            let handshakes = handshakes.clone();
            async move {
                let mut socket = accept_gateway(listener, handshakes).await;
                send_json(&mut socket, ready_frame()).await;
                let start = receive_start(&mut socket).await;
                send_json(
                    &mut socket,
                    json!({
                        "event": "response.error",
                        "requestId": start["requestId"],
                        "lastSeq": -1,
                        "code": "upstream_error",
                        "message": "secret-provider-detail-sentinel",
                        "upstreamStarted": true,
                        "retryable": true,
                    }),
                )
                .await;
            }
        });
        let config = test_config(Url::parse(&identity.uri()).unwrap(), gateway_url);
        let provider = GatewayProvider::new(config).unwrap();
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        let result = tokio::time::timeout(
            Duration::from_secs(5),
            provider.stream(
                test_stream_config(&provider.config),
                tx,
                CancellationToken::new(),
            ),
        )
        .await
        .expect("bounded failed stream");
        let error = result.unwrap_err();
        assert!(!error
            .to_string()
            .contains("secret-provider-detail-sentinel"));
        server.await.unwrap();
        identity.verify().await;
        assert_eq!(handshakes.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn cancellation_sends_request_cancel_and_disconnect_is_interruption() {
        let identity = identity_mock().await;
        let (listener, gateway_url) = test_listener().await;
        let handshakes = Arc::new(AtomicUsize::new(0));
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn({
            let handshakes = handshakes.clone();
            async move {
                let mut socket = accept_gateway(listener, handshakes).await;
                send_json(&mut socket, ready_frame()).await;
                let start = receive_start(&mut socket).await;
                started_tx.send(()).unwrap();
                let cancel = receive_json(&mut socket).await;
                assert_eq!(cancel["event"], "request.cancel");
                assert_eq!(cancel["requestId"], start["requestId"]);
            }
        });
        let config = test_config(Url::parse(&identity.uri()).unwrap(), gateway_url);
        let provider = GatewayProvider::new(config).unwrap();
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        let cancel = CancellationToken::new();
        let task = tokio::spawn({
            let provider = Arc::new(provider);
            let cancel = cancel.clone();
            async move {
                provider
                    .stream(test_stream_config(&provider.config), tx, cancel)
                    .await
            }
        });
        started_rx.await.unwrap();
        cancel.cancel();
        let result = tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(result, Err(ProviderError::Cancelled)));
        server.await.unwrap();
        identity.verify().await;
        assert_eq!(handshakes.load(Ordering::SeqCst), 1);
    }
}
