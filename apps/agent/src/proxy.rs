//! Bounded environment-proxy support for the native Gateway WebSocket client.
//!
//! WSS targets use an HTTP `CONNECT` tunnel when an applicable proxy variable
//! is configured. HTTPS proxies are deliberately rejected: this client does
//! not currently implement TLS to the proxy itself. TLS from the tunnel to the
//! Gateway is still performed and validated by tokio-tungstenite.

use std::env;
use std::net::IpAddr;
use std::time::Duration;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::handshake::client::Response;
use tokio_tungstenite::tungstenite::http::Request;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::{
    client_async_tls_with_config, connect_async_tls_with_config, MaybeTlsStream, WebSocketStream,
};
use url::Url;
use zeroize::{Zeroize, Zeroizing};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_CONNECT_RESPONSE_HEADERS: usize = 8 * 1024;
const MAX_PROXY_ENV_VALUE: usize = 8 * 1024;
const MAX_PROXY_URL: usize = 4 * 1024;
const MAX_PROXY_CREDENTIALS: usize = 2 * 1024;

/// Safe connection failures. The variants never retain the proxy URL, user
/// info, target URL, or a lower-level error string.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum ConnectError {
    #[error("Gateway WebSocket URL is invalid")]
    InvalidTarget,
    #[error("Configured environment proxy is invalid")]
    InvalidProxy,
    #[error("Configured proxy scheme is unsupported; use an http:// proxy")]
    UnsupportedProxyScheme,
    #[error("Gateway connection timed out")]
    Timeout,
    #[error("Could not connect to the Gateway")]
    ConnectionFailed,
    #[error("Environment proxy rejected the CONNECT tunnel")]
    ProxyRejected,
    #[error("Environment proxy returned an invalid CONNECT response")]
    ProxyResponseInvalid,
    #[error("Environment proxy response headers exceeded 8 KiB")]
    ProxyHeadersTooLarge,
    #[error("Gateway WebSocket handshake failed")]
    HandshakeFailed,
}

struct ProxyConfig {
    host: String,
    port: u16,
    authorization: Option<Zeroizing<String>>,
}

struct Target {
    host: String,
    port: u16,
}

/// Connect to a Gateway WebSocket, using environment HTTP CONNECT proxy
/// settings when configured. `HTTPS_PROXY`/`https_proxy` take precedence,
/// followed by `ALL_PROXY`/`all_proxy`; `HTTP_PROXY`/`http_proxy` are accepted
/// as a final fallback for local clients that use one proxy for all traffic.
///
/// Loopback targets and hosts matched by `NO_PROXY`/`no_proxy` connect directly.
/// Both the direct handshake and the complete proxy/tunnel/WebSocket handshake
/// are bounded to ten seconds.
pub async fn connect(
    mut request: Request<()>,
    config: WebSocketConfig,
) -> Result<(WebSocketStream<MaybeTlsStream<TcpStream>>, Response), ConnectError> {
    let target = parse_target(request.uri().to_string().as_str())?;
    let proxy = select_proxy(&target, system_environment_value)?;

    // Proxy-only headers must never leak to the Gateway, even if a caller
    // accidentally put one on its WebSocket request.
    request.headers_mut().remove("proxy-authorization");
    request.headers_mut().remove("proxy-connection");

    let result = timeout(CONNECT_TIMEOUT, async move {
        match proxy {
            Some(proxy) => connect_via_proxy(request, config, &target, proxy).await,
            None => connect_async_tls_with_config(request, Some(config), false, None)
                .await
                .map_err(|_| ConnectError::ConnectionFailed),
        }
    })
    .await
    .map_err(|_| ConnectError::Timeout)?;

    result.map_err(|error| match error {
        ConnectError::ConnectionFailed
        | ConnectError::ProxyRejected
        | ConnectError::ProxyResponseInvalid
        | ConnectError::ProxyHeadersTooLarge
        | ConnectError::InvalidProxy
        | ConnectError::UnsupportedProxyScheme
        | ConnectError::Timeout => error,
        _ => ConnectError::HandshakeFailed,
    })
}

fn system_environment_value(name: &str) -> Result<Option<String>, ConnectError> {
    match env::var_os(name) {
        None => Ok(None),
        Some(value) => value
            .into_string()
            .map(Some)
            .map_err(|_| ConnectError::InvalidProxy),
    }
}

fn select_proxy(
    target: &Target,
    mut environment_value: impl FnMut(&str) -> Result<Option<String>, ConnectError>,
) -> Result<Option<ProxyConfig>, ConnectError> {
    if is_loopback_host(&target.host) {
        return Ok(None);
    }

    for name in ["NO_PROXY", "no_proxy"] {
        if let Some(value) = read_bounded_env(&mut environment_value, name)? {
            if value
                .split(|character: char| character == ',' || character.is_ascii_whitespace())
                .filter(|entry| !entry.is_empty())
                .any(|entry| no_proxy_entry_matches(entry, &target.host, target.port))
            {
                return Ok(None);
            }
        }
    }

    for name in [
        "HTTPS_PROXY",
        "https_proxy",
        "ALL_PROXY",
        "all_proxy",
        "HTTP_PROXY",
        "http_proxy",
    ] {
        if let Some(value) = read_bounded_env(&mut environment_value, name)? {
            if !value.trim().is_empty() {
                return parse_proxy_url(&value).map(Some);
            }
        }
    }
    Ok(None)
}

fn read_bounded_env(
    environment_value: &mut impl FnMut(&str) -> Result<Option<String>, ConnectError>,
    name: &str,
) -> Result<Option<String>, ConnectError> {
    let value = environment_value(name)?;
    if value
        .as_ref()
        .is_some_and(|value| value.len() > MAX_PROXY_ENV_VALUE)
    {
        return Err(ConnectError::InvalidProxy);
    }
    Ok(value)
}

fn parse_target(value: &str) -> Result<Target, ConnectError> {
    let url = Url::parse(value).map_err(|_| ConnectError::InvalidTarget)?;
    if !matches!(url.scheme(), "wss" | "ws")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(ConnectError::InvalidTarget);
    }
    let host = url
        .host_str()
        .ok_or(ConnectError::InvalidTarget)?
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_owned();
    let port = url
        .port()
        .or_else(|| match url.scheme() {
            "wss" => Some(443),
            "ws" => Some(80),
            _ => None,
        })
        .ok_or(ConnectError::InvalidTarget)?;
    Ok(Target { host, port })
}

fn parse_proxy_url(raw: &str) -> Result<ProxyConfig, ConnectError> {
    if raw.len() > MAX_PROXY_URL {
        return Err(ConnectError::InvalidProxy);
    }
    let mut url = Url::parse(raw).map_err(|_| ConnectError::InvalidProxy)?;
    if url.scheme() != "http" {
        return Err(ConnectError::UnsupportedProxyScheme);
    }
    if url.host_str().is_none()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(ConnectError::InvalidProxy);
    }
    let host = url
        .host_str()
        .ok_or(ConnectError::InvalidProxy)?
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_owned();
    let port = url.port().unwrap_or(80);

    let has_credentials = !url.username().is_empty() || url.password().is_some();
    let authorization = if has_credentials {
        let mut username = Zeroizing::new(percent_decode(url.username())?);
        let mut password = Zeroizing::new(
            url.password()
                .map(percent_decode)
                .transpose()?
                .unwrap_or_default(),
        );
        if username
            .len()
            .saturating_add(password.len())
            .saturating_add(1)
            > MAX_PROXY_CREDENTIALS
            || username
                .iter()
                .chain(password.iter())
                .any(|byte| byte.is_ascii_control())
        {
            return Err(ConnectError::InvalidProxy);
        }
        let mut credentials =
            Zeroizing::new(Vec::with_capacity(username.len() + password.len() + 1));
        credentials.extend_from_slice(&username);
        credentials.push(b':');
        credentials.extend_from_slice(&password);
        username.zeroize();
        password.zeroize();
        Some(Zeroizing::new(format!(
            "Basic {}",
            STANDARD.encode(&*credentials)
        )))
    } else {
        None
    };

    // Remove user info from the parsed URL before it leaves this function.
    let _ = url.set_username("");
    let _ = url.set_password(None);

    Ok(ProxyConfig {
        host,
        port,
        authorization,
    })
}

fn percent_decode(value: &str) -> Result<Vec<u8>, ConnectError> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len() {
                decoded.zeroize();
                return Err(ConnectError::InvalidProxy);
            }
            let high = hex_value(bytes[index + 1]).ok_or(ConnectError::InvalidProxy)?;
            let low = hex_value(bytes[index + 2]).ok_or(ConnectError::InvalidProxy)?;
            decoded.push((high << 4) | low);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    Ok(decoded)
}

fn hex_value(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn no_proxy_entry_matches(entry: &str, host: &str, port: u16) -> bool {
    let entry = entry.trim();
    if entry == "*" {
        return true;
    }
    if entry.is_empty() {
        return false;
    }

    let (entry_host, entry_port) = split_no_proxy_host_port(entry);
    if entry_port.is_some_and(|expected| expected != port) {
        return false;
    }
    let entry_host = entry_host
        .strip_prefix("*.")
        .or_else(|| entry_host.strip_prefix('.'))
        .unwrap_or(entry_host)
        .trim_end_matches('.')
        .to_ascii_lowercase();
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    !entry_host.is_empty()
        && (host == entry_host
            || host
                .strip_suffix(&entry_host)
                .is_some_and(|prefix| prefix.ends_with('.')))
}

fn split_no_proxy_host_port(entry: &str) -> (&str, Option<u16>) {
    if let Some(rest) = entry.strip_prefix('[') {
        if let Some(end) = rest.find(']') {
            let host = &rest[..end];
            let suffix = &rest[end + 1..];
            if let Some(port) = suffix.strip_prefix(':') {
                return match port.parse() {
                    Ok(port) => (host, Some(port)),
                    Err(_) => (entry, None),
                };
            }
            if suffix.is_empty() {
                return (host, None);
            }
        }
        return (entry, None);
    }

    if entry.matches(':').count() == 1 {
        if let Some((host, port)) = entry.rsplit_once(':') {
            if let Ok(port) = port.parse::<u16>() {
                return (host, Some(port));
            }
        }
    }
    (entry, None)
}

fn is_loopback_host(host: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if host == "localhost" || host.ends_with(".localhost") {
        return true;
    }
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(address)) => address.octets()[0] == 127,
        Ok(IpAddr::V6(address)) => address.is_loopback(),
        Err(_) => false,
    }
}

async fn connect_via_proxy(
    mut request: Request<()>,
    config: WebSocketConfig,
    target: &Target,
    proxy: ProxyConfig,
) -> Result<(WebSocketStream<MaybeTlsStream<TcpStream>>, Response), ConnectError> {
    request.headers_mut().remove("proxy-authorization");
    request.headers_mut().remove("proxy-connection");
    let mut stream = TcpStream::connect((proxy.host.as_str(), proxy.port))
        .await
        .map_err(|_| ConnectError::ConnectionFailed)?;
    let authority = format_authority(&target.host, target.port);
    let mut connect_request = Zeroizing::new(format!(
        "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n"
    ));
    if let Some(authorization) = proxy.authorization.as_ref() {
        connect_request.push_str("Proxy-Authorization: ");
        connect_request.push_str(authorization);
        connect_request.push_str("\r\n");
    }
    connect_request.push_str("Proxy-Connection: Keep-Alive\r\n\r\n");
    stream
        .write_all(connect_request.as_bytes())
        .await
        .map_err(|_| ConnectError::ConnectionFailed)?;
    connect_request.zeroize();

    read_connect_response(&mut stream).await?;
    client_async_tls_with_config(request, stream, Some(config), None)
        .await
        .map_err(|_| ConnectError::HandshakeFailed)
}

fn format_authority(host: &str, port: u16) -> String {
    if host.parse::<std::net::Ipv6Addr>().is_ok() {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

async fn read_connect_response(stream: &mut TcpStream) -> Result<(), ConnectError> {
    let mut headers = Vec::with_capacity(512);
    loop {
        if headers.len() >= MAX_CONNECT_RESPONSE_HEADERS {
            return Err(ConnectError::ProxyHeadersTooLarge);
        }
        let mut byte = [0u8; 1];
        let read = stream
            .read(&mut byte)
            .await
            .map_err(|_| ConnectError::ProxyResponseInvalid)?;
        if read == 0 {
            return Err(ConnectError::ProxyResponseInvalid);
        }
        headers.push(byte[0]);
        if headers.ends_with(b"\r\n\r\n") {
            break;
        }
    }

    let first_line_end = headers
        .windows(2)
        .position(|window| window == b"\r\n")
        .ok_or(ConnectError::ProxyResponseInvalid)?;
    let status_line = std::str::from_utf8(&headers[..first_line_end])
        .map_err(|_| ConnectError::ProxyResponseInvalid)?;
    let mut fields = status_line.split_ascii_whitespace();
    let version = fields.next().ok_or(ConnectError::ProxyResponseInvalid)?;
    let status = fields.next().ok_or(ConnectError::ProxyResponseInvalid)?;
    if !matches!(version, "HTTP/1.0" | "HTTP/1.1") {
        return Err(ConnectError::ProxyResponseInvalid);
    }
    if status.parse::<u16>().ok() != Some(200) {
        return Err(ConnectError::ProxyRejected);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::{SinkExt, StreamExt};
    use std::collections::HashMap;
    use tokio::net::TcpListener;
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    use tokio_tungstenite::tungstenite::Message;

    fn target(value: &str) -> Target {
        parse_target(value).expect("valid websocket target")
    }

    fn env_map(values: &[(&str, &str)]) -> HashMap<String, String> {
        values
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect()
    }

    fn select_from_map(
        target: &Target,
        values: &HashMap<String, String>,
    ) -> Result<Option<ProxyConfig>, ConnectError> {
        select_proxy(target, |name| Ok(values.get(name).cloned()))
    }

    #[test]
    fn selects_case_variants_and_fallback_proxy_variables() {
        let gateway = target("wss://gateway.example.test/v1/socket");
        for (name, value) in [
            ("HTTPS_PROXY", "http://proxy-upper.test:8080"),
            ("https_proxy", "http://proxy-lower.test:8080"),
            ("ALL_PROXY", "http://proxy-all-upper.test:8080"),
            ("all_proxy", "http://proxy-all-lower.test:8080"),
            ("HTTP_PROXY", "http://proxy-http-upper.test:8080"),
            ("http_proxy", "http://proxy-http-lower.test:8080"),
        ] {
            let values = env_map(&[(name, value)]);
            let selected = select_from_map(&gateway, &values)
                .expect("valid proxy")
                .expect("proxy selected");
            assert_eq!(
                selected.host,
                Url::parse(value).unwrap().host_str().unwrap()
            );
        }

        let values = env_map(&[
            ("https_proxy", "http://proxy-lower.test:8080"),
            ("HTTPS_PROXY", "http://proxy-upper.test:8080"),
        ]);
        let selected = select_from_map(&gateway, &values).unwrap().unwrap();
        assert_eq!(selected.host, "proxy-upper.test");
    }

    #[test]
    fn honors_no_proxy_domains_ports_case_variants_and_loopback() {
        let values = env_map(&[
            ("HTTPS_PROXY", "http://proxy.example.test:8080"),
            ("NO_PROXY", "example.test:443,.internal.test"),
            ("no_proxy", "*.dev.test,[::1]:443"),
        ]);
        for target_url in [
            "wss://example.test/v1/socket",
            "wss://sub.example.test/v1/socket",
            "wss://api.internal.test/v1/socket",
            "wss://internal.test/v1/socket",
            "wss://service.dev.test/v1/socket",
            "wss://[::1]/v1/socket",
            "wss://127.0.0.1:9443/v1/socket",
            "wss://machine.localhost/v1/socket",
        ] {
            assert!(
                select_from_map(&target(target_url), &values)
                    .unwrap()
                    .is_none(),
                "expected proxy bypass for {target_url}"
            );
        }

        let wrong_port = target("wss://example.test:8443/v1/socket");
        assert!(select_from_map(&wrong_port, &values).unwrap().is_some());
    }

    #[test]
    fn unsupported_proxy_schemes_fail_without_exposing_userinfo() {
        let gateway = target("wss://gateway.example.test/v1/socket");
        let values = env_map(&[(
            "HTTPS_PROXY",
            "https://private-user:private-password@proxy.example.test:8443",
        )]);
        let error = match select_from_map(&gateway, &values) {
            Err(error) => error,
            Ok(_) => panic!("unsupported scheme should be rejected"),
        };
        assert_eq!(error, ConnectError::UnsupportedProxyScheme);
        let message = error.to_string();
        assert!(message.contains("unsupported"));
        assert!(!message.contains("private-user"));
        assert!(!message.contains("private-password"));
        assert!(!format!("{error:?}").contains("private-password"));
    }

    #[test]
    fn no_proxy_wildcard_bypasses_even_an_unsupported_proxy() {
        let gateway = target("wss://gateway.example.test/v1/socket");
        let values = env_map(&[
            (
                "HTTPS_PROXY",
                "socks5://private-user:private-password@proxy.test:1080",
            ),
            ("NO_PROXY", "*"),
        ]);
        assert!(select_from_map(&gateway, &values).unwrap().is_none());
    }

    #[tokio::test]
    #[allow(clippy::result_large_err)]
    async fn opens_a_websocket_through_mock_connect_proxy_with_basic_auth() {
        let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target_listener.local_addr().unwrap();
        let mut target_task = tokio::spawn(async move {
            let (stream, _) = target_listener.accept().await.unwrap();
            let mut socket = tokio_tungstenite::accept_hdr_async(
                stream,
                |request: &tokio_tungstenite::tungstenite::handshake::server::Request, response| {
                    assert!(!request.headers().contains_key("proxy-authorization"));
                    Ok(response)
                },
            )
            .await
            .unwrap();
            match socket.next().await.unwrap().unwrap() {
                Message::Text(text) if text == "ping" => {}
                other => panic!("unexpected WebSocket message: {other:?}"),
            }
            socket.send(Message::Text("pong".into())).await.unwrap();
        });

        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        let (request_sender, request_receiver) = tokio::sync::oneshot::channel();
        let mut proxy_task = tokio::spawn(async move {
            let (mut client, _) = proxy_listener.accept().await.unwrap();
            let request = read_test_headers(&mut client).await;
            let _ = request_sender.send(request);
            let mut upstream = TcpStream::connect(target_addr).await.unwrap();
            client
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await
                .unwrap();
            let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
        });

        let mut request = format!("ws://{target_addr}/v1/socket")
            .into_client_request()
            .unwrap();
        request.headers_mut().insert(
            "proxy-authorization",
            "Basic target-must-not-see-this".parse().unwrap(),
        );
        let proxy =
            parse_proxy_url(&format!("http://proxy-user:proxy-password@{proxy_addr}")).unwrap();
        let target = parse_target(request.uri().to_string().as_str()).unwrap();
        let (mut socket, _response) = timeout(
            Duration::from_secs(3),
            connect_via_proxy(request, WebSocketConfig::default(), &target, proxy),
        )
        .await
        .expect("local tunnel should be bounded")
        .expect("proxy and websocket handshake should succeed");

        let proxy_request = request_receiver.await.unwrap();
        let proxy_request = String::from_utf8(proxy_request).unwrap();
        assert!(proxy_request.starts_with(&format!(
            "CONNECT {target_addr} HTTP/1.1\r\nHost: {target_addr}\r\n"
        )));
        assert!(proxy_request.contains(&format!(
            "Proxy-Authorization: Basic {}\r\n",
            STANDARD.encode("proxy-user:proxy-password")
        )));
        assert!(!proxy_request.contains("private-password"));

        timeout(
            Duration::from_secs(2),
            socket.send(Message::Text("ping".into())),
        )
        .await
        .expect("WebSocket send should complete")
        .unwrap();
        match timeout(Duration::from_secs(2), socket.next())
            .await
            .expect("mock Gateway should reply through the CONNECT tunnel")
            .unwrap()
            .unwrap()
        {
            Message::Text(text) if text == "pong" => {}
            other => panic!("unexpected WebSocket reply: {other:?}"),
        }

        drop(socket);
        timeout(Duration::from_secs(2), &mut target_task)
            .await
            .expect("mock Gateway task should finish")
            .unwrap();
        timeout(Duration::from_secs(2), &mut proxy_task)
            .await
            .expect("proxy tunnel should close after the client disconnects")
            .unwrap();
    }

    #[tokio::test]
    async fn bounds_connect_response_headers_to_eight_kib() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let _ = stream
                .write_all(&vec![b'A'; MAX_CONNECT_RESPONSE_HEADERS + 1])
                .await;
        });
        let mut stream = TcpStream::connect(address).await.unwrap();
        assert_eq!(
            read_connect_response(&mut stream).await.unwrap_err(),
            ConnectError::ProxyHeadersTooLarge
        );
        server.await.unwrap();
    }

    async fn read_test_headers(stream: &mut TcpStream) -> Vec<u8> {
        let mut headers = Vec::new();
        loop {
            let mut byte = [0; 1];
            if stream.read_exact(&mut byte).await.is_err() {
                break;
            }
            headers.push(byte[0]);
            if headers.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        headers
    }
}
