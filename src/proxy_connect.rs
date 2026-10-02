//! Bounded CONNECT evidence. Raw response data is exposed only through accessors.
use std::fmt;

use http::{HeaderMap, StatusCode};

/// Outcome of capturing a raw CONNECT rejection body.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ProxyConnectBodyCapture {
    /// The complete identity-framed body was captured (or CONNECT succeeded).
    Complete,
    /// The body exceeded the limit, or ended before its declared length.
    Truncated,
    /// The optional body-read deadline elapsed; the original rejection remains.
    TimedOut,
    /// Reading the optional body failed; the original rejection remains.
    ReadError,
    /// Transfer/content encoding or invalid length prevents completeness checks.
    UnsupportedFraming,
}

/// A proxy response to CONNECT, distinct from the encrypted origin response.
#[derive(Clone)]
pub struct ProxyConnectResponse {
    target_authority: String,
    status: StatusCode,
    reason: String,
    headers: HeaderMap,
    body: Vec<u8>,
    body_capture: ProxyConnectBodyCapture,
}

impl ProxyConnectResponse {
    /// Destination authority of this CONNECT, without credentials or a path.
    pub fn target_authority(&self) -> &str {
        &self.target_authority
    }
    /// CONNECT response status; this is not an origin HTTP status.
    pub fn status(&self) -> StatusCode {
        self.status
    }
    /// Proxy-supplied reason phrase. Treat as untrusted data.
    pub fn reason(&self) -> &str {
        &self.reason
    }
    /// Response headers, bounded by an 8KiB response-head limit.
    pub fn headers(&self) -> &HeaderMap {
        &self.headers
    }
    /// At most 1KiB of raw body bytes; transfer encodings are not decoded.
    pub fn body(&self) -> &[u8] {
        &self.body
    }
    /// Whether the complete, identity-framed body was captured.
    pub fn body_complete(&self) -> bool {
        self.body_capture == ProxyConnectBodyCapture::Complete
    }
    /// Capture outcome, distinct from the original CONNECT rejection.
    pub fn body_capture(&self) -> ProxyConnectBodyCapture {
        self.body_capture
    }
}

impl fmt::Debug for ProxyConnectResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProxyConnectResponse")
            .field("target_authority", &self.target_authority)
            .field("status", &self.status)
            .field("body_bytes", &self.body.len())
            .field("body_capture", &self.body_capture)
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
pub(crate) struct Rejection(pub(crate) ProxyConnectResponse);
impl fmt::Display for Rejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0.status == StatusCode::PROXY_AUTHENTICATION_REQUIRED {
            write!(f, "proxy authentication required (CONNECT 407)")
        } else {
            write!(
                f,
                "unsuccessful tunnel (CONNECT {})",
                self.0.status.as_u16()
            )
        }
    }
}
impl std::error::Error for Rejection {}

#[cfg(feature = "__tls")]
pub(crate) use transport::{connect, Tunnel};

#[cfg(feature = "__tls")]
mod transport {
    use std::{
        io,
        pin::Pin,
        task::{Context, Poll},
        time::Duration,
    };

    use http::header::{CONTENT_ENCODING, CONTENT_LENGTH, TRANSFER_ENCODING};
    use hyper::rt::{Read, ReadBufCursor, Write};
    use hyper_util::{
        client::legacy::connect::{Connected, Connection},
        rt::TokioIo,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;
    use crate::error::BoxError;

    const HEAD_LIMIT: usize = 8192;
    const BODY_LIMIT: usize = 1024;
    const BODY_DEADLINE: Duration = Duration::from_millis(100);

    // Preserve any bytes following a successful response head for the TLS stack.
    pub(crate) struct Tunnel<T> {
        inner: T,
        prefix: bytes::Bytes,
    }
    impl<T> Tunnel<T> {
        pub(crate) fn new(inner: T, prefix: Vec<u8>) -> Self {
            Self {
                inner,
                prefix: prefix.into(),
            }
        }
    }
    impl<T: Connection> Connection for Tunnel<T> {
        fn connected(&self) -> Connected {
            self.inner.connected()
        }
    }
    impl<T: Read + Unpin> Read for Tunnel<T> {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            mut buf: ReadBufCursor<'_>,
        ) -> Poll<io::Result<()>> {
            if !self.prefix.is_empty() {
                let count = buf.remaining().min(self.prefix.len());
                buf.put_slice(&self.prefix.split_to(count));
                return Poll::Ready(Ok(()));
            }
            Pin::new(&mut self.inner).poll_read(cx, buf)
        }
    }
    impl<T: Write + Unpin> Write for Tunnel<T> {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.inner).poll_write(cx, buf)
        }
        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_flush(cx)
        }
        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_shutdown(cx)
        }
        fn is_write_vectored(&self) -> bool {
            self.inner.is_write_vectored()
        }
        fn poll_write_vectored(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            bufs: &[io::IoSlice<'_>],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
        }
    }

    pub(crate) async fn connect<T: Read + Write + Unpin>(
        conn: T,
        host: String,
        port: u16,
        user_agent: Option<http::HeaderValue>,
        auth: Option<http::HeaderValue>,
        headers: Option<HeaderMap>,
        diagnostics: bool,
    ) -> Result<(Tunnel<T>, Option<ProxyConnectResponse>), BoxError> {
        let authority = format!("{host}:{port}");
        let mut request =
            format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n").into_bytes();
        for (name, value) in [("User-Agent", user_agent), ("Proxy-Authorization", auth)] {
            if let Some(value) = value {
                append_header(&mut request, name, &value);
            }
        }
        if let Some(headers) = headers {
            for (name, value) in &headers {
                append_header(&mut request, name.as_str(), value);
            }
        }
        request.extend_from_slice(b"\r\n");
        let mut conn = TokioIo::new(conn);
        conn.write_all(&request).await?;
        let mut buffer = [0u8; HEAD_LIMIT];
        let mut used = 0;
        let (head_end, mut response) = loop {
            if used == HEAD_LIMIT {
                return Err("proxy headers too long for tunnel".into());
            }
            let count = conn.read(&mut buffer[used..]).await?;
            if count == 0 {
                return Err("unexpected eof while tunneling".into());
            }
            used += count;
            let mut header_slots = [httparse::EMPTY_HEADER; 128];
            let mut parsed = httparse::Response::new(&mut header_slots);
            let head_end = match parsed.parse(&buffer[..used])? {
                httparse::Status::Partial => continue,
                httparse::Status::Complete(end) => end,
            };
            let mut headers = HeaderMap::new();
            for header in parsed.headers {
                headers.append(
                    http::header::HeaderName::from_bytes(header.name.as_bytes())?,
                    http::HeaderValue::from_bytes(header.value)?,
                );
            }
            break (
                head_end,
                ProxyConnectResponse {
                    target_authority: authority,
                    status: StatusCode::from_u16(parsed.code.ok_or("missing CONNECT status")?)?,
                    reason: parsed.reason.unwrap_or_default().to_owned(),
                    headers,
                    body: Vec::new(),
                    body_capture: ProxyConnectBodyCapture::Complete,
                },
            );
        };
        if diagnostics {
            // Record the head before optional reads can be cancelled by the outer deadline.
            let mut values = response.headers.get_all("x-proxymesh-ip").iter();
            let exit_ip = values
                .next()
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse::<std::net::IpAddr>().ok())
                .filter(|_| values.next().is_none());
            log::debug!(
                "proxy CONNECT response target={} status={} exit_ip={:?}",
                response.target_authority,
                response.status.as_u16(),
                exit_ip
            );
        }
        if response.status == StatusCode::OK {
            return Ok((
                Tunnel::new(conn.into_inner(), buffer[head_end..used].to_vec()),
                diagnostics.then_some(response),
            ));
        }
        if !diagnostics {
            return Err(
                if response.status == StatusCode::PROXY_AUTHENTICATION_REQUIRED {
                    "proxy authentication required"
                } else {
                    "unsuccessful tunnel"
                }
                .into(),
            );
        }
        let initial = &buffer[head_end..used];
        response
            .body
            .extend_from_slice(&initial[..initial.len().min(BODY_LIMIT)]);
        let lengths: Vec<_> = response.headers.get_all(CONTENT_LENGTH).iter().collect();
        let length = if lengths.len() == 1 {
            lengths[0]
                .to_str()
                .ok()
                .and_then(|v| v.parse::<usize>().ok())
        } else {
            None
        };
        let unsupported = response.headers.contains_key(TRANSFER_ENCODING)
            || response
                .headers
                .get_all(CONTENT_ENCODING)
                .iter()
                .any(|v| !v.as_bytes().eq_ignore_ascii_case(b"identity"))
            || (!lengths.is_empty() && length.is_none());
        // Content-Length bounds encoded wire bytes too, but Transfer-Encoding
        // overrides it. Unknown framing still permits bounded raw diagnostics.
        let length = length.filter(|_| !response.headers.contains_key(TRANSFER_ENCODING));
        let complete = if unsupported {
            ProxyConnectBodyCapture::UnsupportedFraming
        } else {
            ProxyConnectBodyCapture::Complete
        };
        let deadline = tokio::time::Instant::now() + BODY_DEADLINE;
        response.body_capture = loop {
            if let Some(length) = length {
                if initial.len() > length {
                    break ProxyConnectBodyCapture::UnsupportedFraming;
                }
                if response.body.len() == length {
                    break complete;
                }
            }
            if response.body.len() == BODY_LIMIT {
                break ProxyConnectBodyCapture::Truncated;
            }
            let mut chunk = [0u8; BODY_LIMIT];
            let remaining = (BODY_LIMIT - response.body.len())
                .min(length.map_or(BODY_LIMIT, |n| n.saturating_sub(response.body.len())));
            match tokio::time::timeout_at(deadline, conn.read(&mut chunk[..remaining])).await {
                Err(_) => break ProxyConnectBodyCapture::TimedOut,
                Ok(Err(_)) => break ProxyConnectBodyCapture::ReadError,
                Ok(Ok(0)) => {
                    break if length.is_none() {
                        complete
                    } else {
                        ProxyConnectBodyCapture::Truncated
                    }
                }
                Ok(Ok(count)) => response.body.extend_from_slice(&chunk[..count]),
            }
        };
        Err(Box::new(Rejection(response)))
    }

    fn append_header(buffer: &mut Vec<u8>, name: &str, value: &http::HeaderValue) {
        buffer.extend_from_slice(name.as_bytes());
        buffer.extend_from_slice(b": ");
        buffer.extend_from_slice(value.as_bytes());
        buffer.extend_from_slice(b"\r\n");
    }
}

#[cfg(all(test, feature = "__tls"))]
mod proxy_connect_tests {
    #[cfg(feature = "__rustls")]
    use std::sync::Arc;
    use std::time::Duration;

    use hyper_util::rt::TokioIo;
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};

    use super::*;
    use crate::proxy_connect::transport::connect;

    async fn head<T: AsyncRead + Unpin>(io: &mut T) -> Vec<u8> {
        let mut bytes = Vec::new();
        while !bytes.ends_with(b"\r\n\r\n") {
            bytes.push(io.read_u8().await.unwrap());
            assert!(bytes.len() < 8192);
        }
        bytes
    }

    async fn capture(
        parts: Vec<Vec<u8>>,
        hold: bool,
    ) -> Result<ProxyConnectResponse, crate::error::BoxError> {
        let (client, mut server) = tokio::io::duplex(16384);
        let task = tokio::spawn(async move {
            head(&mut server).await;
            for part in parts {
                server.write_all(&part).await.unwrap();
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
            if hold {
                std::future::pending::<()>().await;
            }
        });
        let result = connect(
            TokioIo::new(client),
            "example.com".into(),
            443,
            None,
            None,
            None,
            true,
        )
        .await;
        task.abort();
        match result {
            Ok((_, response)) => Ok(response.unwrap()),
            Err(error) => match error.downcast::<Rejection>() {
                Ok(error) => Ok(error.0),
                Err(error) => Err(error),
            },
        }
    }

    #[tokio::test]
    async fn proxy_connect_fragmented_statuses_and_redaction() {
        for status in [407, 408, 500, 502, 503, 504] {
            let response = capture(vec![b"HT".to_vec(), format!("TP/1.1 {status} SecretReason\r\nX-ProxyMesh-IP: 192.0.2.1\r\nX-Secret: secret-header\r\nContent-Length: 11\r\n\r\nsecret-body").into_bytes()], false).await.unwrap();
            assert_eq!(response.status().as_u16(), status);
            assert_eq!(response.reason(), "SecretReason");
            assert_eq!(response.target_authority(), "example.com:443");
            assert_eq!(response.headers()["x-proxymesh-ip"], "192.0.2.1");
            assert_eq!(response.body(), b"secret-body");
            assert!(response.body_complete());
            let error = Rejection(response);
            let displayed = format!("{error:?} {error}");
            for secret in ["secret-body", "secret-header", "SecretReason"] {
                assert!(!displayed.contains(secret));
            }
            if status == 407 {
                assert!(displayed.contains("proxy authentication required"));
            }
        }
    }

    #[tokio::test]
    async fn proxy_connect_capture_limits_and_framing() {
        let cases: Vec<(Vec<u8>, bool, ProxyConnectBodyCapture)> = vec![
            (
                b"HTTP/1.1 503 Failure\r\nContent-Length: 0\r\n\r\n".to_vec(),
                true,
                ProxyConnectBodyCapture::Complete,
            ),
            (
                b"HTTP/1.1 503 Failure\r\n\r\nclose-framed".to_vec(),
                false,
                ProxyConnectBodyCapture::Complete,
            ),
            (
                b"HTTP/1.1 503 Failure\r\nContent-Length: 10\r\n\r\nshort".to_vec(),
                false,
                ProxyConnectBodyCapture::Truncated,
            ),
            (
                b"HTTP/1.1 503 Failure\r\nContent-Length: 10\r\n\r\nshort".to_vec(),
                true,
                ProxyConnectBodyCapture::TimedOut,
            ),
            (
                b"HTTP/1.1 503 Failure\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n"
                    .to_vec(),
                false,
                ProxyConnectBodyCapture::UnsupportedFraming,
            ),
            (
                b"HTTP/1.1 503 Failure\r\nContent-Encoding: gzip\r\nContent-Length: 3\r\n\r\nabc"
                    .to_vec(),
                true,
                ProxyConnectBodyCapture::UnsupportedFraming,
            ),
            (
                b"HTTP/1.1 503 Failure\r\nContent-Length: invalid\r\n\r\nabc".to_vec(),
                false,
                ProxyConnectBodyCapture::UnsupportedFraming,
            ),
            (
                b"HTTP/1.1 503 Failure\r\nContent-Length: 3\r\nContent-Length: 3\r\n\r\nabc"
                    .to_vec(),
                false,
                ProxyConnectBodyCapture::UnsupportedFraming,
            ),
            (
                [
                    b"HTTP/1.1 503 Failure\r\nContent-Length: 2000\r\n\r\n".as_slice(),
                    &[b'a'; 2000],
                ]
                .concat(),
                true,
                ProxyConnectBodyCapture::Truncated,
            ),
        ];
        for (bytes, hold, expected) in cases {
            let response = capture(vec![bytes], hold).await.unwrap();
            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(response.body_capture(), expected);
            assert!(response.body().len() <= 1024);
        }
        for bytes in [
            b"NOT HTTP\r\n\r\n".to_vec(),
            [b"HTTP/1.1 200 OK\r\nHuge: ".as_slice(), &[b'x'; 8192]].concat(),
        ] {
            assert!(capture(vec![bytes], false).await.is_err());
        }
    }

    #[tokio::test]
    async fn proxy_connect_encoded_bodies_after_separate_head_are_captured() {
        for (headers, body) in [
            (
                "Content-Encoding: gzip\r\nContent-Length: 3",
                b"abc".as_slice(),
            ),
            (
                "Transfer-Encoding: chunked",
                b"3\r\nabc\r\n0\r\n\r\n".as_slice(),
            ),
            ("Content-Length: invalid", b"raw-unknown-length".as_slice()),
        ] {
            let response = capture(
                vec![
                    format!("HTTP/1.1 503 Failure\r\n{headers}\r\n\r\n").into_bytes(),
                    body.to_vec(),
                ],
                false,
            )
            .await
            .unwrap();
            assert_eq!(response.body(), body);
            assert_eq!(
                response.body_capture(),
                ProxyConnectBodyCapture::UnsupportedFraming
            );
            assert!(!response.body_complete());
        }
        let response = capture(
            vec![
                b"HTTP/1.1 503 Failure\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec(),
                b"3\r\nabc\r\n".to_vec(),
            ],
            true,
        )
        .await
        .unwrap();
        assert_eq!(response.body(), b"3\r\nabc\r\n");
        assert_eq!(response.body_capture(), ProxyConnectBodyCapture::TimedOut);
        assert!(!response.body_complete());
    }

    #[tokio::test]
    async fn proxy_connect_trickle_has_one_body_deadline() {
        let (client, mut server) = tokio::io::duplex(1024);
        let task = tokio::spawn(async move {
            head(&mut server).await;
            server
                .write_all(b"HTTP/1.1 503 Failure\r\nContent-Length: 100\r\n\r\n")
                .await
                .unwrap();
            for _ in 0..100 {
                tokio::time::sleep(Duration::from_millis(20)).await;
                if server.write_all(b"x").await.is_err() {
                    break;
                }
            }
        });
        let result = tokio::time::timeout(
            Duration::from_millis(400),
            connect(
                TokioIo::new(client),
                "example.com".into(),
                443,
                None,
                None,
                None,
                true,
            ),
        )
        .await
        .unwrap();
        let error = result.err().unwrap().downcast::<Rejection>().unwrap();
        assert_eq!(error.0.body_capture(), ProxyConnectBodyCapture::TimedOut);
        assert!(!error.0.body().is_empty());
        task.abort();
    }

    #[tokio::test]
    async fn proxy_connect_preserves_tunnel_bytes() {
        let (client, mut server) = tokio::io::duplex(1024);
        let task = tokio::spawn(async move {
            head(&mut server).await;
            server
                .write_all(b"HTTP/1.1 200 OK\r\nX-ProxyMesh-IP: 192.0.2.2\r\n\r\ntunnel-bytes")
                .await
                .unwrap();
        });
        let (io, response) = connect(
            TokioIo::new(client),
            "example.com".into(),
            443,
            None,
            None,
            None,
            true,
        )
        .await
        .unwrap();
        assert_eq!(response.unwrap().headers()["x-proxymesh-ip"], "192.0.2.2");
        let mut bytes = Vec::new();
        TokioIo::new(io).read_to_end(&mut bytes).await.unwrap();
        assert_eq!(bytes, b"tunnel-bytes");
        task.await.unwrap();
    }

    #[test]
    fn proxy_connect_headers_are_scoped_and_reserved() {
        let mut headers = HeaderMap::new();
        headers.insert("x-proxymesh-not-ip", "192.0.2.1".parse().unwrap());
        let proxy = crate::Proxy::all("http://localhost:8080")
            .unwrap()
            .connect_headers_for_host("EXAMPLE.com", headers)
            .unwrap();
        assert!(proxy
            .connect_headers(&"https://example.com/".parse().unwrap())
            .is_some());
        assert!(proxy
            .connect_headers(&"https://other.com/".parse().unwrap())
            .is_none());
        assert!(!format!("{proxy:?}").contains("192.0.2.1"));
        for name in [
            "host",
            "proxy-authorization",
            "authorization",
            "connection",
            "proxy-connection",
            "content-length",
            "transfer-encoding",
            "te",
            "trailer",
            "upgrade",
            "keep-alive",
        ] {
            let mut headers = HeaderMap::new();
            headers.insert(
                http::header::HeaderName::from_static(name),
                "secret".parse().unwrap(),
            );
            assert!(proxy
                .clone()
                .connect_headers_for_host("example.com", headers)
                .is_err());
        }
        for host in [
            "",
            "example.com:443",
            "https://example.com",
            "user@example.com",
            "example.com/path",
        ] {
            assert!(proxy
                .clone()
                .connect_headers_for_host(host, HeaderMap::new())
                .is_err());
        }
    }

    #[tokio::test]
    async fn proxy_connect_public_error_and_disabled_path() {
        for diagnostics in [false, true] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let task = tokio::spawn(async move {
                let (mut socket, _) = listener.accept().await.unwrap();
                let request = String::from_utf8(head(&mut socket).await).unwrap();
                assert!(request
                    .to_ascii_lowercase()
                    .contains("proxy-authorization: basic "));
                socket.write_all(b"HTTP/1.1 503 Failure\r\nX-ProxyMesh-IP: 192.0.2.1\r\nContent-Length: 10\r\n\r\nshort").await.unwrap();
                std::future::pending::<()>().await;
            });
            let client = crate::Client::builder()
                .proxy_connect_diagnostics(diagnostics)
                .proxy(
                    crate::Proxy::all(format!("http://{address}"))
                        .unwrap()
                        .basic_auth("test-user", "test-secret"),
                )
                .connect_timeout(Duration::from_secs(2))
                .build()
                .unwrap();
            let error = client.get("https://example.com/").send().await.unwrap_err();
            assert!(error.is_connect());
            assert!(!error.is_timeout());
            assert!(!error.is_status());
            assert_eq!(error.proxy_connect_response().is_some(), diagnostics);
            if let Some(info) = error.proxy_connect_response() {
                assert_eq!(info.body_capture(), ProxyConnectBodyCapture::TimedOut);
                assert_eq!(info.status(), StatusCode::SERVICE_UNAVAILABLE);
            }
            assert!(!format!("{error:?}").contains("test-secret"));
            task.abort();
        }
    }

    #[tokio::test]
    async fn proxy_connect_outer_timeout_preserved() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            head(&mut socket).await;
            std::future::pending::<()>().await;
        });
        let client = crate::Client::builder()
            .proxy_connect_diagnostics(true)
            .proxy(crate::Proxy::all(format!("http://{address}")).unwrap())
            .connect_timeout(Duration::from_millis(30))
            .build()
            .unwrap();
        let error = client.get("https://example.com/").send().await.unwrap_err();
        assert!(error.is_connect());
        assert!(error.is_timeout());
        assert!(error.proxy_connect_response().is_none());
        task.abort();
    }

    #[cfg(feature = "__rustls")]
    async fn tls_proxy(requests: usize) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
        let cert =
            CertificateDer::from(include_bytes!("../tests/support/proxy-connect.der").to_vec());
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            include_bytes!("../tests/support/proxy-connect-key.der").to_vec(),
        ));
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let request = String::from_utf8(head(&mut socket).await)
                .unwrap()
                .to_ascii_lowercase();
            assert!(request.starts_with("connect "));
            if requests == 2 {
                assert!(request.contains("x-proxymesh-not-ip: 192.0.2.1"));
            }
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nX-ProxyMesh-IP: 192.0.2.9\r\n\r\n")
                .await
                .unwrap();
            let Ok(mut socket) = acceptor.accept(socket).await else {
                return;
            };
            for _ in 0..requests {
                let request = String::from_utf8(head(&mut socket).await)
                    .unwrap()
                    .to_ascii_lowercase();
                assert!(!request.contains("x-proxymesh-not-ip"));
                assert!(!request.contains("proxy-authorization"));
                socket
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                    .await
                    .unwrap();
            }
        });
        (address, task)
    }

    #[cfg(feature = "__rustls")]
    #[tokio::test]
    async fn proxy_connect_verified_tls_metadata_pooling_and_no_origin_leak() {
        let (address, task) = tls_proxy(2).await;
        let mut headers = HeaderMap::new();
        headers.insert("x-proxymesh-not-ip", "192.0.2.1".parse().unwrap());
        let proxy = crate::Proxy::all(format!("http://{address}"))
            .unwrap()
            .connect_headers_for_host("localhost", headers)
            .unwrap();
        let client = crate::Client::builder()
            .use_rustls_tls()
            .http1_only()
            .proxy(proxy)
            .proxy_connect_diagnostics(true)
            .add_root_certificate(
                crate::Certificate::from_der(include_bytes!("../tests/support/proxy-connect.der"))
                    .unwrap(),
            )
            .timeout(Duration::from_secs(2))
            .build()
            .unwrap();
        for _ in 0..2 {
            let response = client.get("https://localhost/").send().await.unwrap();
            let info = response.extensions().get::<ProxyConnectResponse>().unwrap();
            assert_eq!(info.status(), StatusCode::OK);
            assert_eq!(info.headers()["x-proxymesh-ip"], "192.0.2.9");
            assert!(info.body().is_empty());
            assert_eq!(response.text().await.unwrap(), "ok");
        }
        task.await.unwrap();
    }

    #[cfg(feature = "__rustls")]
    #[tokio::test]
    async fn proxy_connect_does_not_bypass_tls_verification() {
        for trusted in [false, true] {
            let (address, task) = tls_proxy(0).await;
            let mut builder = crate::Client::builder()
                .use_rustls_tls()
                .proxy_connect_diagnostics(true)
                .proxy(crate::Proxy::all(format!("http://{address}")).unwrap())
                .timeout(Duration::from_secs(2));
            if trusted {
                builder = builder.add_root_certificate(
                    crate::Certificate::from_der(include_bytes!(
                        "../tests/support/proxy-connect.der"
                    ))
                    .unwrap(),
                );
            }
            let host = if trusted {
                "wrong-host.invalid"
            } else {
                "localhost"
            };
            let error = builder
                .build()
                .unwrap()
                .get(format!("https://{host}/"))
                .send()
                .await
                .unwrap_err();
            assert!(error.is_connect());
            assert!(error.proxy_connect_response().is_none());
            task.await.unwrap();
        }
    }
}
