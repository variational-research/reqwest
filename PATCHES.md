# Proxy CONNECT diagnostics patch

Upstream: reqwest 0.12.12, git 8b8fdd2552ad645c7e9dd494930b3e95e2aedef2.
Published crate SHA-256: 43e734407157c3c2034e0258f5e4473ddb361b1e85f95a66690d67264d7cd1da.
Maintainers: Variational common/Pricing maintainers.

This fork retains the reqwest package name and version so consuming workspaces
can select it through a commit-pinned `[patch.crates-io]` entry without changing
reqwest type identity. Original source, licenses and tests are retained. The
committed Cargo.lock makes fork tests reproducible with rustls 0.23.45 and
rustls-webpki 0.103.15; consumers resolve dependencies through their own lockfile.

## APIs and limits

- `ClientBuilder::proxy_connect_diagnostics(bool)` defaults off. Enabled clients
  expose failed CONNECT responses through `Error::proxy_connect_response()` and
  successful responses through `Response::extensions().get::<ProxyConnectResponse>()`.
  Successful metadata belongs to the connection and survives pool reuse.
- `Proxy::connect_headers_for_host(host, headers)` validates the exact hostname
  and reserves authentication, Host, connection-management and framing headers.
  Custom headers are sent only on CONNECT for that destination, never as origin
  headers. Callers that need cooldown enforcement must control cross-origin
  redirects separately, because a redirect does not re-enter their middleware.
- `ProxyConnectResponse` exposes authority, status, reason, response headers, raw
  body prefix, completeness and `ProxyConnectBodyCapture`. Headers are bounded by
  an 8KiB head and 128 header fields; bodies by 1KiB and one 100ms read deadline
  inside the existing connection/request timeout. No transfer/content decoding
  occurs. Unsupported framing retains bounded raw bytes even when the body arrives
  separately. It reports `UnsupportedFraming` on framed completion/EOF, or the
  capture limit/deadline/read-error outcome; it cannot be considered complete text.
- Optional body-read errors/timeouts retain the original CONNECT rejection and
  its connect-error classification. Outer cancellation can still prevent a
  response record from being returned. A DEBUG event before body reads records
  authority, status and a validated single ProxyMesh exit IP. It never logs
  credentials, arbitrary headers, a reason phrase or a body. Generic Debug and
  Display also omit those raw fields.
- Successful CONNECT bytes buffered beyond the response head are replayed to TLS.
  Certificate/hostname validation remains enabled. A subsequent TLS error has no
  successful response extension and is not converted to a CONNECT rejection.
- Ordinary clients with diagnostics disabled and no custom CONNECT headers keep
  the original CONNECT parser and timing path. The option has no effect without TLS.

## Verification and upgrades

The focused `Proxy CONNECT` workflow runs for changes on the patch branch and
pull requests targeting it, using nightly-2026-01-22, the backend toolchain.
This checks the supported backend configuration; it does not establish the
upstream package's historical Rust 1.64 minimum with the modern test lockfile.
The inherited upstream CI workflow is retained unchanged.

Run from the repository root with that toolchain:

```sh
cargo test --locked --lib --no-default-features --features json,rustls-tls,gzip proxy_connect
cargo check --locked --no-default-features
cargo test --locked --lib --no-default-features --features native-tls,socks proxy_connect
```

Local validation passed all 10 Rustls and 8 native-TLS CONNECT tests, no-TLS
compilation and formatting. Strict Clippy reports 14 existing upstream warnings;
the same warnings reproduce on unmodified v0.12.12 with the same dependencies.
The coverage-gap check ran; generic I/O and tracing branches remain uncovered.

The localhost certificate and PKCS#8 key under `tests/support/proxy-connect*` are
public test-only fixtures with no production identity. They expire in 2036.
Never install them as production trust roots.

When upgrading, compare the source patch against the upstream git commit above.
Review changes in proxy.rs, proxy_connect.rs, connect.rs, error.rs, lib.rs,
async_impl/client.rs and the httparse manifest entry. Re-run both
TLS implementations, no-TLS compilation and the workspace dependency checks.
Newer reqwest releases moved CONNECT into hyper-util; do not mechanically apply
this patch without reviewing that connector boundary and all error classifications.
