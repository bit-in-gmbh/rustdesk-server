# Changelog

## Fork Changes

### Added — Management Policy Hook

Added a connection authorization policy hook to `hbbs`.

The policy is evaluated for TCP:

- `PunchHoleRequest`
- `RequestRelay`

The following information is submitted to the configured policy endpoint:

- Account access token
- Target ID
- Connection type
- Source IP address
- Relay request UUID for `RequestRelay`

Configuration:

```text
POLICY_MODE=off|observe|enforce
POLICY_ENDPOINT=http://127.0.0.1:8081/internal/v1/connection-authorizations
POLICY_SERVICE_TOKEN_FILE=/run/secrets/hbbs-policy-token
POLICY_TIMEOUT_MS=300
POLICY_INSTANCE_ID=hbbs-1
```

Policy modes:

- `off` — Policy checks are disabled.
- `observe` — Policy checks are performed, but denied or failed checks do not reject the connection.
- `enforce` — Connections are rejected on explicit deny responses, timeouts, connection failures, HTTP errors, or invalid responses.

Policy decisions are not retried or cached.

Compatibility was verified against RustDesk Client `1.4.6`, tag commit `1abc897c451c8b5bbff3792509a7fef9d12f2ce3`.

The client provides:

- Account access token
- Target ID
- Connection type

through `PunchHoleRequest`.

For relay requests, `RequestRelay.uuid` is used as the relay request ID. An unset relay connection type is interpreted as `remote_desktop`.

### Added — Secure TCP

Added support for the RustDesk `KeyExchange` protocol on protobuf-framed TCP connections handled by `hbbs`.

Protocol behavior by port:

- `21115/TCP` — Optional Secure TCP negotiation for NAT testing and online queries. RustDesk Client `1.4.6` continues to use the compatible plaintext path.
- `21116/TCP` — Secure TCP negotiation for rendezvous connections, including `PunchHoleRequest` and `RequestRelay`.
- `21116/UDP` — No Secure TCP negotiation.
- `21118/TCP` — No Secure TCP negotiation for WebSocket connections. **Use WebSocket** remains disabled in this fork.
- Local text commands on `21115/TCP` remain unchanged.

Each Secure TCP connection uses a new ephemeral `box_` key pair. The server signs its ephemeral public key using the persistent Ed25519 server key. The client responds with its ephemeral public key and the authenticated and encrypted `secretbox` key.

The implementation follows RustDesk Client `1.4.6` behavior:

- Protobuf framing/cardinality
- Zero nonce for `box_`
- Separate direction-specific counters starting at `1`
- `18` second handshake timeout

### Changed — Plaintext Compatibility

Plaintext compatibility is retained for existing OSS clients and tokenless requests.

Connection handling follows these rules:

- A normal message received before `KeyExchange` commits the connection to the compatible plaintext path.
- Tokenless OSS requests remain supported.
- A plaintext request containing an account access token on `21116/TCP` is closed before policy evaluation.
- No plaintext fallback is permitted after `KeyExchange` has started or failed.

## License

This fork remains licensed under the **GNU Affero General Public License v3.0 (AGPL-3.0)**.
