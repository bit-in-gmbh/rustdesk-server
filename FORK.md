# RustDesk Server Fork

Based on RustDesk Server OSS `1.1.16`, commit `73523b31cfd25d77dee862e6fc9f5e1fb5e485ef`.

## Management Policy Hook

`hbbs` invokes the management policy for TCP `PunchHoleRequest` and `RequestRelay` requests. The access token, target ID, connection type, source IP, and, for relay requests, the request UUID are sent to the policy endpoint.

Configuration:

```text
POLICY_MODE=off|observe|enforce
POLICY_ENDPOINT=http://127.0.0.1:8081/internal/v1/connection-authorizations
POLICY_SERVICE_TOKEN_FILE=/run/secrets/hbbs-policy-token
POLICY_TIMEOUT_MS=300
POLICY_INSTANCE_ID=hbbs-1
```

`observe` permits denied or failed checks. `enforce` rejects deny responses, timeouts, connection failures, HTTP errors, and invalid responses. There are no retries and no decision cache.

RustDesk Client `1.4.6`, tag commit `1abc897c451c8b5bbff3792509a7fef9d12f2ce3`, sets the account access token, target ID, and connection type in `PunchHoleRequest`. `RequestRelay.uuid` is the relay request ID. An unset relay connection type is handled as `remote_desktop`.

## Secure TCP

`hbbs` supports the RustDesk `KeyExchange` on protobuf-framed TCP connections:

- Port `21115/TCP`: optional negotiation for NAT testing and online queries. RustDesk Client `1.4.6` continues to use the compatible plaintext path here.
- Port `21116/TCP`: negotiation for rendezvous connections, including `PunchHoleRequest` and `RequestRelay`.
- Port `21116/UDP`: no negotiation.
- WebSocket port `21118/TCP`: no Secure TCP negotiation; **Use WebSocket** remains disabled for this fork.
- The local text-command path on `21115/TCP` remains unchanged.

Each connection uses a new ephemeral `box_` key pair. The server signs the ephemeral public key with its persistent Ed25519 key. The client responds with its ephemeral public key and the authenticated, encrypted `secretbox` key. The handshake uses the protobuf cardinality, the zero nonce for `box_`, and RustDesk Client `1.4.6`'s separate, direction-specific counters starting at `1`. The handshake timeout is `18` seconds.

A normal message received first commits the connection to the compatible plaintext path. Tokenless OSS requests remain supported. A plaintext request on `21116/TCP` with an account access token is closed before invoking the policy. There is no plaintext fallback after a `KeyExchange` has started or failed.

Private keys, symmetric keys, access tokens, license keys, encrypted payloads, and authorization headers are not logged.

## Binaries and License

The modified binary is `hbbs`. `hbbr` remains the unmodified upstream binary and is started in deployment from the official image.

The fork remains AGPL-3.0 licensed. The license text, fork history, submodule pin, and corresponding source code are included with distribution.
