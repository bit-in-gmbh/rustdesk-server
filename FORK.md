# RustDesk Server Fork

Basis: RustDesk Server OSS `1.1.16`, Commit `73523b31cfd25d77dee862e6fc9f5e1fb5e485ef`.

## Management Policy Hook

`hbbs` ruft die Management-Policy für TCP-`PunchHoleRequest` und `RequestRelay` auf. Der Access-Token, die Ziel-ID, der Connection-Type, die Quell-IP und bei Relay-Anfragen die Request-UUID werden an den Policy-Endpunkt übermittelt.

Konfiguration:

```text
POLICY_MODE=off|observe|enforce
POLICY_ENDPOINT=http://127.0.0.1:8081/internal/v1/connection-authorizations
POLICY_SERVICE_TOKEN_FILE=/run/secrets/hbbs-policy-token
POLICY_TIMEOUT_MS=300
POLICY_INSTANCE_ID=hbbs-1
```

`observe` lässt abgelehnte oder fehlgeschlagene Prüfungen zu. `enforce` lehnt Deny-Antworten, Timeouts, Verbindungsfehler, HTTP-Fehler und ungültige Antworten ab. Es gibt keinen Retry und keinen Decision Cache.

RustDesk Client `1.4.6`, Tag-Commit `1abc897c451c8b5bbff3792509a7fef9d12f2ce3`, setzt bei `PunchHoleRequest` den Account-Access-Token, die Ziel-ID und den Connection-Type. `RequestRelay.uuid` ist die Relay-Request-ID. Ein nicht gesetzter Relay-Connection-Type wird als `remote_desktop` verarbeitet.

## Secure TCP

`hbbs` bietet den RustDesk-`KeyExchange` auf protobuf-gerahmten TCP-Verbindungen an:

- Port `21115/TCP`: optionale Aushandlung für NAT-Test und Online-Abfragen. RustDesk Client `1.4.6` verwendet hier weiterhin den kompatiblen Klartextpfad.
- Port `21116/TCP`: Aushandlung für Rendezvous-Verbindungen einschließlich `PunchHoleRequest` und `RequestRelay`.
- Port `21116/UDP`: keine Aushandlung.
- WebSocket-Port `21118/TCP`: keine Secure-TCP-Aushandlung; **Use WebSocket** bleibt für diesen Fork deaktiviert.
- Der lokale Textbefehlspfad auf `21115/TCP` bleibt unverändert.

Jede Verbindung verwendet ein neues ephemeres `box_`-Schlüsselpaar. Der Server signiert den ephemeren Public Key mit seinem persistenten Ed25519-Schlüssel. Der Client antwortet mit seinem ephemeren Public Key und dem authentisiert verschlüsselten `secretbox`-Schlüssel. Der Handshake verwendet die Protobuf-Cardinalität, den Null-Nonce für `box_` und die getrennten, bei `1` beginnenden Richtungszähler von RustDesk Client `1.4.6`. Das Handshake-Limit beträgt `18` Sekunden.

Eine zuerst empfangene normale Nachricht legt die Verbindung auf den kompatiblen Klartextpfad fest. Tokenlose OSS-Anfragen bleiben unterstützt. Eine Klartextanfrage auf `21116/TCP` mit Account-Access-Token wird vor dem Policy-Aufruf geschlossen. Nach einem begonnenen oder fehlgeschlagenen `KeyExchange` gibt es keinen Klartext-Fallback.

Private Schlüssel, symmetrische Schlüssel, Access-Tokens, Licence-Keys, verschlüsselte Payloads und Authorization-Header werden nicht geloggt.

## Binaries und Lizenz

Das angepasste Binary ist `hbbs`. `hbbr` bleibt das unveränderte Upstream-Binary und wird im Deployment aus dem offiziellen Image gestartet.

Der Fork bleibt AGPL-3.0. Lizenztext, Fork-Historie, Submodul-Pin und korrespondierender Quellcode werden bei Verteilung mitgeliefert.
