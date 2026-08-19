# Management Policy Hook

Dieser Fork basiert auf RustDesk Server `1.1.16`, Upstream-Commit `73523b31cfd25d77dee862e6fc9f5e1fb5e485ef`. Der Patch liegt absichtlich nur in `src/policy_client.rs` und zwei Aufrufstellen in `src/rendezvous_server.rs` (`PunchHoleRequest` und `RequestRelay`). `hbbr` bleibt das unveränderte Upstream-Binary und wird im Deployment aus dem offiziellen Image gestartet.

Konfiguration:

```text
POLICY_MODE=off|observe|enforce
POLICY_ENDPOINT=http://127.0.0.1:8081/internal/v1/connection-authorizations
POLICY_SERVICE_TOKEN_FILE=/run/secrets/hbbs-policy-token
POLICY_TIMEOUT_MS=300
POLICY_INSTANCE_ID=hbbs-1
```

Es gibt keinen Retry und keinen Decision Cache im Verbindungsweg. `observe` protokolliert `would_deny`, lässt die Verbindung aber fortsetzen. `enforce` ist Fail Closed bei Deny, Timeout, Verbindungsfehlern, HTTP-Fehlern und ungültigen Antworten. Access Tokens und Authorization-Header werden nie geloggt.

Der Quellcode von RustDesk Client `1.4.6` (`1abc89781ee38aaf35954a14d7d463cd91de00dc`) bestätigt: `PunchHoleRequest` enthält den Account-Access-Token, Ziel-ID und Connection-Type, aber keine Requester-ID/Device-UUID. Die `uuid` in `RequestRelay` ist eine neu erzeugte Relay-Request-ID und wird deshalb als `relay_request_uuid` auditiert; sie ist keine Geräteidentität. Außerdem setzt 1.4.6 beim ersten `RequestRelay` den Connection-Type nicht, sodass er dort als Default `remote_desktop` ankommt. Die fachliche Identität wird ausschließlich über den vom Backend ausgegebenen Access-Token bestimmt; IP und Relay-Request-ID sind nur Auditkontext.

Vor Enforce müssen die Deny-Reaktionen (`PunchHoleResponse` mit `ID_NOT_EXIST`/`other_failure` sowie `RelayResponse.refuse_reason`) mit einem echten RustDesk Client `1.4.6` als Golden Contract bestätigt werden. Für typabhängige Relay-Regeln ist zusätzlich eine kleine Client-Protokollerweiterung erforderlich; ohne sie darf Enforce keine vom Connection-Type abhängigen Relay-Entscheidungen treffen.

Der Fork bleibt AGPL-3.0. Lizenztext, vollständige Fork-Historie, Submodul-Pin und korrespondierender Quellcode müssen bei Verteilung mitgeliefert werden.
