use hbb_common::log;
use serde::{Deserialize, Serialize};
use std::{
    env, fs,
    io::{Error, ErrorKind, Result},
    time::Duration,
};
use uuid::Uuid;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicyMode {
    Off,
    Observe,
    Enforce,
}

impl PolicyMode {
    fn parse(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "off" | "" => Ok(Self::Off),
            "observe" => Ok(Self::Observe),
            "enforce" => Ok(Self::Enforce),
            value => Err(Error::new(
                ErrorKind::InvalidInput,
                format!("invalid POLICY_MODE {value:?}"),
            )),
        }
    }
}

#[derive(Clone)]
pub struct PolicyClient {
    mode: PolicyMode,
    endpoint: String,
    service_token: String,
    instance_id: String,
    timeout: Duration,
    client: reqwest::Client,
}

#[derive(Debug, Serialize)]
pub struct AuthorizationRequest {
    pub request_id: String,
    pub request_kind: &'static str,
    pub access_token: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub requester_rustdesk_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub relay_request_uuid: String,
    pub requester_ip: String,
    pub target_rustdesk_id: String,
    pub connection_type: String,
    pub relay_requested: bool,
    pub hbbs_instance: String,
}

#[derive(Debug, Deserialize)]
struct AuthorizationResponse {
    decision_id: String,
    decision: String,
    reason_code: String,
}

impl PolicyClient {
    pub fn from_env() -> Result<Self> {
        let mode = PolicyMode::parse(&env::var("POLICY_MODE").unwrap_or_default())?;
        let endpoint = env::var("POLICY_ENDPOINT").unwrap_or_else(|_| {
            "http://127.0.0.1:8081/internal/v1/connection-authorizations".to_owned()
        });
        let instance_id = env::var("POLICY_INSTANCE_ID").unwrap_or_else(|_| "hbbs-1".to_owned());
        let timeout_ms = env::var("POLICY_TIMEOUT_MS")
            .unwrap_or_else(|_| "300".to_owned())
            .parse::<u64>()
            .map_err(|_| {
                Error::new(
                    ErrorKind::InvalidInput,
                    "POLICY_TIMEOUT_MS must be an integer",
                )
            })?;
        if timeout_ms == 0 {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "POLICY_TIMEOUT_MS must be positive",
            ));
        }
        let token_file = env::var("POLICY_SERVICE_TOKEN_FILE").unwrap_or_default();
        let service_token = if mode == PolicyMode::Off {
            String::new()
        } else if token_file.trim().is_empty() {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "POLICY_SERVICE_TOKEN_FILE is required in observe/enforce mode",
            ));
        } else {
            fs::read_to_string(token_file)?.trim().to_owned()
        };
        if mode != PolicyMode::Off && service_token.is_empty() {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "policy service token is empty",
            ));
        }
        let timeout = Duration::from_millis(timeout_ms);
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .map_err(|err| Error::new(ErrorKind::Other, err))?;
        Ok(Self {
            mode,
            endpoint,
            service_token,
            instance_id,
            timeout,
            client,
        })
    }

    pub fn log_configuration(&self) {
        match self.mode {
            PolicyMode::Off => {
                log::warn!("POLICY_MODE=off; authorization hook is bypassed (break-glass)")
            }
            mode => log::info!(
                "policy hook configured: mode={:?}, endpoint={}, timeout_ms={}, instance={}",
                mode,
                self.endpoint,
                self.timeout.as_millis(),
                self.instance_id
            ),
        }
    }

    #[cfg(test)]
    pub(crate) fn for_test(mode: PolicyMode, endpoint: String, timeout: Duration) -> Self {
        Self {
            mode,
            endpoint,
            service_token: "test-service-token".to_owned(),
            instance_id: "test-hbbs".to_owned(),
            timeout,
            client: reqwest::Client::builder().timeout(timeout).build().unwrap(),
        }
    }

    pub async fn authorize(&self, mut request: AuthorizationRequest) -> bool {
        if self.mode == PolicyMode::Off {
            return true;
        }
        request.request_id = Uuid::new_v4().to_string();
        request.hbbs_instance = self.instance_id.clone();
        let request_id = request.request_id.clone();
        let result = async {
            let response = self
                .client
                .post(&self.endpoint)
                .bearer_auth(&self.service_token)
                .json(&request)
                .send()
                .await
                .map_err(|err| format!("request failed: {err}"))?;
            if !response.status().is_success() {
                return Err(format!("backend returned HTTP {}", response.status()));
            }
            response
                .json::<AuthorizationResponse>()
                .await
                .map_err(|err| format!("invalid response: {err}"))
        }
        .await;
        match result {
            Ok(response) if response.decision == "allow" => {
                log::debug!(
                    "policy allow: request_id={}, decision_id={}, reason={}",
                    request_id,
                    response.decision_id,
                    response.reason_code
                );
                true
            }
            Ok(response) if self.mode == PolicyMode::Observe => {
                log::warn!(
                    "policy would_deny: request_id={}, decision_id={}, reason={}",
                    request_id,
                    response.decision_id,
                    response.reason_code
                );
                true
            }
            Ok(response) => {
                log::warn!(
                    "policy deny: request_id={}, decision_id={}, reason={}",
                    request_id,
                    response.decision_id,
                    response.reason_code
                );
                false
            }
            Err(error) if self.mode == PolicyMode::Observe => {
                log::error!(
                    "policy unavailable in observe mode: request_id={}, error={}",
                    request_id,
                    error
                );
                true
            }
            Err(error) => {
                log::error!(
                    "policy unavailable; failing closed: request_id={}, error={}",
                    request_id,
                    error
                );
                false
            }
        }
    }
}

pub fn connection_type(value: i32) -> String {
    match value {
        1 => "file_transfer",
        2 => "port_forward",
        3 => "rdp",
        4 => "view_camera",
        _ => "remote_desktop",
    }
    .to_owned()
}

pub fn request(
    kind: &'static str,
    access_token: String,
    relay_request_uuid: String,
    requester_ip: String,
    target_rustdesk_id: String,
    connection_type: String,
    relay_requested: bool,
) -> AuthorizationRequest {
    AuthorizationRequest {
        request_id: String::new(),
        request_kind: kind,
        access_token,
        requester_rustdesk_id: String::new(),
        relay_request_uuid,
        requester_ip,
        target_rustdesk_id,
        connection_type,
        relay_requested,
        hbbs_instance: String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hbb_common::tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
        time::sleep,
    };

    #[test]
    fn parses_modes_strictly() {
        assert_eq!(PolicyMode::parse("off").unwrap(), PolicyMode::Off);
        assert_eq!(PolicyMode::parse("OBSERVE").unwrap(), PolicyMode::Observe);
        assert_eq!(PolicyMode::parse("enforce").unwrap(), PolicyMode::Enforce);
        assert!(PolicyMode::parse("permissive").is_err());
    }

    #[test]
    fn maps_connection_types() {
        assert_eq!(connection_type(0), "remote_desktop");
        assert_eq!(connection_type(1), "file_transfer");
        assert_eq!(connection_type(2), "port_forward");
        assert_eq!(connection_type(3), "rdp");
        assert_eq!(connection_type(4), "view_camera");
        assert_eq!(connection_type(99), "remote_desktop");
    }

    #[test]
    fn names_relay_correlation_without_claiming_device_identity() {
        let value = serde_json::to_value(request(
            "relay",
            "token".to_owned(),
            "relay-uuid".to_owned(),
            "127.0.0.1".to_owned(),
            "target".to_owned(),
            "remote_desktop".to_owned(),
            true,
        ))
        .unwrap();
        assert_eq!(value["relay_request_uuid"], "relay-uuid");
        assert!(value.get("requester_uuid").is_none());
    }

    fn client(mode: PolicyMode, endpoint: String, timeout: Duration) -> PolicyClient {
        PolicyClient {
            mode,
            endpoint,
            service_token: "service-secret".to_owned(),
            instance_id: "test-hbbs".to_owned(),
            timeout,
            client: reqwest::Client::builder().timeout(timeout).build().unwrap(),
        }
    }

    fn test_request() -> AuthorizationRequest {
        request(
            "relay",
            "user-token".to_owned(),
            "requester-uuid".to_owned(),
            "127.0.0.1".to_owned(),
            "target-id".to_owned(),
            "default".to_owned(),
            true,
        )
    }

    async fn response_server(body: &'static str, delay: Duration) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        hbb_common::tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buffer = [0_u8; 4096];
            let _ = stream.read(&mut buffer).await;
            sleep(delay).await;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(response.as_bytes()).await;
        });
        format!("http://{address}")
    }

    fn run_async(test: impl std::future::Future<Output = ()>) {
        hbb_common::tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(test);
    }

    #[test]
    fn observe_logs_deny_but_allows() {
        run_async(async {
            let endpoint = response_server(
                r#"{"decision_id":"decision-1","decision":"deny","reason_code":"default_deny"}"#,
                Duration::ZERO,
            )
            .await;
            assert!(
                client(PolicyMode::Observe, endpoint, Duration::from_millis(100))
                    .authorize(test_request())
                    .await
            );
        });
    }

    #[test]
    fn enforce_blocks_deny_and_backend_failure() {
        run_async(async {
            let endpoint = response_server(
                r#"{"decision_id":"decision-2","decision":"deny","reason_code":"explicit_deny"}"#,
                Duration::ZERO,
            )
            .await;
            assert!(
                !client(PolicyMode::Enforce, endpoint, Duration::from_millis(100))
                    .authorize(test_request())
                    .await
            );
            assert!(
                !client(
                    PolicyMode::Enforce,
                    "http://127.0.0.1:1".to_owned(),
                    Duration::from_millis(50)
                )
                .authorize(test_request())
                .await
            );
        });
    }

    #[test]
    fn timeout_is_fail_open_only_in_observe() {
        run_async(async {
            let endpoint = response_server(
                r#"{"decision_id":"late","decision":"allow","reason_code":"explicit_allow"}"#,
                Duration::from_millis(100),
            )
            .await;
            assert!(
                client(PolicyMode::Observe, endpoint, Duration::from_millis(10))
                    .authorize(test_request())
                    .await
            );
        });
    }
}
