use super::*;
use crate::policy_client::PolicyMode;
use hbb_common::{
    bytes::{Bytes, BytesMut},
    futures_util::{SinkExt, StreamExt},
    tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, UdpSocket},
        sync::mpsc,
        task::JoinHandle,
        time::Duration,
    },
};
use serde_json::Value;
use sodiumoxide::crypto::{box_, secretbox, sign};
use std::net::SocketAddr;

struct TestClient {
    stream: Framed<TcpStream, BytesCodec>,
    encrypt: Option<Encrypt>,
    key: Option<[u8; secretbox::KEYBYTES]>,
}

impl TestClient {
    async fn connect(addr: SocketAddr) -> Self {
        let stream = TcpStream::connect(addr).await.unwrap();
        stream.set_nodelay(true).unwrap();
        Self {
            stream: Framed::new(stream, BytesCodec::new()),
            encrypt: None,
            key: None,
        }
    }

    async fn receive_raw(&mut self) -> BytesMut {
        timeout(1_000, self.stream.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap()
    }

    async fn receive(&mut self) -> RendezvousMessage {
        let mut bytes = self.receive_raw().await;
        if let Some(encrypt) = self.encrypt.as_mut() {
            encrypt.dec(&mut bytes).unwrap();
        }
        RendezvousMessage::parse_from_bytes(&bytes).unwrap()
    }

    async fn send_raw(&mut self, message: &RendezvousMessage) {
        self.stream
            .send(Bytes::from(message.write_to_bytes().unwrap()))
            .await
            .unwrap();
    }

    async fn send(&mut self, message: &RendezvousMessage) {
        let mut bytes = message.write_to_bytes().unwrap();
        if let Some(encrypt) = self.encrypt.as_mut() {
            bytes = encrypt.enc(&bytes);
        }
        self.stream.send(Bytes::from(bytes)).await.unwrap();
    }

    async fn secure(&mut self, signing_pk: &sign::PublicKey) -> Vec<u8> {
        let offer = self.receive().await;
        let exchange = match offer.union {
            Some(rendezvous_message::Union::KeyExchange(exchange)) => exchange,
            _ => panic!("expected key exchange offer"),
        };
        assert_eq!(exchange.keys.len(), 1);
        let server_ephemeral = sign::verify(&exchange.keys[0], signing_pk).unwrap();
        let server_pk = box_::PublicKey::from_slice(&server_ephemeral).unwrap();
        let (client_pk, client_sk) = box_::gen_keypair();
        let key = secretbox::gen_key();
        let encrypted_key = box_::seal(
            &key.0,
            &box_::Nonce([0; box_::NONCEBYTES]),
            &server_pk,
            &client_sk,
        );
        let mut response = RendezvousMessage::new();
        response.set_key_exchange(KeyExchange {
            keys: vec![client_pk.0.to_vec().into(), encrypted_key.into()],
            ..Default::default()
        });
        self.send_raw(&response).await;
        self.key = Some(key.0);
        self.encrypt = Some(Encrypt::new(key));
        server_ephemeral
    }
}

async fn test_server(policy: PolicyClient) -> (RendezvousServer, String, sign::PublicKey) {
    let (signing_pk, signing_sk) = sign::gen_keypair();
    let db_path = std::env::temp_dir().join(format!(
        "rustdesk-secure-tcp-{}.sqlite3",
        uuid::Uuid::new_v4()
    ));
    let pm = PeerMap::for_test(db_path.to_str().unwrap()).await.unwrap();
    let (tx, _rx) = mpsc::unbounded_channel();
    let key = base64::encode(signing_pk.0);
    (
        RendezvousServer {
            tcp_punch: Default::default(),
            pm,
            tx,
            relay_servers: Default::default(),
            relay_servers0: Default::default(),
            rendezvous_servers: Default::default(),
            inner: Arc::new(Inner {
                serial: 0,
                version: String::new(),
                software_url: String::new(),
                mask: None,
                local_ip: String::new(),
                sk: Some(signing_sk),
                policy,
            }),
        },
        key,
        signing_pk,
    )
}

fn off_policy() -> PolicyClient {
    PolicyClient::for_test(PolicyMode::Off, String::new(), Duration::from_secs(1))
}

async fn spawn_nat(mut server: RendezvousServer) -> (SocketAddr, JoinHandle<ResultType<()>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (stream, peer) = listener.accept().await?;
        let synthetic_peer = SocketAddr::from(([198, 51, 100, 10], peer.port()));
        server
            .handle_listener2_inner(stream, synthetic_peer, 1_000)
            .await
    });
    (addr, task)
}

async fn spawn_rendezvous(
    mut server: RendezvousServer,
    key: String,
) -> (SocketAddr, JoinHandle<ResultType<()>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (stream, peer) = listener.accept().await?;
        server
            .handle_listener_inner(stream, peer, &key, false)
            .await
    });
    (addr, task)
}

fn test_nat_request() -> RendezvousMessage {
    let mut message = RendezvousMessage::new();
    message.set_test_nat_request(TestNatRequest::new());
    message
}

#[tokio::test(flavor = "multi_thread")]
async fn nat_port_supports_plaintext_and_secure_clients() {
    let (server, _, signing_pk) = test_server(off_policy()).await;

    let (addr, task) = spawn_nat(server.clone()).await;
    let mut plaintext = TestClient::connect(addr).await;
    plaintext.send_raw(&test_nat_request()).await;
    let offer = plaintext.receive().await;
    assert!(matches!(
        offer.union,
        Some(rendezvous_message::Union::KeyExchange(_))
    ));
    let response = plaintext.receive().await;
    assert!(matches!(
        response.union,
        Some(rendezvous_message::Union::TestNatResponse(_))
    ));
    task.await.unwrap().unwrap();

    let (addr, task) = spawn_nat(server).await;
    let mut secured = TestClient::connect(addr).await;
    secured.secure(&signing_pk).await;
    secured.send(&test_nat_request()).await;
    let response = secured.receive().await;
    assert!(matches!(
        response.union,
        Some(rendezvous_message::Union::TestNatResponse(_))
    ));
    task.await.unwrap().unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn rendezvous_round_trip_and_tokenless_plaintext_are_compatible() {
    let (server, key, signing_pk) = test_server(off_policy()).await;

    let (addr, task) = spawn_rendezvous(server.clone(), key.clone()).await;
    let mut secured = TestClient::connect(addr).await;
    secured.secure(&signing_pk).await;
    secured.send(&test_nat_request()).await;
    let response = secured.receive().await;
    assert!(matches!(
        response.union,
        Some(rendezvous_message::Union::TestNatResponse(_))
    ));
    task.await.unwrap().unwrap();

    let (addr, task) = spawn_rendezvous(server, key.clone()).await;
    let mut plaintext = TestClient::connect(addr).await;
    let mut request = RendezvousMessage::new();
    request.set_punch_hole_request(PunchHoleRequest {
        id: "missing-peer".to_owned(),
        licence_key: key,
        ..Default::default()
    });
    plaintext.send_raw(&request).await;
    let offer = plaintext.receive().await;
    assert!(matches!(
        offer.union,
        Some(rendezvous_message::Union::KeyExchange(_))
    ));
    let response = plaintext.receive().await;
    assert!(matches!(
        response.union,
        Some(rendezvous_message::Union::PunchHoleResponse(_))
    ));
    drop(plaintext);
    task.await.unwrap().unwrap();
}

async fn read_http_body(stream: &mut TcpStream) -> String {
    let mut request = Vec::new();
    let mut buffer = [0_u8; 1024];
    loop {
        let count = stream.read(&mut buffer).await.unwrap();
        assert!(count > 0);
        request.extend_from_slice(&buffer[..count]);
        let Some(header_end) = request.windows(4).position(|part| part == b"\r\n\r\n") else {
            continue;
        };
        let header_end = header_end + 4;
        let headers = String::from_utf8_lossy(&request[..header_end]);
        let content_length = headers
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().unwrap())
            })
            .unwrap();
        if request.len() >= header_end + content_length {
            return String::from_utf8(request[header_end..header_end + content_length].to_vec())
                .unwrap();
        }
    }
}

async fn policy_endpoint(expected: usize) -> (String, mpsc::UnboundedReceiver<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        for _ in 0..expected {
            let (mut stream, _) = listener.accept().await.unwrap();
            tx.send(read_http_body(&mut stream).await).unwrap();
            let body = r#"{"decision_id":"test","decision":"allow","reason_code":"test_allow"}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            stream.write_all(response.as_bytes()).await.unwrap();
        }
    });
    (format!("http://{addr}"), rx)
}

#[tokio::test(flavor = "multi_thread")]
async fn encrypted_policy_requests_preserve_tokens() {
    let (endpoint, mut requests) = policy_endpoint(2).await;
    let policy = PolicyClient::for_test(PolicyMode::Enforce, endpoint, Duration::from_secs(1));
    let (server, key, signing_pk) = test_server(policy).await;

    let (addr, punch_task) = spawn_rendezvous(server.clone(), key.clone()).await;
    let mut punch_client = TestClient::connect(addr).await;
    punch_client.secure(&signing_pk).await;
    let mut punch = RendezvousMessage::new();
    punch.set_punch_hole_request(PunchHoleRequest {
        id: "missing-peer".to_owned(),
        licence_key: key.clone(),
        token: "punch-secret".to_owned(),
        ..Default::default()
    });
    punch_client.send(&punch).await;
    assert!(matches!(
        punch_client.receive().await.union,
        Some(rendezvous_message::Union::PunchHoleResponse(_))
    ));
    drop(punch_client);
    punch_task.await.unwrap().unwrap();

    let (addr, relay_task) = spawn_rendezvous(server, key.clone()).await;
    let mut relay_client = TestClient::connect(addr).await;
    relay_client.secure(&signing_pk).await;
    let mut relay = RendezvousMessage::new();
    relay.set_request_relay(RequestRelay {
        id: "missing-peer".to_owned(),
        uuid: "relay-request".to_owned(),
        licence_key: key,
        token: "relay-secret".to_owned(),
        ..Default::default()
    });
    relay_client.send(&relay).await;

    let first: Value = serde_json::from_str(&requests.recv().await.unwrap()).unwrap();
    let second: Value = serde_json::from_str(&requests.recv().await.unwrap()).unwrap();
    assert_eq!(first["request_kind"], "punch_hole");
    assert_eq!(first["access_token"], "punch-secret");
    assert_eq!(second["request_kind"], "relay");
    assert_eq!(second["access_token"], "relay-secret");
    drop(relay_client);
    relay_task.await.unwrap().unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn plaintext_access_token_is_rejected_before_policy() {
    let policy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let policy = PolicyClient::for_test(
        PolicyMode::Enforce,
        format!("http://{}", policy_listener.local_addr().unwrap()),
        Duration::from_millis(50),
    );
    let (server, key, _) = test_server(policy).await;
    let (addr, task) = spawn_rendezvous(server, key.clone()).await;
    let mut client = TestClient::connect(addr).await;
    let mut request = RendezvousMessage::new();
    request.set_punch_hole_request(PunchHoleRequest {
        id: "missing-peer".to_owned(),
        licence_key: key,
        token: "must-not-reach-policy".to_owned(),
        ..Default::default()
    });
    client.send_raw(&request).await;
    let offer = client.receive().await;
    assert!(matches!(
        offer.union,
        Some(rendezvous_message::Union::KeyExchange(_))
    ));
    assert!(timeout(500, client.stream.next()).await.unwrap().is_none());
    task.await.unwrap().unwrap();
    assert!(timeout(100, policy_listener.accept()).await.is_err());
}

async fn spawn_handshake(
    signing_sk: sign::SecretKey,
    handshake_timeout: u64,
) -> (SocketAddr, JoinHandle<ResultType<TcpNegotiation>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (stream, peer) = listener.accept().await?;
        let mut stream = Framed::new(stream, BytesCodec::new());
        RendezvousServer::negotiate_tcp(&mut stream, peer, Some(&signing_sk), handshake_timeout)
            .await
    });
    (addr, task)
}

async fn rejected_exchange(keys: Vec<Bytes>) {
    let (_, signing_sk) = sign::gen_keypair();
    let (addr, task) = spawn_handshake(signing_sk, 1_000).await;
    let mut client = TestClient::connect(addr).await;
    let offer = client.receive().await;
    assert!(matches!(
        offer.union,
        Some(rendezvous_message::Union::KeyExchange(_))
    ));
    let mut response = RendezvousMessage::new();
    response.set_key_exchange(KeyExchange {
        keys,
        ..Default::default()
    });
    client.send_raw(&response).await;
    let _ = client
        .stream
        .send(Bytes::from(test_nat_request().write_to_bytes().unwrap()))
        .await;
    assert!(task.await.unwrap().is_err());
    assert!(timeout(500, client.stream.next()).await.unwrap().is_none());
}

#[tokio::test(flavor = "multi_thread")]
async fn malformed_handshakes_are_rejected_without_fallback() {
    rejected_exchange(vec![]).await;
    rejected_exchange(vec![Bytes::from(vec![0; box_::PUBLICKEYBYTES])]).await;
    rejected_exchange(vec![
        Bytes::from(vec![0; box_::PUBLICKEYBYTES]),
        Bytes::from(vec![0; secretbox::KEYBYTES + box_::MACBYTES]),
        Bytes::new(),
    ])
    .await;
    rejected_exchange(vec![
        Bytes::from(vec![0; box_::PUBLICKEYBYTES - 1]),
        Bytes::from(vec![0; secretbox::KEYBYTES + box_::MACBYTES]),
    ])
    .await;
    rejected_exchange(vec![
        Bytes::from(vec![0; box_::PUBLICKEYBYTES]),
        Bytes::from(vec![0; secretbox::KEYBYTES + box_::MACBYTES - 1]),
    ])
    .await;
    rejected_exchange(vec![
        Bytes::from(vec![0; box_::PUBLICKEYBYTES]),
        Bytes::from(vec![0; secretbox::KEYBYTES + box_::MACBYTES]),
    ])
    .await;

    let (_, signing_sk) = sign::gen_keypair();
    let (addr, task) = spawn_handshake(signing_sk, 25).await;
    let mut client = TestClient::connect(addr).await;
    client.receive().await;
    assert!(task.await.unwrap().is_err());
    assert!(timeout(500, client.stream.next()).await.unwrap().is_none());

    let (_, signing_sk) = sign::gen_keypair();
    let (addr, task) = spawn_handshake(signing_sk, 1_000).await;
    let mut client = TestClient::connect(addr).await;
    client.receive().await;
    client
        .stream
        .send(Bytes::from_static(&[0xff]))
        .await
        .unwrap();
    assert!(task.await.unwrap().is_err());
    assert!(timeout(500, client.stream.next()).await.unwrap().is_none());
}

#[tokio::test(flavor = "multi_thread")]
async fn duplicate_key_exchange_closes_secured_connection() {
    let (server, key, signing_pk) = test_server(off_policy()).await;
    let (addr, task) = spawn_rendezvous(server, key).await;
    let mut client = TestClient::connect(addr).await;
    client.secure(&signing_pk).await;
    let mut duplicate = RendezvousMessage::new();
    duplicate.set_key_exchange(KeyExchange::new());
    client.send(&duplicate).await;
    assert!(timeout(500, client.stream.next()).await.unwrap().is_none());
    task.await.unwrap().unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn simultaneous_connections_have_distinct_keys_and_counters() {
    let (server, key, signing_pk) = test_server(off_policy()).await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server_task = tokio::spawn(async move {
        let mut tasks = Vec::new();
        for _ in 0..2 {
            let (stream, peer) = listener.accept().await.unwrap();
            let mut server = server.clone();
            let key = key.clone();
            tasks.push(tokio::spawn(async move {
                server
                    .handle_listener_inner(stream, peer, &key, false)
                    .await
                    .unwrap();
            }));
        }
        for task in tasks {
            task.await.unwrap();
        }
    });

    let mut first = TestClient::connect(addr).await;
    let mut second = TestClient::connect(addr).await;
    let (first_ephemeral, second_ephemeral) =
        tokio::join!(first.secure(&signing_pk), second.secure(&signing_pk));
    assert_ne!(first_ephemeral, second_ephemeral);
    let (first_key, second_key) = match (first.key, second.key) {
        (Some(first), Some(second)) => (first, second),
        _ => unreachable!(),
    };
    assert_ne!(first_key, second_key);

    first.send(&test_nat_request()).await;
    second.send(&test_nat_request()).await;
    assert!(matches!(
        first.receive().await.union,
        Some(rendezvous_message::Union::TestNatResponse(_))
    ));
    assert!(matches!(
        second.receive().await.union,
        Some(rendezvous_message::Union::TestNatResponse(_))
    ));
    server_task.await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn loopback_nat_listener_keeps_raw_command_protocol() {
    let (server, _, _) = test_server(off_policy()).await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server_task = tokio::spawn(async move {
        let (stream, peer) = listener.accept().await.unwrap();
        server.handle_listener2(stream, peer).await;
    });

    let mut client = TcpStream::connect(addr).await.unwrap();
    client.write_all(b"h").await.unwrap();
    let mut response = Vec::new();
    timeout(1_000, client.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert!(String::from_utf8(response)
        .unwrap()
        .contains("relay-servers"));
    server_task.await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn udp_registration_path_remains_plaintext() {
    let (mut server, _, _) = test_server(off_policy()).await;
    let mut socket = create_udp_listener(0, 0).await.unwrap();
    let server_addr = SocketAddr::from(([127, 0, 0, 1], socket.local_addr().unwrap().port()));
    let server_task = tokio::spawn(async move {
        let (bytes, peer) = socket.next().await.unwrap().unwrap();
        server
            .handle_udp(&bytes, peer.into(), &mut socket, "")
            .await
            .unwrap();
    });

    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut request = RendezvousMessage::new();
    request.set_register_pk(RegisterPk {
        id: "peer01".to_owned(),
        uuid: Bytes::from_static(b"uuid"),
        pk: Bytes::from_static(b"public-key"),
        ..Default::default()
    });
    client
        .send_to(&request.write_to_bytes().unwrap(), server_addr)
        .await
        .unwrap();
    let mut response = vec![0_u8; 1024];
    let (count, _) = timeout(1_000, client.recv_from(&mut response))
        .await
        .unwrap()
        .unwrap();
    let response = RendezvousMessage::parse_from_bytes(&response[..count]).unwrap();
    assert!(matches!(
        response.union,
        Some(rendezvous_message::Union::RegisterPkResponse(_))
    ));
    server_task.await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn websocket_path_remains_plaintext() {
    let (server, key, _) = test_server(off_policy()).await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server_task = tokio::spawn(async move {
        let (stream, peer) = listener.accept().await.unwrap();
        let mut server = server;
        server
            .handle_listener_inner(stream, peer, &key, true)
            .await
            .unwrap();
    });

    let stream = TcpStream::connect(addr).await.unwrap();
    let (mut client, _) = tokio_tungstenite::client_async(format!("ws://{addr}"), stream)
        .await
        .unwrap();
    client
        .send(tungstenite::Message::Binary(
            test_nat_request().write_to_bytes().unwrap(),
        ))
        .await
        .unwrap();
    let response = timeout(1_000, client.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let tungstenite::Message::Binary(response) = response else {
        panic!("expected binary WebSocket response");
    };
    let response = RendezvousMessage::parse_from_bytes(&response).unwrap();
    assert!(matches!(
        response.union,
        Some(rendezvous_message::Union::TestNatResponse(_))
    ));
    client.close(None).await.unwrap();
    server_task.await.unwrap();
}
