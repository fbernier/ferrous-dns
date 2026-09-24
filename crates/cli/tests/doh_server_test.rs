//! Dedicated DNS-over-HTTPS listener (RFC 8484) end-to-end test.
//!
//! The handler attributes each query to the TCP peer, so the listener must
//! hand it the connection's address; without it every request fails.

mod common;

use base64::Engine;
use common::{build_a_query, handler_with_canned_addresses};
use ferrous_dns::server::{serve_doh, DohContext};
use hickory_proto::op::Message;
use hickory_proto::rr::RData;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[tokio::test]
async fn dedicated_doh_listener_answers_a_wire_query() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let answer = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
    tokio::spawn(serve_doh(
        listener,
        Arc::new(DohContext {
            handler: handler_with_canned_addresses(vec![answer], 300),
            trusted_proxies: Vec::new(),
        }),
    ));

    let query =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(build_a_query("example.com"));
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(
            format!(
                "GET /dns-query?dns={query} HTTP/1.1\r\nHost: {addr}\r\n\
                 Accept: application/dns-message\r\nConnection: close\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();

    let split = response
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("an HTTP response");
    let head = String::from_utf8_lossy(&response[..split]);
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    let message = Message::from_vec(&response[split + 4..]).unwrap();
    let addresses: Vec<IpAddr> = message
        .answers
        .iter()
        .filter_map(|record| match &record.data {
            RData::A(a) => Some(IpAddr::V4(a.0)),
            _ => None,
        })
        .collect();
    assert_eq!(addresses, [answer]);
}
