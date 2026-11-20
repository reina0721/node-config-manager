//! Xray's WireGuard UserManager is available over gRPC. The pinned CLI's
//! JSON-to-user conversion does not handle PeerConfig.
use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use prost::Message;
use serde_json::Value;
use std::{
    io::Write,
    process::{Command, Stdio},
};

#[derive(Message)]
struct TypedMessage {
    #[prost(string, tag = "1")]
    name: String,
    #[prost(bytes = "vec", tag = "2")]
    value: Vec<u8>,
}

impl TypedMessage {
    fn new(name: &str, value: impl Message) -> Self {
        Self {
            name: name.into(),
            value: value.encode_to_vec(),
        }
    }
}

#[derive(Message)]
struct Peer {
    #[prost(string, tag = "1")]
    public_key: String,
    #[prost(string, repeated, tag = "5")]
    allowed_ips: Vec<String>,
}

#[derive(Message)]
struct User {
    #[prost(string, tag = "2")]
    email: String,
    #[prost(message, optional, tag = "3")]
    account: Option<TypedMessage>,
}

#[derive(Message)]
struct AddUser {
    #[prost(message, optional, tag = "1")]
    user: Option<User>,
}

#[derive(Message)]
struct AlterInbound {
    #[prost(string, tag = "1")]
    tag: String,
    #[prost(message, optional, tag = "2")]
    operation: Option<TypedMessage>,
}

pub(super) fn add_peer(socket: &str, inbound: &Value) -> Result<()> {
    let peer = &inbound["settings"]["peers"][0];
    let peer_config = Peer {
        public_key: hex::encode(
            STANDARD.decode(
                peer["publicKey"]
                    .as_str()
                    .context("Missing WireGuard public key")?,
            )?,
        ),
        allowed_ips: serde_json::from_value(peer["allowedIPs"].clone())?,
    };
    let user = User {
        email: peer["email"]
            .as_str()
            .context("Missing WireGuard account alias")?
            .into(),
        account: Some(TypedMessage::new(
            "xray.proxy.wireguard.PeerConfig",
            peer_config,
        )),
    };
    let args = AlterInbound {
        tag: inbound["tag"]
            .as_str()
            .context("Missing WireGuard inbound tag")?
            .into(),
        operation: Some(TypedMessage::new(
            "xray.app.proxyman.command.AddUserOperation",
            AddUser { user: Some(user) },
        )),
    }
    .encode_to_vec();

    let mut body = tempfile::NamedTempFile::new()?;
    body.write_all(&[0])?; // uncompressed gRPC message
    body.write_all(&u32::try_from(args.len())?.to_be_bytes())?;
    body.write_all(&args)?;
    body.flush()?;
    let data = format!("@{}", body.path().display());
    let response = Command::new("/usr/bin/curl")
        .args([
            "--disable",
            "--noproxy",
            "*",
            "--max-time",
            "2",
            "--fail",
            "--silent",
            "--http2-prior-knowledge",
            "--unix-socket",
            socket,
            "--header",
            "Content-Type: application/grpc",
            "--header",
            "TE: trailers",
            "--data-binary",
            &data,
            "--dump-header",
            "-",
            "--output",
            "/dev/null",
            "http://localhost/xray.app.proxyman.command.HandlerService/AlterInbound",
        ])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()?;
    ensure!(
        response.status.success()
            && String::from_utf8_lossy(&response.stdout)
                .lines()
                .any(|line| line.eq_ignore_ascii_case("grpc-status: 0")),
        "proxy_runtime_update_failed"
    );
    Ok(())
}
