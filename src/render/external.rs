//! Parse local share links into the same outbound model as managed profiles.
//! Validation is purely syntactic and never opens a connection.
use anyhow::{Context, Result, bail, ensure};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD},
};
use percent_encoding::percent_decode_str;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use uuid::Uuid;

pub(crate) struct External {
    pub name: String,
    pub outbound: Value,
    pub xray: bool,
}

fn base64_bytes(value: &str) -> Result<Vec<u8>> {
    for engine in [URL_SAFE_NO_PAD, URL_SAFE, STANDARD_NO_PAD, STANDARD] {
        if let Ok(bytes) = engine.decode(value) {
            return Ok(bytes);
        }
    }
    bail!("Invalid share-link encoding")
}

fn decoded(value: &str) -> Result<String> {
    let value = percent_decode_str(value).decode_utf8()?.into_owned();
    ensure!(
        !value.chars().any(char::is_control),
        "Invalid share-link field"
    );
    Ok(value)
}

fn uuid(value: &str) -> Result<Uuid> {
    let id = Uuid::parse_str(value)?;
    ensure!(!id.is_nil(), "Missing proxy UUID");
    Ok(id)
}

fn stream(values: &BTreeMap<String, String>, address: &str, scheme: &str) -> Result<Value> {
    let get = |key: &str| values.get(key).map(String::as_str).unwrap_or_default();
    let security = match get("security") {
        "" if matches!(scheme, "trojan" | "hysteria2" | "tuic") => "tls",
        "" | "none" => "none",
        "tls" => "tls",
        "reality" if scheme == "vless" => "reality",
        _ => bail!("Unsupported share-link security"),
    };
    ensure!(
        !matches!(scheme, "trojan" | "hysteria2" | "tuic") || security == "tls",
        "Expected TLS"
    );
    let network = match (scheme, get("type")) {
        ("tuic", "") => "tuic",
        ("hysteria2", "") => "hysteria",
        (_, "" | "tcp" | "raw") => "raw",
        (_, "ws") => "ws",
        (_, "grpc") => "grpc",
        (_, "xhttp") => "xhttp",
        (_, "httpupgrade") => "httpupgrade",
        _ => bail!("Unsupported share-link transport"),
    };
    let sni = if get("sni").is_empty() {
        address
    } else {
        get("sni")
    };
    ensure!(
        (crate::config::domain(sni) || sni.parse::<std::net::IpAddr>().is_ok())
            && !matches!(get("allowInsecure"), "1" | "true")
            && !matches!(get("insecure"), "1" | "true"),
        "Invalid TLS fields"
    );
    let mut result = json!({"network":network,"security":security});
    if security == "tls" {
        result["tlsSettings"] = json!({"serverName":sni});
        if !get("fp").is_empty() {
            result["tlsSettings"]["fingerprint"] = json!(get("fp"));
        }
        if !get("alpn").is_empty() {
            result["tlsSettings"]["alpn"] = json!(get("alpn").split(',').collect::<Vec<_>>());
        }
    } else if security == "reality" {
        let key = get("pbk");
        let short_id = get("sid");
        ensure!(
            base64_bytes(key)?.len() == 32
                && short_id.len() <= 16
                && short_id.len().is_multiple_of(2)
                && short_id.bytes().all(|byte| byte.is_ascii_hexdigit()),
            "Invalid REALITY fields"
        );
        let fingerprint = if get("fp").is_empty() {
            "chrome"
        } else {
            get("fp")
        };
        result["realitySettings"] =
            json!({"serverName":sni,"fingerprint":fingerprint,"password":key,"shortId":short_id});
    }
    let path = if get("path").is_empty() {
        "/"
    } else {
        get("path")
    };
    let host = get("host");
    ensure!(
        path.starts_with('/') && !host.chars().any(char::is_whitespace),
        "Invalid transport fields"
    );
    match network {
        "ws" => {
            result["wsSettings"] = json!({"path":path});
            if !host.is_empty() {
                result["wsSettings"]["headers"] = json!({"Host":host});
            }
        }
        "grpc" => {
            let service = get("serviceName");
            ensure!(!service.is_empty(), "Missing gRPC service name");
            result["grpcSettings"] = json!({"serviceName":service});
        }
        "xhttp" => {
            let mode = get("mode");
            ensure!(
                matches!(mode, "" | "auto" | "packet-up" | "stream-up" | "stream-one"),
                "Invalid XHTTP mode"
            );
            result["xhttpSettings"] =
                json!({"path":path,"mode":if mode.is_empty() {"auto"} else {mode}});
            if !host.is_empty() {
                result["xhttpSettings"]["host"] = json!(host);
            }
        }
        "httpupgrade" => {
            result["httpupgradeSettings"] = json!({"path":path,"host":host});
        }
        _ => {}
    }
    Ok(result)
}

pub(crate) fn parse(link: &str, index: usize) -> Result<External> {
    ensure!(
        !link.is_empty() && link.len() <= 2048 && !link.chars().any(char::is_whitespace),
        "Invalid external share link"
    );
    let (scheme, value) = link
        .split_once("://")
        .context("Missing share-link protocol")?;
    let (value, nickname) = value.rsplit_once('#').unwrap_or((value, ""));
    let nickname = decoded(nickname)?;
    let (identity, address, port, options, nickname) = if scheme == "vmess" {
        let data: Value = serde_json::from_slice(&base64_bytes(value)?)?;
        let field = |key: &str| data[key].as_str().unwrap_or_default();
        let address = field("add").to_owned();
        let port = data["port"]
            .as_u64()
            .map(|port| port.to_string())
            .unwrap_or_else(|| field("port").to_owned())
            .parse::<u16>()?;
        let options = [
            ("type", field("net")),
            ("security", field("tls")),
            ("sni", field("sni")),
            ("fp", field("fp")),
            ("host", field("host")),
            (
                if field("net") == "grpc" {
                    "serviceName"
                } else {
                    "path"
                },
                field("path"),
            ),
        ]
        .into_iter()
        .map(|(key, val)| (key.to_owned(), val.to_owned()))
        .collect();
        ensure!(
            matches!(field("aid"), "" | "0") && matches!(field("type"), "" | "none"),
            "Unsupported VMess option"
        );
        (
            field("id").to_owned(),
            address,
            port,
            options,
            field("ps").to_owned(),
        )
    } else {
        let (address, query) = value.split_once('?').unwrap_or((value, ""));
        let pairs = serde_urlencoded::from_str::<Vec<(String, String)>>(query)?;
        let mut options = BTreeMap::new();
        for (key, value) in pairs {
            ensure!(
                !value.chars().any(char::is_control) && options.insert(key, value).is_none(),
                "Invalid or repeated share-link parameter"
            );
        }
        let (identity, address) = address
            .trim_end_matches('/')
            .rsplit_once('@')
            .context("Missing credentials or address")?;
        let endpoint = crate::catalogue::endpoint(address, 0)?;
        (
            decoded(identity)?,
            endpoint.address,
            endpoint.port,
            options,
            nickname,
        )
    };
    ensure!(
        (crate::config::domain(&address) || address.parse::<std::net::IpAddr>().is_ok())
            && port != 0
            && !identity.is_empty()
            && !nickname.chars().any(char::is_control),
        "Invalid proxy address or identity"
    );
    let get = |key: &str| options.get(key).map(String::as_str).unwrap_or_default();
    let mut transport = stream(&options, &address, scheme)?;
    let mut settings = json!({"address":address,"port":port});
    let protocol = match scheme {
        "vless" => {
            ensure!(
                matches!(get("flow"), "" | "xtls-rprx-vision"),
                "Unsupported VLESS flow"
            );
            let mut identity = json!({"id":uuid(&identity)?,"encryption":if get("encryption").is_empty() {"none"} else {get("encryption")}});
            if !get("flow").is_empty() {
                identity["flow"] = json!(get("flow"));
            }
            settings = json!({"vnext":[{"address":address,"port":port,"users":[identity]}]});
            scheme
        }
        "vmess" => {
            settings["id"] = json!(uuid(&identity)?);
            scheme
        }
        "trojan" => {
            settings["password"] = json!(identity);
            scheme
        }
        "ss" => {
            ensure!(get("plugin").is_empty(), "Unsupported Shadowsocks plugin");
            let secret = if identity.contains(':') {
                identity
            } else {
                String::from_utf8(base64_bytes(&identity)?)?
            };
            let (method, password) = secret
                .split_once(':')
                .context("Missing Shadowsocks credentials")?;
            ensure!(
                !password.is_empty()
                    && matches!(
                        method,
                        "aes-128-gcm"
                            | "aes-256-gcm"
                            | "chacha20-ietf-poly1305"
                            | "2022-blake3-aes-128-gcm"
                            | "2022-blake3-aes-256-gcm"
                    ),
                "Unsupported Shadowsocks method"
            );
            settings["method"] = json!(method);
            settings["password"] = json!(password);
            "shadowsocks"
        }
        "hysteria2" => {
            ensure!(get("obfs").is_empty(), "Unsupported Hysteria2 obfuscation");
            transport["hysteriaSettings"] = json!({"version":2,"auth":identity});
            "hysteria"
        }
        "tuic" => {
            let (id, password) = identity
                .split_once(':')
                .context("Missing TUIC credentials")?;
            ensure!(!password.is_empty(), "Missing TUIC password");
            settings["uuid"] = json!(uuid(id)?);
            settings["password"] = json!(password);
            scheme
        }
        _ => bail!("Unsupported share-link protocol"),
    };
    let nickname: String = nickname.chars().take(72).collect();
    let name = if nickname.is_empty() {
        format!("外部 {} · {scheme}", index + 1)
    } else {
        format!("外部 {} · {nickname}", index + 1)
    };
    Ok(External {
        name,
        outbound: json!({"protocol":protocol,"settings":settings,"streamSettings":transport}),
        xray: protocol != "tuic",
    })
}
