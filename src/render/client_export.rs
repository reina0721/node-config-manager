use anyhow::{Context, Result};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use serde_json::{Value, json};
use std::net::Ipv6Addr;

pub(super) fn xray_config(profiles: &Value, portal: Option<&str>) -> Result<Value> {
    let profiles = profiles["profiles"]
        .as_array()
        .context("Missing profiles")?;
    let mut inbounds = Vec::new();
    let mut rules = Vec::new();
    let mut outbounds = Vec::new();
    for (index, profile) in profiles.iter().enumerate() {
        let port = 10808 + index;
        let tag = format!("device-{port}");
        let name = profile["name"].as_str().context("Missing profile name")?;
        inbounds.push(json!({"tag":tag,"protocol":"socks","listen":"127.0.0.1","port":port,"settings":{"udp":true}}));
        rules.push(json!({"type":"field","inboundTag":[tag],"outboundTag":name}));
        let mut outbound = profile["outbound"].clone();
        outbound["tag"] = json!(name);
        outbounds.push(outbound);
    }
    if let Some(host) = portal {
        let builtin = profiles
            .iter()
            .find_map(|profile| {
                let name = profile["name"].as_str()?;
                super::builtin_profile(name).then_some(name)
            })
            .context("Missing private authentication outbound")?;
        rules.insert(0, json!({"type":"field","domain":[format!("full:{host}")],"network":"tcp","port":"443","outboundTag":builtin}));
    }
    Ok(
        json!({"log":{"loglevel":"warning"},"inbounds":inbounds,"outbounds":outbounds,"routing":{"domainStrategy":"AsIs","rules":rules}}),
    )
}

pub(crate) struct ShareLink {
    pub name: String,
    pub url: String,
}

fn text(value: &Value) -> &str {
    value.as_str().unwrap_or_default()
}

fn authority(address: &str, port: u64) -> String {
    if address.parse::<Ipv6Addr>().is_ok() {
        format!("[{address}]:{port}")
    } else {
        format!("{address}:{port}")
    }
}

fn escape(value: &str) -> String {
    utf8_percent_encode(value, NON_ALPHANUMERIC).to_string()
}

fn profile_link(profile: &Value) -> Result<Option<ShareLink>> {
    let name = text(&profile["name"]);
    if let Some(url) = profile["external_url"].as_str() {
        return Ok(Some(ShareLink {
            name: name.to_owned(),
            url: url.to_owned(),
        }));
    }
    let outbound = &profile["outbound"];
    let settings = &outbound["settings"];
    let stream = &outbound["streamSettings"];
    let transport = match text(&stream["network"]) {
        "raw" => "tcp",
        "mkcp" => "kcp",
        other => other,
    };
    let protocol = text(&outbound["protocol"]);
    if protocol == "mtproto" {
        let address = escape(text(&settings["address"]));
        let port = settings["port"].as_u64().context("Missing MTProto port")?;
        let secret = text(&settings["secret"]);
        return Ok(Some(ShareLink {
            name: name.to_string(),
            url: format!("tg://proxy?server={address}&port={port}&secret={secret}"),
        }));
    }
    if !matches!(
        protocol,
        "vless" | "vmess" | "trojan" | "shadowsocks" | "hysteria"
    ) {
        return Ok(None);
    }
    let tls = text(&stream["security"]);
    let security = &stream[if tls == "reality" {
        "realitySettings"
    } else {
        "tlsSettings"
    }];
    let server = if protocol == "vless" {
        &settings["vnext"][0]
    } else {
        settings
    };
    let address = text(&server["address"]);
    let port = server["port"].as_u64().context("Missing share link port")?;
    let endpoint = authority(address, port);
    let sni = text(&security["serverName"]);
    let origin = text(&security["fingerprint"]);
    let config = match transport {
        "xhttp" => &stream["xhttpSettings"],
        "ws" => &stream["wsSettings"],
        "grpc" => &stream["grpcSettings"],
        "httpupgrade" => &stream["httpupgradeSettings"],
        _ => &Value::Null,
    };
    let fragment = escape(name);
    let mut query = vec![
        ("type", transport),
        ("security", tls),
        ("sni", sni),
        ("fp", origin),
    ];
    let path = text(&config["path"]);
    let host = config["host"]
        .as_str()
        .or_else(|| config["headers"]["Host"].as_str())
        .unwrap_or_default();
    query.extend([
        ("path", path),
        ("host", host),
        ("mode", text(&config["mode"])),
        ("serviceName", text(&config["serviceName"])),
    ]);
    let url = match protocol {
        "vless" => {
            let user = &server["users"][0];
            query.extend([
                ("encryption", text(&user["encryption"])),
                ("flow", text(&user["flow"])),
            ]);
            if tls == "reality" {
                query.extend([
                    ("pbk", text(&security["password"])),
                    ("sid", text(&security["shortId"])),
                ]);
            }
            query.retain(|(_, value)| !value.is_empty());
            format!(
                "vless://{}@{endpoint}?{}#{fragment}",
                text(&user["id"]),
                serde_urlencoded::to_string(query)?
            )
        }
        "vmess" => {
            let encoded = STANDARD.encode(serde_json::to_vec(&json!({
                "v":"2","ps":name,"add":address,"port":port.to_string(),"id":settings["id"],
                "aid":"0","scy":"auto","net":transport,"tls":tls,"type":"none","sni":sni,
                "host":host,"path":if transport == "grpc" {text(&config["serviceName"])} else {path},
                "fp":origin
            }))?);
            format!("vmess://{encoded}")
        }
        "trojan" => {
            query.retain(|(_, value)| !value.is_empty());
            format!(
                "trojan://{}@{endpoint}?{}#{fragment}",
                escape(text(&settings["password"])),
                serde_urlencoded::to_string(query)?
            )
        }
        "shadowsocks" => {
            let secret = format!(
                "{}:{}",
                text(&settings["method"]),
                text(&settings["password"])
            );
            format!(
                "ss://{}@{endpoint}#{fragment}",
                URL_SAFE_NO_PAD.encode(secret)
            )
        }
        "hysteria" => format!(
            "hysteria2://{}@{endpoint}/?{}#{fragment}",
            escape(text(&stream["hysteriaSettings"]["auth"])),
            serde_urlencoded::to_string([("sni", sni)])?
        ),
        _ => return Ok(None),
    };
    Ok(Some(ShareLink {
        name: name.into(),
        url,
    }))
}

pub(super) fn links(profiles: &Value) -> Result<Vec<ShareLink>> {
    profiles["profiles"]
        .as_array()
        .context("Missing profiles")?
        .iter()
        .filter_map(|profile| profile_link(profile).transpose())
        .collect()
}

fn native_kind(outbound: &Value) -> Option<&'static str> {
    match outbound["protocol"].as_str()? {
        "hysteria" => Some("native-hysteria"),
        "wireguard" => Some("native-wireguard"),
        "tuic" => Some("native-tuic"),
        "amneziawg" => Some("native-amneziawg"),
        _ => None,
    }
}

pub(super) fn native_list(profiles: &Value) -> Result<Value> {
    let rows = profiles["profiles"]
        .as_array()
        .context("Missing profiles")?;
    Ok(json!(
        rows.iter()
            .filter_map(|profile| {
                let kind = native_kind(&profile["outbound"])?;
                let id = crate::store::digest(text(&profile["name"]).as_bytes());
                Some(json!({"format":format!("{kind}/{id}"),"name":profile["name"]}))
            })
            .collect::<Vec<_>>()
    ))
}

pub(super) fn native_profile(profiles: &Value, kind: &str, id: &str) -> Result<Vec<u8>> {
    let rows = profiles["profiles"]
        .as_array()
        .context("Missing profiles")?;
    let profile = rows
        .iter()
        .find(|profile| {
            native_kind(&profile["outbound"]) == Some(kind)
                && crate::store::digest(text(&profile["name"]).as_bytes()) == id
        })
        .context("not_found")?;
    let outbound = &profile["outbound"];
    let settings = &outbound["settings"];
    if kind == "native-tuic" {
        return Ok(serde_json::to_vec_pretty(
            &crate::proxy_access::tuic::client(outbound, 1080),
        )?);
    }
    if matches!(kind, "native-wireguard" | "native-amneziawg") {
        let addresses = settings["address"]
            .as_array()
            .context("Missing WireGuard addresses")?;
        let peer = &settings["peers"][0];
        let addresses = addresses
            .iter()
            .map(|address| {
                let addr = text(address);
                format!("{addr}/{}", if addr.contains(':') { 128 } else { 32 })
            })
            .collect::<Vec<_>>()
            .join(", ");
        let parameters = if kind == "native-amneziawg" {
            crate::proxy_access::amneziawg::PARAMETERS
        } else {
            ""
        };
        return Ok(format!(
            "[Interface]\nPrivateKey = {}\nAddress = {addresses}\nMTU = 1280\n{parameters}\n[Peer]\nPublicKey = {}\nEndpoint = {}\nAllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 25\n",
            text(&settings["secretKey"]), text(&peer["publicKey"]), text(&peer["endpoint"]),
        ).into_bytes());
    }
    let address = text(&settings["address"]);
    let port = settings["port"].as_u64().context("Missing Hysteria port")?;
    Ok(serde_json::to_vec_pretty(&json!({
        "server":authority(address,port),
        "auth":outbound["streamSettings"]["hysteriaSettings"]["auth"],
        "tls":{"sni":outbound["streamSettings"]["tlsSettings"]["serverName"]},
        "socks5":{"listen":"127.0.0.1:1080"}
    }))?)
}

pub(super) fn qr_sheet(profiles: &Value) -> Result<Vec<u8>> {
    use qrcode::{Color, EcLevel, QrCode};
    use std::fmt::Write;
    let links = links(profiles)?;
    let rows = links.len().div_ceil(2);
    let height = rows * 560;
    let mut svg = format!(
        r#"<svg xmlns="http://www.w3.org/2000/svg" width="1080" height="{height}" viewBox="0 0 1080 {height}"><rect width="100%" height="100%" fill="white"/>"#
    );
    for (index, link) in links.iter().enumerate() {
        let code = QrCode::with_error_correction_level(link.url.as_bytes(), EcLevel::L)
            .context("Share link does not fit into a QR code")?;
        let width = code.width();
        let size = 500 / (width + 8);
        let x = (index % 2) * 540 + (540 - width * size) / 2;
        let y = (index / 2) * 560 + 20;
        let name = link
            .name
            .replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;");
        write!(
            svg,
            r#"<g transform="translate({x} {y}) scale({size})"><title>{name}</title><path d=""#
        )?;
        for (position, color) in code.to_colors().into_iter().enumerate() {
            if color == Color::Dark {
                write!(svg, "M{} {}h1v1h-1z", position % width, position / width)?;
            }
        }
        write!(
            svg,
            r#"" shape-rendering="crispEdges"/></g><text x="{}" y="{}" font-family="sans-serif" font-size="12" text-anchor="middle">{} · {name}</text>"#,
            x + width * size / 2,
            y + width * size + 20,
            index + 1
        )?;
    }
    svg.push_str("</svg>");
    Ok(svg.into_bytes())
}
