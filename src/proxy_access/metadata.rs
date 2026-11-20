use crate::store::Store;
use serde::{Deserialize, Serialize};
use std::{
    io::Write,
    net::IpAddr,
    path::PathBuf,
    process::{Command, Stdio},
};
const MAX_DATABASE_BYTES: u64 = 128 * 1024 * 1024;

fn geoip_path(store: &Store) -> PathBuf {
    store.state_dir.join("proxy-access/geoip.mmdb")
}

pub(super) fn prepare_location_db(store: &Store) -> anyhow::Result<()> {
    let path = geoip_path(store);
    if path.exists() {
        return crate::store::check_private(&path, false);
    }
    let parent = path.parent().expect("private device state path");
    crate::store::check_private(parent, true)?;
    let mut source = tempfile::NamedTempFile::new_in(parent)?;
    source.write_all(&crate::artifacts::locked_asset("device-geodata", "city")?)?;
    source.flush()?;
    let output = tempfile::NamedTempFile::new_in(parent)?;
    let result = Command::new("/usr/bin/gzip")
        .args(["-dc", "--"])
        .arg(source.path())
        .stdout(output.reopen()?)
        .stderr(Stdio::null())
        .status()?;
    anyhow::ensure!(
        result.success() && output.as_file().metadata()?.len() <= MAX_DATABASE_BYTES,
        "Invalid IP geolocation database archive"
    );
    // The destination is immutable in place. Readers may map the old inode
    // while a verified replacement is published by atomic rename.
    unsafe { maxminddb::Reader::open_mmap(output.path()) }?;
    output.as_file().sync_all()?;
    output.persist_noclobber(&path)?;
    std::fs::File::open(parent)?.sync_all()?;
    Ok(())
}

#[derive(Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
pub(super) struct DeviceInfo {
    pub last_login: Option<u64>,
    pub source_ip: Option<IpAddr>,
    pub source_observed_at: Option<u64>,
    pub location: Option<Location>,
    pub system: Option<String>,
    pub system_version: Option<String>,
    pub client: Option<ClientReport>,
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
pub(super) struct Location {
    country: Option<String>,
    region: Option<String>,
    city: Option<String>,
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
pub(super) struct ClientReport {
    name: String,
    version: Option<String>,
}

impl DeviceInfo {
    pub(super) fn is_empty(&self) -> bool {
        self == &Self::default()
    }

    pub(super) fn browser(
        &mut self,
        agent: Option<&str>,
        platform: Option<&str>,
        release: Option<&str>,
    ) {
        let system = match platform.map(unquote) {
            Some("Windows") => Some("Windows"),
            Some("macOS") => Some("macOS"),
            Some("Android") => Some("Android"),
            Some("iOS") => Some("iOS"),
            Some("Linux") => Some("Linux"),
            Some("Chrome OS") => Some("ChromeOS"),
            _ => agent.and_then(|agent| {
                [
                    ("iPhone", "iOS"),
                    ("iPad", "iPadOS"),
                    ("Android", "Android"),
                    ("Windows NT", "Windows"),
                    ("CrOS", "ChromeOS"),
                    ("Macintosh", "macOS"),
                    ("Linux", "Linux"),
                ]
                .into_iter()
                .find_map(|(marker, name)| agent.contains(marker).then_some(name))
            }),
        };
        self.system = system.map(str::to_owned);
        self.system_version = match (system, release.map(unquote).and_then(numeric_version)) {
            (Some("Windows"), Some(version)) => {
                match version
                    .split('.')
                    .next()
                    .and_then(|v| v.parse::<u32>().ok())
                {
                    Some(13..) => Some("11".to_owned()),
                    Some(1..=10) => Some("10".to_owned()),
                    _ => None,
                }
            }
            (Some("macOS" | "Android" | "iOS" | "iPadOS" | "ChromeOS"), Some(version)) => {
                Some(version.to_owned())
            }
            (Some("iOS" | "iPadOS"), None) => agent
                .and_then(|agent| agent.split_once(" OS ").map(|(_, tail)| tail))
                .and_then(|tail| tail.split_whitespace().next())
                .and_then(numeric_version)
                .map(|version| version.replace('_', ".")),
            _ => None,
        };
    }
}

fn unquote(value: &str) -> &str {
    value.trim().trim_matches('"')
}

fn numeric_version(value: &str) -> Option<&str> {
    let length = value.len();
    ((1..=32).contains(&length)
        && value
            .split(['.', '_'])
            .all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()))
        && value.bytes().any(|b| b.is_ascii_digit() && b != b'0'))
    .then_some(value)
}

pub(super) fn client_report(agent: &str) -> Option<ClientReport> {
    let product = agent.split_ascii_whitespace().next()?;
    let (name, version) = product.split_once('/').unwrap_or((product, ""));
    let name = match name.to_ascii_lowercase().as_str() {
        "mihomo" => "Mihomo",
        "clash.meta" | "clash-meta" => "Clash.Meta",
        "clash" => "Clash",
        "clash-verge" => "Clash Verge",
        "clashforandroid" => "Clash for Android",
        "xray" => "Xray",
        _ => return None,
    };
    let version = version.trim_start_matches('v');
    let version = ((1..=48).contains(&version.len())
        && version.as_bytes()[0].is_ascii_digit()
        && version
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'+' | b'_')))
    .then(|| version.to_owned());
    Some(ClientReport {
        name: name.into(),
        version,
    })
}

pub(super) fn public_address(address: IpAddr) -> bool {
    match address.to_canonical() {
        IpAddr::V4(ip) => {
            let [a, b, c, _] = ip.octets();
            !ip.is_private()
                && !ip.is_loopback()
                && !ip.is_link_local()
                && !ip.is_documentation()
                && !(a == 0
                    || a >= 224
                    || a == 100 && (64..=127).contains(&b)
                    || a == 192 && b == 0 && c == 0
                    || a == 198 && (18..=19).contains(&b))
        }
        IpAddr::V6(ip) => {
            let [first, second, ..] = ip.segments();
            first & 0xe000 == 0x2000 && !(first == 0x2001 && second == 0x0db8)
        }
    }
}

#[derive(Deserialize)]
struct GeoNames {
    en: Option<String>,
    #[serde(rename = "zh-CN")]
    chinese: Option<String>,
}

#[derive(Deserialize)]
struct GeoPart {
    names: Option<GeoNames>,
    iso_code: Option<String>,
}

impl GeoPart {
    fn label(self) -> Option<String> {
        self.names
            .and_then(|names| names.chinese.or(names.en))
            .or(self.iso_code)
    }
}

#[derive(Deserialize)]
struct GeoRecord {
    country: Option<GeoPart>,
    #[serde(default)]
    subdivisions: Vec<GeoPart>,
    city: Option<GeoPart>,
}

pub(super) fn location(store: &Store, address: IpAddr) -> Option<Location> {
    let path = geoip_path(store);
    crate::store::check_private(&path, false).ok()?;
    if std::fs::metadata(&path).ok()?.len() > MAX_DATABASE_BYTES {
        return None;
    }
    // The database is protected and installed once via atomic rename.
    let reader = unsafe { maxminddb::Reader::open_mmap(path) }.ok()?;
    let record: GeoRecord = reader
        .lookup(address.to_canonical())
        .ok()?
        .decode()
        .ok()??;
    let result = Location {
        country: record.country.and_then(GeoPart::label),
        region: record
            .subdivisions
            .into_iter()
            .last()
            .and_then(GeoPart::label),
        city: record.city.and_then(GeoPart::label),
    };
    (result.country.is_some() || result.region.is_some() || result.city.is_some()).then_some(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trusted_sources_and_optional_browser_fields() {
        let mut info = DeviceInfo::default();
        info.browser(Some("Mozilla/5.0 (Windows NT 10.0)"), None, None);
        assert_eq!(info.system.as_deref(), Some("Windows"));
        assert_eq!(info.system_version, None);
        info.browser(None, Some("\"Windows\""), Some("\"15.0.0\""));
        assert_eq!(info.system_version.as_deref(), Some("11"));
        info.browser(Some("Mozilla (X11; Linux x86_64)"), None, None);
        assert_eq!(info.system.as_deref(), Some("Linux"));
        assert_eq!(info.system_version, None);
        assert!(public_address("8.8.4.4".parse().unwrap()));
        assert!(public_address("2606:4700:4700::1111".parse().unwrap()));
        assert!(!public_address("::ffff:127.0.0.1".parse().unwrap()));
        assert!(!public_address("100.64.10.1".parse().unwrap()));
        assert_eq!(
            client_report("Mihomo/v1.19.32").unwrap().version.as_deref(),
            Some("1.19.32")
        );
        assert!(client_report("Mozilla/5.0").is_none());
    }
}
