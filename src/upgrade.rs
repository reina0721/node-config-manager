use crate::{
    admin_auth, host, proxy_access,
    store::{self, Store},
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

const REPOSITORY: &str = "reina0721/node-config-manager";
const UNIT: &str = "nodectl-admin-version-switch";
const TIME_LIMIT: u64 = 30 * 60;
const WEB_MINIMUM: [u64; 3] = [0, 6, 5];
const ACCESS_MINIMUM: [u64; 3] = [0, 7, 1];
const MANAGEMENT_MINIMUM: [u64; 3] = [0, 8, 0];
const TRANSPORT_MINIMUM: [u64; 3] = [0, 8, 2];
const TRAFFIC_CYCLE_MINIMUM: [u64; 3] = [0, 10, 0];
const SHARED_CONSOLE_MINIMUM: [u64; 3] = [0, 11, 0];

#[derive(Serialize, Deserialize)]
struct Switch {
    target: String,
    started: u64,
    finished: Option<u64>,
    ok: Option<bool>,
}

fn status_file(store: &Store) -> PathBuf {
    admin_auth::directory(store).join("version-switch.json")
}

fn status(store: &Store) -> Result<Option<Switch>> {
    let path = status_file(store);
    if !path.exists() {
        return Ok(None);
    }
    store::check_private(&path, false)?;
    let mut switch: Switch = serde_json::from_slice(&fs::read(path)?)?;
    if switch.finished.is_none()
        && admin_auth::now().saturating_sub(switch.started) > TIME_LIMIT + 10
    {
        switch.finished = Some(switch.started + TIME_LIMIT);
        switch.ok = Some(false);
    }
    Ok(Some(switch))
}

fn save(store: &Store, value: &Switch) -> Result<()> {
    store::atomic_write(&status_file(store), &serde_json::to_vec(value)?)
}

pub fn pending(store: &Store) -> Result<bool> {
    Ok(status(store)?.is_some_and(|s| s.finished.is_none()))
}

fn stable_version(input: &str) -> Result<[u64; 3]> {
    let parts: Vec<_> = input
        .strip_prefix('v')
        .unwrap_or(input)
        .split('.')
        .collect();
    ensure!(parts.len() == 3, "bad_request");
    let mut version = [0; 3];
    for (value, part) in version.iter_mut().zip(parts) {
        ensure!(
            !part.is_empty()
                && part.bytes().all(|b| b.is_ascii_digit())
                && (part.len() == 1 || !part.starts_with('0')),
            "bad_request"
        );
        *value = part.parse().map_err(|_| anyhow::anyhow!("bad_request"))?;
    }
    Ok(version)
}

pub fn validate_web(store: &Store, input: &str) -> Result<String> {
    let version = stable_version(input)?;
    ensure!(version >= WEB_MINIMUM, "bad_request");
    validate_compatibility(store, version)?;
    Ok(format!("v{}.{}.{}", version[0], version[1], version[2]))
}

fn validate_compatibility(store: &Store, version: [u64; 3]) -> Result<()> {
    ensure!(
        version >= ACCESS_MINIMUM || !proxy_access::enabled(store)?,
        "version_auth_incompatible"
    );
    if version < stable_version(env!("CARGO_PKG_VERSION"))? {
        let minimum = snapshot_minimum(store)?;
        ensure!(
            version >= minimum,
            if minimum >= TRANSPORT_MINIMUM {
                "version_snapshot_incompatible"
            } else {
                "version_management_incompatible"
            }
        );
    }
    Ok(())
}

fn snapshot_minimum(store: &Store) -> Result<[u64; 3]> {
    let mut minimum = if proxy_access::has_traffic_cycles(store)? {
        TRAFFIC_CYCLE_MINIMUM
    } else if proxy_access::has_account_policies(store)? || crate::fleet::has_records(store)? {
        MANAGEMENT_MINIMUM
    } else {
        WEB_MINIMUM
    };
    if proxy_access::has_client_definitions(store)? {
        minimum = minimum.max(SHARED_CONSOLE_MINIMUM);
    }
    for pointer in ["current", "previous"] {
        if let Some(id) = store.pointer(pointer)? {
            let (config, _, manifest) = store.verify_with_manifest(&id)?;
            let generator = stable_version(&manifest.generator_version)?;
            if config.shared_console || config.auth_portal.is_some() {
                minimum = minimum.max(SHARED_CONSOLE_MINIMUM);
            }
            if generator >= TRANSPORT_MINIMUM {
                minimum = minimum.max(generator);
            } else if config.management.is_some() {
                minimum = minimum.max(MANAGEMENT_MINIMUM);
            }
        }
    }
    Ok(minimum)
}

#[derive(Deserialize)]
struct Release {
    tag_name: String,
    draft: bool,
    prerelease: bool,
    assets: Vec<ReleaseAsset>,
}
#[derive(Deserialize)]
struct ReleaseAsset {
    name: String,
}

fn available() -> Result<Vec<String>> {
    let arch = match std::env::consts::ARCH {
        "x86_64" => "x86_64",
        "aarch64" => "aarch64",
        _ => anyhow::bail!("Unsupported release architecture"),
    };
    let output = host::command(
        "curl",
        &[
            "--disable",
            "--proto",
            "=https",
            "--proto-redir",
            "=https",
            "--tlsv1.2",
            "--fail",
            "--silent",
            "--show-error",
            "--connect-timeout",
            "4",
            "--max-time",
            "8",
            "--max-filesize",
            "2097152",
            &format!("https://api.github.com/repos/{REPOSITORY}/releases?per_page=30"),
        ],
    )?;
    let releases: Vec<Release> = serde_json::from_str(&output)?;
    let mut result = vec![];
    for release in releases {
        if release.draft || release.prerelease {
            continue;
        }
        let Ok(version) = stable_version(&release.tag_name) else {
            continue;
        };
        let archive = format!(
            "nodectl-{}-{arch}-unknown-linux-gnu.tar.gz",
            release.tag_name
        );
        if version >= WEB_MINIMUM
            && [archive.as_str(), "SHA256SUMS", "SHA256SUMS.sigstore.json"]
                .iter()
                .all(|name| release.assets.iter().any(|asset| &asset.name == name))
        {
            result.push((version, release.tag_name));
        }
    }
    result.sort_unstable_by_key(|release| std::cmp::Reverse(release.0));
    Ok(result.into_iter().map(|(_, tag)| tag).collect())
}

pub fn versions(store: &Store) -> Result<Value> {
    let running = format!("v{}", env!("CARGO_PKG_VERSION"));
    let releases = available();
    let proxy_access = proxy_access::enabled(store)?;
    let minimum = snapshot_minimum(store)?.max(if proxy_access {
        ACCESS_MINIMUM
    } else {
        WEB_MINIMUM
    });
    Ok(json!({
        "running":running,
        "lookup_failed":releases.is_err(),
        "releases":releases.unwrap_or_default(),
        "status":status(store)?,
        "proxy_access_enabled":proxy_access,
        "minimum_version":format!("v{}.{}.{}", minimum[0], minimum[1], minimum[2]),
    }))
}

pub fn schedule(store: &Store, version: &str, port: u16) -> Result<()> {
    let target = validate_web(store, version)?;
    let _guard = store.lock()?;
    ensure!(!pending(store)?, "version_switch_pending");
    ensure!(
        std::env::current_exe()? == Path::new("/usr/local/bin/nodectl"),
        "Online version switching requires the standard nodectl installation"
    );
    let mut state = Switch {
        target,
        started: admin_auth::now(),
        finished: None,
        ok: None,
    };
    save(store, &state)?;
    let result = host::command(
        "systemd-run",
        &[
            &format!("--unit={UNIT}"),
            "--on-active=3s",
            "--timer-property=AccuracySec=100ms",
            "--timer-property=RandomizedDelaySec=0",
            "--property=RuntimeMaxSec=30min",
            "--collect",
            "/usr/local/bin/nodectl",
            "--config-dir",
            store
                .config_dir
                .to_str()
                .context("Invalid configuration directory")?,
            "--state-dir",
            store
                .state_dir
                .to_str()
                .context("Invalid state directory")?,
            "admin",
            "switch-version",
            "--version",
            &state.target,
            "--port",
            &port.to_string(),
        ],
    );
    if result.is_err() {
        state.finished = Some(admin_auth::now());
        state.ok = Some(false);
        save(store, &state)?;
    }
    result.map(|_| ())
}

pub fn switch(store: &Store, version: &str, port: u16) -> Result<()> {
    let mut state = status(store)?.context("Version switch was not scheduled")?;
    ensure!(
        state.finished.is_none() && state.target == version,
        "Version switch was not scheduled"
    );
    let result = (|| {
        validate_web(store, version)?;
        installer(store, version, Path::new("/usr/local"), true, Some(port))
    })();
    state.finished = Some(admin_auth::now());
    state.ok = Some(result.is_ok());
    save(store, &state)?;
    result
}

pub fn run(store: &Store, version: &str, prefix: &Path, execute: bool) -> Result<()> {
    let _lock = if execute { Some(store.lock()?) } else { None };
    if execute {
        validate_compatibility(store, stable_version(version)?)?;
    }
    installer(store, version, prefix, execute, None)
}

fn installer(
    store: &Store,
    version: &str,
    prefix: &Path,
    execute: bool,
    admin_port: Option<u16>,
) -> Result<()> {
    ensure!(prefix.is_absolute(), "Installation prefix must be absolute");
    let script = include_str!("../install.sh");
    let mut command = Command::new("/bin/sh");
    command.args(["-s", "--"]);
    if let Some(port) = admin_port {
        command.args(["--switch-admin", "--admin-port", &port.to_string()]);
    } else {
        command.arg("--install-only");
    }
    command
        .args(["--version", version, "--prefix"])
        .arg(prefix)
        .arg("--config-dir")
        .arg(&store.config_dir)
        .arg("--state-dir")
        .arg(&store.state_dir)
        .arg(if execute { "--execute" } else { "--dry-run" })
        .env_clear()
        .env("PATH", "/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
        .stdin(Stdio::piped());
    for name in [
        "http_proxy",
        "https_proxy",
        "all_proxy",
        "no_proxy",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "NO_PROXY",
        "CURL_CA_BUNDLE",
        "SSL_CERT_FILE",
    ] {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    let mut child = command
        .spawn()
        .context("Cannot start trusted embedded installer")?;
    child
        .stdin
        .take()
        .context("Missing installer input")?
        .write_all(script.as_bytes())?;
    ensure!(
        child.wait()?.success(),
        "Signed installation or console activation failed"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::process::{Command, Stdio};

    #[test]
    fn action_flags_do_not_override_console_switch_mode() {
        for args in [
            ["--switch-admin", "--dry-run"],
            ["--dry-run", "--switch-admin"],
        ] {
            let mut installer = Command::new("/bin/sh")
                .args(["-s", "--", "--version", "v0.6.5"])
                .args(args)
                .stdin(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            installer
                .stdin
                .take()
                .unwrap()
                .write_all(include_bytes!("../install.sh"))
                .unwrap();
            let result = installer.wait_with_output().unwrap();
            assert!(!result.status.success());
            assert!(
                String::from_utf8_lossy(&result.stderr)
                    .contains("Console switching requires root and --execute")
            );
        }
    }
}
