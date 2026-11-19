use crate::{
    config::Config,
    host, provision,
    store::{self, Store},
};
use anyhow::{Context, Result, ensure};
use std::{
    fs,
    path::{Path, PathBuf},
};

const ROOT: &str = "/etc/ssl/dmit/auth";
const ACME: &str = "/root/.acme.sh/acme.sh";

fn portal_dir(hostname: &str) -> Result<PathBuf> {
    ensure!(
        crate::config::domain(hostname),
        "Invalid authentication certificate hostname"
    );
    Ok(Path::new(ROOT).join(hostname))
}

pub(super) fn directory(config: &Config) -> Result<PathBuf> {
    let Some(hostname) = config.auth_domain() else {
        return Ok(PathBuf::from(&config.tls.domain_cert_dir));
    };
    let root = portal_dir(&hostname)?;
    let target = fs::read_link(root.join("current"))
        .context("Private authentication certificate missing")?;
    ensure!(
        target.parent() == Some(Path::new("certificates"))
            && target
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| {
                    name.len() == 64 && name.bytes().all(|byte| byte.is_ascii_hexdigit())
                }),
        "Invalid authentication certificate pointer"
    );
    Ok(root.join(target))
}

pub(crate) fn verify(config: &Config) -> Result<()> {
    if let Some(hostname) = config.auth_domain() {
        verify_files(&hostname, &directory(config)?)?;
    }
    Ok(())
}

fn verify_files(hostname: &str, directory: &Path) -> Result<()> {
    let fullchain = directory.join("fullchain.pem");
    let key = directory.join("privkey.pem");
    store::check_private(&key, false)?;
    let cert = fullchain.to_str().context("Invalid certificate path")?;
    let key = key.to_str().context("Invalid certificate path")?;
    host::command(
        "openssl",
        &["x509", "-in", cert, "-noout", "-checkend", "86400"],
    )?;
    host::command(
        "openssl",
        &[
            "verify",
            "-CApath",
            "/etc/ssl/certs",
            "-verify_hostname",
            hostname,
            "-untrusted",
            cert,
            cert,
        ],
    )?;
    let cert_pub = host::command("openssl", &["x509", "-in", cert, "-noout", "-pubkey"])?;
    let key_pub = host::command("openssl", &["pkey", "-in", key, "-pubout"])?;
    ensure!(
        cert_pub == key_pub,
        "Authentication certificate key mismatch"
    );
    Ok(())
}

pub(crate) fn activate(hostname: &str, source: &Path) -> Result<()> {
    host::linux_root()?;
    let root = portal_dir(hostname)?;
    verify_files(hostname, source)?;
    let fullchain = fs::read(source.join("fullchain.pem"))?;
    let key = fs::read(source.join("privkey.pem"))?;
    let target = Path::new("certificates").join(store::digest(&fullchain));
    let destination = root.join(&target);
    store::private_dir(&destination)?;
    store::atomic_write(&destination.join("fullchain.pem"), &fullchain)?;
    store::atomic_write(&destination.join("privkey.pem"), &key)?;
    verify_files(hostname, &destination)?;
    store::replace_link(&target, &root.join("current"))
}

pub(crate) fn verify_public_dns(config: &Config) -> Result<()> {
    let Some(hostname) = config.auth_domain() else {
        return Ok(());
    };
    #[cfg(feature = "integration-test")]
    if std::env::var("NODECTL_TEST_DNS").as_deref() == Ok("yes") {
        return Ok(());
    }
    for kind in ["A", "AAAA", "CNAME"] {
        let url = format!("https://cloudflare-dns.com/dns-query?name={hostname}&type={kind}");
        let response: serde_json::Value = serde_json::from_str(&host::command(
            "curl",
            &[
                "--disable",
                "--noproxy",
                "*",
                "--fail",
                "--silent",
                "--show-error",
                "--max-time",
                "10",
                "-H",
                "Accept: application/dns-json",
                &url,
            ],
        )?)?;
        ensure!(
            matches!(response["Status"].as_u64(), Some(0 | 3))
                && response
                    .get("Answer")
                    .is_none_or(|answer| { answer.as_array().is_some_and(Vec::is_empty) }),
            "Private authentication hostname must have no public A, AAAA, or CNAME record"
        );
    }
    Ok(())
}

pub(crate) fn issue(
    store: &Store,
    hostname: &str,
    token_file: &Path,
    zone: Option<&str>,
) -> Result<()> {
    host::linux_root()?;
    let root = portal_dir(hostname)?;
    store::check_private(token_file, false)?;
    let token = fs::read_to_string(token_file)?;
    let token = token.trim();
    ensure!(
        !token.is_empty() && !token.chars().any(char::is_whitespace),
        "Invalid protected DNS token"
    );
    ensure!(
        zone.is_none_or(|zone| zone.len() == 32 && zone.bytes().all(|b| b.is_ascii_hexdigit())),
        "Invalid Cloudflare zone ID"
    );
    let acme_home = store.state_dir.join("auth-acme");
    let stage = root.join("renewal");
    store::private_dir(&acme_home)?;
    store::private_dir(&stage)?;
    let home = acme_home.to_str().context("Invalid ACME directory")?;
    let mut env = vec![("CF_Token", token)];
    if let Some(zone) = zone {
        env.push(("CF_Zone_ID", zone));
    }
    provision::long_command_in(
        ACME,
        &[
            "--config-home",
            home,
            "--issue",
            "--server",
            "letsencrypt",
            "--dns",
            "dns_cf",
            "--keylength",
            "ec-256",
            "-d",
            hostname,
        ],
        &env,
        None,
        &[0, 2],
    )?;
    let stage_path = stage
        .to_str()
        .context("Invalid certificate staging directory")?;
    ensure!(crate::config::abs_path(stage_path), "Unsafe renewal path");
    let reload = format!(
        "/usr/local/bin/nodectl activate-auth-certificate --hostname {hostname} --source {stage_path}"
    );
    let cert = stage.join("fullchain.pem");
    let key = stage.join("privkey.pem");
    if !key.exists() {
        store::atomic_write(&key, b"")?;
    }
    provision::long_command(
        ACME,
        &[
            "--config-home",
            home,
            "--install-cert",
            "--ecc",
            "-d",
            hostname,
            "--fullchain-file",
            cert.to_str().context("Invalid certificate path")?,
            "--key-file",
            key.to_str().context("Invalid certificate path")?,
            "--reloadcmd",
            &reload,
        ],
        &env,
    )?;
    activate(hostname, &stage)?;
    // Keep the node's existing acme.sh schedule and credentials independent.
    ensure!(crate::config::abs_path(home), "Unsafe renewal path");
    let service = "[Unit]\nDescription=Renew private nodectl authentication certificates\n[Service]\nType=oneshot\nUMask=0077\n";
    let timer = "[Unit]\nDescription=Schedule private nodectl certificate renewal\n[Timer]\nOnCalendar=*-*-* 03,15:00:00\nRandomizedDelaySec=1h\nPersistent=true\n[Install]\nWantedBy=timers.target\n";
    store::atomic_write(
        Path::new("/etc/systemd/system/nodectl-auth-certificate.service"),
        format!("{service}ExecStart={ACME} --cron --config-home {home}\n").as_bytes(),
    )?;
    store::atomic_write(
        Path::new("/etc/systemd/system/nodectl-auth-certificate.timer"),
        timer.as_bytes(),
    )?;
    host::command("systemctl", &["daemon-reload"])?;
    host::command(
        "systemctl",
        &["enable", "--now", "nodectl-auth-certificate.timer"],
    )?;
    Ok(())
}
