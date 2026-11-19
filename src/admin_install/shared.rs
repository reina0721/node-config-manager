use super::{CONFIG, MARKER, ROOT, verify_api_ready};
use crate::{
    config::Config,
    host,
    store::{self, Store},
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::{Path, PathBuf},
};

const API: &str = "/etc/systemd/system/nodectl-admin.service";
const SNIPPET: &str = "/etc/nodectl-admin/shared.d/console.conf";

#[derive(Serialize, Deserialize)]
struct ServiceBefore {
    enabled: String,
    active: bool,
}

impl ServiceBefore {
    fn capture(name: &str) -> Result<Self> {
        let state = host::service_state(name)?;
        Ok(Self {
            enabled: state.enabled,
            active: state.active,
        })
    }

    fn restore(&self, name: &str) -> Result<()> {
        let state = host::service_state(name)?;
        if state.enabled != self.enabled {
            match self.enabled.as_str() {
                "enabled" => {
                    host::command("systemctl", &["enable", name])?;
                }
                "enabled-runtime" => {
                    host::command("systemctl", &["enable", "--runtime", name])?;
                }
                _ if state.enabled.starts_with("enabled") => {
                    host::command("systemctl", &["disable", name])?;
                }
                _ => {}
            }
        }
        if self.active {
            host::command("systemctl", &["restart", name])?;
        } else if state.active {
            host::command("systemctl", &["stop", name])?;
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
struct Journal {
    api: Option<String>,
    snippet: Option<String>,
    current: Option<PathBuf>,
    api_service: ServiceBefore,
    legacy_service: ServiceBefore,
}

fn destination() -> PathBuf {
    Path::new(ROOT).join("current")
}

fn journal(store: &Store) -> PathBuf {
    crate::admin_auth::directory(store).join("shared-console.json")
}

fn owned(path: &str) -> Result<Option<String>> {
    match fs::symlink_metadata(path) {
        Ok(meta) => {
            ensure!(meta.is_file(), "Refusing unmanaged console path {path}");
            let contents = fs::read_to_string(path)?;
            ensure!(
                contents.starts_with(MARKER),
                "Refusing unmanaged console path {path}"
            );
            Ok(Some(contents))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn restore_file(path: &str, content: Option<String>) -> Result<()> {
    if let Some(content) = content {
        store::atomic_write(Path::new(path), content.as_bytes())
    } else {
        remove(path)
    }
}

fn remove(path: impl AsRef<Path>) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

pub(super) fn recover(store: &Store, config: &Config) -> Result<()> {
    let path = journal(store);
    store::check_private(&path, false)?;
    let previous: Journal = serde_json::from_slice(&fs::read(&path)?)?;
    restore_file(API, previous.api)?;
    restore_file(SNIPPET, previous.snippet)?;
    if let Some(source) = previous.current {
        store::replace_link(&source, &destination())?;
    } else {
        remove(destination())?;
    }
    host::command("systemctl", &["daemon-reload"])?;
    previous.api_service.restore("nodectl-admin")?;
    previous.legacy_service.restore("nodectl-admin-nginx")?;
    reload(config)?;
    remove(path)
}

fn reload(config: &Config) -> Result<()> {
    host::command(
        &config.runtime.nginx_binary,
        &["-t", "-c", "/etc/nginx/nginx.conf"],
    )?;
    host::command("systemctl", &["reload", "nginx"])?;
    Ok(())
}

pub(super) fn activate(
    store: &Store,
    config: &Config,
    digest: &str,
    api: &str,
    csp: &str,
) -> Result<()> {
    let path = journal(store);
    ensure!(
        !path.exists(),
        "Recover the interrupted shared console installation first"
    );
    let current = store
        .pointer("current")?
        .context("Apply the shared HTTPS console configuration first")?;
    let applied = store.verify(&current)?.0;
    ensure!(
        applied.shared_console && applied.node.domain == config.node.domain,
        "Apply the shared HTTPS console configuration first"
    );
    store::private_dir(Path::new(CONFIG))?;
    store::private_dir(Path::new(SNIPPET).parent().unwrap())?;
    let before = Journal {
        api: owned(API)?,
        snippet: owned(SNIPPET)?,
        current: fs::read_link(destination()).ok(),
        api_service: ServiceBefore::capture("nodectl-admin")?,
        legacy_service: ServiceBefore::capture("nodectl-admin-nginx")?,
    };
    ensure!(
        !destination().exists() || before.current.is_some(),
        "Refusing unmanaged console root"
    );
    store::atomic_write(&path, &serde_json::to_vec(&before)?)?;
    host::checkpoint("shared-console-journal")?;
    let result = (|| -> Result<()> {
        store::replace_link(&Path::new("releases").join(digest), &destination())?;
        store::atomic_write(Path::new(API), api.as_bytes())?;
        store::atomic_write(Path::new(SNIPPET), locations(config, csp).as_bytes())?;
        host::command(
            &config.runtime.nginx_binary,
            &["-t", "-c", "/etc/nginx/nginx.conf"],
        )?;
        host::command("systemctl", &["daemon-reload"])?;
        host::command("systemctl", &["enable", "nodectl-admin"])?;
        host::command("systemctl", &["restart", "nodectl-admin"])?;
        verify_api_ready()?;
        host::checkpoint("shared-console-reload")?;
        reload(config)?;
        verify_https(config)?;
        if before.legacy_service.active || before.legacy_service.enabled.starts_with("enabled") {
            host::command("systemctl", &["disable", "--now", "nodectl-admin-nginx"])?;
        }
        remove(&path)
    })();
    if result.is_err() {
        recover(store, config).context("Shared console recovery incomplete")?;
    }
    result
}

fn verify_https(config: &Config) -> Result<()> {
    let host = &config.node.domain;
    let resolve = format!("{host}:443:127.0.0.1");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(8);
    while std::time::Instant::now() < deadline {
        let status = |path: &str| {
            host::command(
                "curl",
                &[
                    "--disable",
                    "--noproxy",
                    "*",
                    "--silent",
                    "--max-time",
                    "2",
                    "--resolve",
                    &resolve,
                    "-o",
                    "/dev/null",
                    "-w",
                    "%{http_code}",
                    &format!("https://{host}{path}"),
                ],
            )
        };
        if status("/nc/").is_ok_and(|code| code == "200")
            && status("/nc/api/session").is_ok_and(|code| code == "401")
        {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
    anyhow::bail!("The shared HTTPS console did not become ready")
}

fn locations(c: &Config, csp: &str) -> String {
    let domain = &c.node.domain;
    let guard = format!(
        "if ($host != {domain}) {{ return 404; }}\nif ($ssl_server_name != {domain}) {{ return 404; }}"
    );
    let headers = format!(
        r#"
        access_log off;
        error_log /dev/null;
        add_header X-Content-Type-Options nosniff always;
        add_header Referrer-Policy no-referrer always;
        add_header X-Frame-Options DENY always;
        add_header Cache-Control "private, no-store" always;
        add_header Content-Security-Policy "{csp}" always;"#
    );
    let api = r#"
        client_max_body_size 128k;
        limit_req_status 429;
        proxy_pass http://127.0.0.1:9080;
        proxy_set_header Host $host;
        proxy_cache off;
        proxy_buffering off;"#;
    format!(
        r#"{MARKER}
    location = /nc {{
        {guard}
        return 308 /nc/;
    }}
    location = /nc/api/login {{
        {guard}
        {headers}
        {api}
        limit_req zone=nc_login burst=3 nodelay;
        proxy_read_timeout 15s;
    }}
    location ^~ /nc/api/ {{
        {guard}
        {headers}
        {api}
        limit_req zone=nc_requests burst=20 nodelay;
        proxy_read_timeout 180s;
    }}
    location ^~ /nc/ {{
        {guard}
        {headers}
        root {ROOT}/current;
        try_files $uri $uri/index.html =404;
    }}
"#
    )
}
