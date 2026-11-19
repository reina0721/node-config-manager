use crate::{
    admin_auth,
    store::{self, Store},
};
use anyhow::{Context, Result};
use serde_json::{Value, json};
use std::fs;

pub fn panel(store: &Store) -> Result<Value> {
    let config = store.inputs().ok().map(|(config, _)| config);
    let access = crate::proxy_access::list(store)?;
    Ok(json!({
        "administrator_configured":admin_auth::generation(store).is_ok(),
        "session_lifetime":admin_auth::SESSION_LIFETIME,
        "session_idle_timeout":admin_auth::SESSION_IDLE_TIMEOUT,
        "subscription_enabled":config.is_some_and(|c| c.distributes()),
        "subscription_access":crate::share::access_status(store),
        "browser_access":access["enabled"],
        "browser_ttl":access["ttl_seconds"],
    }))
}

pub fn xray(store: &Store) -> Result<Value> {
    let _guard = store.lock()?;
    let id = store.pointer("current")?.context("not_deployed")?;
    let (config, _) = store.verify(&id)?;
    let path = store.release(&id)?.join("xray.json");
    store::check_private(&path, false)?;
    let mut content: Value = serde_json::from_slice(&fs::read(path)?)?;
    fn redact(value: &mut Value) {
        if let Some(fields) = value.as_object_mut() {
            for (key, value) in fields {
                if [
                    "clients",
                    "users",
                    "accounts",
                    "privateKey",
                    "secretKey",
                    "preSharedKey",
                    "shortIds",
                    "decryption",
                    "encryption",
                    "id",
                    "user",
                    "pass",
                    "password",
                    "auth",
                ]
                .contains(&key.as_str())
                {
                    *value = json!("<redacted>");
                } else {
                    redact(value);
                }
            }
        } else if let Some(items) = value.as_array_mut() {
            items.iter_mut().for_each(redact);
        }
    }
    redact(&mut content);
    Ok(json!({
        "release":id, "configuration":content, "encrypted":config.encrypted(),
        "browser_access":crate::proxy_access::enabled(store)?,
        "managed_routing":crate::egress::needs_ingress(&config)
    }))
}

pub fn openapi() -> Value {
    let mut paths = serde_json::Map::new();
    let json_content = |schema: Value| json!({"application/json":{"schema":schema}});
    let error = |description: &str| {
        json!({"description":description, "content":json_content(
            json!({"$ref":"#/components/schemas/Error"})
        )})
    };
    let mut add = |path: &str, method: &str, summary: &str, body: Option<Value>, task: bool| {
        let ok = if task {
            json!({"$ref":"#/components/schemas/Task"})
        } else {
            json!({})
        };
        let mut operation = json!({
            "summary":summary, "responses":{
                "200":{"description":"Success", "content":json_content(ok)},
                "400":error("Invalid input or operation failed"),
                "401":error("Session expired or missing"),
                "403":error("Origin, CSRF, or access policy denied"),
                "404":error("Resource does not exist"),
                "409":error("Stale plan or another operation is running"),
                "429":error("Too many requests")
            }
        });
        if let Some(body) = body {
            operation["security"] = json!([{"session":[],"csrf":[]}]);
            operation["requestBody"] = json!({"required":true,"content":json_content(body)});
        }
        if path.contains("{job}") {
            operation["parameters"] = json!([{"in":"path","name":"job","required":true,"schema":{"type":"string","pattern":"^[a-f0-9]{64}$"}}]);
        }
        paths.entry(path).or_insert_with(|| json!({}))[method] = operation;
    };
    for (path, summary) in [
        (
            "/session",
            "Read or refresh the current session and its CSRF token",
        ),
        ("/overview", "Node version, health, and service status"),
        (
            "/config",
            "Typed configuration, revision and supported inbound combinations",
        ),
        ("/nodes", "Active subscription and protocol entry points"),
        ("/services", "Managed services and active state"),
        ("/network", "Network and WARP status"),
        ("/dns", "DNS and certificates"),
        (
            "/operations",
            "Operation history and configuration snapshots",
        ),
        ("/jobs/{job}", "Read a task until finished is non-null"),
        (
            "/versions",
            "Signed release versions and last switch result",
        ),
        ("/proxy-access", "Account, device and traffic status"),
        ("/proxy-access/export", "Export usernames and device limits"),
        ("/fleet", "Registered peers and granted scopes"),
        (
            "/catalogue/copy-source",
            "Read the resource definitions and revision available for copying",
        ),
        ("/panel", "Administration and authorization settings"),
        ("/xray", "Redacted active Xray snapshot"),
        ("/openapi", "This OpenAPI definition"),
    ] {
        add(path, "get", summary, None, false);
    }
    for (path, summary, body, task) in [
        (
            "/outbounds/test",
            "Probe an applied upstream using the pinned Xray client",
            json!({"type":"object","required":["id"],"properties":{"id":{"type":"string","format":"uuid"}}}),
            true,
        ),
        (
            "/catalogue/preview",
            "Preview one typed object change",
            json!({"type":"object","required":["kind"],"properties":{
                "base":{"type":"string","description":"Configuration revision from GET /config"},
                "id":{"type":["string","null"],"format":"uuid"},
                "kind":{"enum":["host","inbound","group","upstream","rule"]},"value":{"type":["object","null"]},
                "credential":{"type":"object","writeOnly":true},"clear_credential":{"type":"boolean"}
            }}),
            false,
        ),
        (
            "/fleet/copy-preview",
            "Preview copying resource definitions into disabled drafts on the target",
            json!({"type":"object","required":["source","target","source_base","target_base","request","resources"],"properties":{
                "source":{"type":"string","description":"Local node or registered peer ID"},
                "target":{"type":"string","description":"Local node or registered peer ID"},
                "source_base":{"type":"string"},"target_base":{"type":"string"},
                "request":{"type":"string","format":"uuid","description":"Stable transfer identifier"},
                "resources":{"type":"array","items":{"type":"object","required":["kind","id"],"properties":{
                    "kind":{"enum":["inbound","host","group","upstream","rule"]},"id":{"type":"string","format":"uuid"}
                }}}
            }}),
            false,
        ),
        (
            "/routing/match",
            "Check the first custom match against supplied destination fields",
            json!({"type":"object","required":["inbound","port","network"],"properties":{
                "inbound":{"type":"string"},"domain":{"type":"string"},"ip":{"type":"string"},
                "port":{"type":"integer","minimum":1,"maximum":65535},"network":{"enum":["tcp","udp"]}
            }}),
            false,
        ),
        (
            "/config/check",
            "Check a candidate; poll the returned job",
            json!({"type":"object","required":["plan"],"properties":{"plan":{"type":"string"}}}),
            true,
        ),
        (
            "/config/apply",
            "Apply a checked candidate; confirm must equal plan",
            json!({"type":"object","required":["plan","confirm"],"properties":{"plan":{"type":"string"},"confirm":{"type":"string"}}}),
            true,
        ),
        (
            "/config/preview",
            "Preview a typed configuration",
            json!({"type":"object","required":["config"],"properties":{"config":{"type":"object"},"unlock":{"type":"string","writeOnly":true}}}),
            false,
        ),
        (
            "/proxy-access",
            "Change account, device or browser authorization state",
            json!({"type":"object","required":["action"],"properties":{"action":{"enum":[
            "settings","create","import","delete","edit","create-device","delete-device","policy","group-members","reset-traffic","traffic-cycle"]}}}),
            false,
        ),
        (
            "/fleet/grant",
            "Issue one scoped pairing credential shown once",
            json!({"type":"object","required":["name","scope"],"properties":{"name":{"type":"string"},"scope":{"enum":["read","manage"]}}}),
            false,
        ),
        (
            "/fleet/register",
            "Register a certificate-verified peer at a fixed address",
            json!({"type":"object","required":["name","hostname","address","port","token"],"properties":{
                "name":{"type":"string"},"hostname":{"type":"string"},"address":{"type":"string"},"port":{"type":"integer"},"token":{"type":"string","writeOnly":true}
            }}),
            false,
        ),
        (
            "/fleet/remove",
            "Remove a registration or revoke a grant by ID",
            json!({"type":"object","required":["id","grant"],"properties":{"id":{"type":"string","format":"uuid"},"grant":{"type":"boolean"}}}),
            false,
        ),
        (
            "/operations",
            "Run a confirmed node operation",
            json!({"type":"object","required":["operation","confirm"],"properties":{"operation":{"type":"string"},"confirm":{"type":"string"}}}),
            true,
        ),
        (
            "/logout",
            "End this administrator session",
            json!({"type":"object","maxProperties":0}),
            false,
        ),
    ] {
        add(path, "post", summary, Some(body), task);
    }
    add(
        "/login",
        "post",
        "Exchange an administrator token for a session cookie and CSRF token",
        Some(
            json!({"type":"object","required":["token"],"properties":{"token":{"type":"string","writeOnly":true}}}),
        ),
        false,
    );
    paths.get_mut("/login").unwrap()["post"]["security"] = json!([]);
    json!({
        "openapi":"3.1.0","info":{"title":"nodectl Admin API","version":env!("CARGO_PKG_VERSION")},
        "servers":[{"url":"/admin/api"}],"security":[{"session":[]}],
        "paths":paths,
        "components":{"securitySchemes":{
            "session":{"type":"apiKey","in":"cookie","name":"__Host-nodectl_admin"},
            "csrf":{"type":"apiKey","in":"header","name":"X-CSRF-Token"},
            "peer":{"type":"http","scheme":"bearer","description":"Scoped pairing token on /peer/ routes, sent only over HTTPS."}
        },"schemas":{
            "Error":{"type":"object","required":["error","message"],"properties":{
                "error":{"type":"string"},"message":{"type":"string"},
                "field_errors":{"type":"array","items":{"type":"object","required":["field","code","message"],
                    "properties":{"field":{"type":"string"},"code":{"type":"string"},"message":{"type":"string"}}}}
            }},
            "Task":{"type":"object","required":["job"],"properties":{"job":{"type":"string","example":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}}}
        }}
    })
}
