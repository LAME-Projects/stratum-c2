/* ─────────────────────────────────────────────────────────────────────────────
   app.js — Main init, WS dispatch, topbar state
───────────────────────────────────────────────────────────────────────────── */

(async function main() {

  // ── OIDC callback: ?oidc_display=... or ?oidc_error=... ────────────────────
  // Cookie is already set by the server redirect — no token in URL.
  const _qp = new URLSearchParams(window.location.search);
  const _oidcDisplay = _qp.get('oidc_display');
  const _oidcError   = _qp.get('oidc_error');

  if (_oidcDisplay !== null) {
    history.replaceState(null, '', window.location.pathname);
    await API.oidcHandleCallback(_oidcDisplay);
    if (API.isLoggedIn()) {
      showView('app-view');
      await _bootApp();
    } else {
      showView('login-view');
      await _initLogin();
    }
  } else if (_oidcError) {
    history.replaceState(null, '', window.location.pathname);
    showView('login-view');
    await _initLogin(_oidcError);
  } else {
    // Try to restore session from cookie via /me
    try {
      const data = await API.me();
      API.setAuth(data.username, data.display);
      showView('app-view');
      await _bootApp();
    } catch {
      showView('login-view');
      await _initLogin();
    }
  }

  /* ════════════════════════════════════════════════════════════════════════
     LOGIN
  ════════════════════════════════════════════════════════════════════════ */
  async function _initLogin(oidcError = null) {
    const form      = document.getElementById('login-form');
    const errEl     = document.getElementById('login-error');
    const btn       = document.getElementById('login-btn');
    const oidcArea  = document.getElementById('login-oidc-area');
    const oidcBtn   = document.getElementById('login-oidc-btn');

    if (btn)     { btn.disabled = false; btn.textContent = 'Connect'; }
    if (oidcBtn) { oidcBtn.disabled = false; oidcBtn.textContent = 'Sign in with OIDC Provider'; }
    if (errEl)   errEl.classList.remove('visible');

    function _showErr(msg) { if (errEl) { errEl.textContent = msg; errEl.classList.add('visible'); } }
    function _hideErr()    { if (errEl) errEl.classList.remove('visible'); }

    // Show OIDC error from callback redirect — MED-12: codes only, no free-text from provider
    if (oidcError) {
      const _oidcMessages = {
        provider_error:    'Authentication failed: the identity provider returned an error.',
        missing_params:    'Authentication failed: incomplete response from identity provider.',
        invalid_token:     'Authentication failed: token validation error.',
        auth_error:        'Authentication failed: internal error during login.',
        not_authorized:    'Access denied: your account is not authorized.',
        already_connected: 'This account is already connected from another client.',
      };
      _showErr(_oidcMessages[oidcError] || 'Authentication failed.');
    }

    // Detect auth mode and toggle form vs OIDC button.
    // On network failure: show the local form anyway (safe fallback) and show an error.
    let _isOidc = false;
    try {
      const modeData = await API.authMode();
      _isOidc = modeData.auth_mode !== 'local';
    } catch(e) {
      if (e.status === 0) _showErr('Server unreachable. Check that Stratum is running and try again.');
    }

    if (_isOidc) {
      if (form)     form.style.display     = 'none';
      if (oidcArea) oidcArea.style.display = '';
    } else {
      if (form)     form.style.display     = '';
      if (oidcArea) oidcArea.style.display = 'none';
    }

    function _netErr(e) {
      if (e.status === 0)   return 'Server unreachable. Check that Stratum is running and try again.';
      if (e.status === 429) return 'Too many failed attempts. Please wait 60 seconds.';
      if (e.status === 401) return 'Invalid username or password.';
      if (e.status >= 500)  return `Server error (${e.status}). Check the server logs.`;
      return e.message || `Unexpected error (${e.status || 0}).`;
    }

    // Local login submit
    if (form) form.onsubmit = async (e) => {
      e.preventDefault();
      _hideErr();
      const user = document.getElementById('login-user')?.value.trim();
      const pass = document.getElementById('login-pass')?.value;
      if (!user || !pass) { _showErr('Username and password required.'); return; }
      btn.disabled = true;
      btn.textContent = 'Connecting…';
      try {
        await API.login(user, pass);
        showView('app-view');
        await _bootApp();
      } catch(e) {
        _showErr(_netErr(e));
        btn.disabled = false;
        btn.textContent = 'Connect';
      }
    };

    // OIDC button
    if (oidcBtn) oidcBtn.onclick = async () => {
      oidcBtn.disabled = true;
      oidcBtn.textContent = 'Redirecting…';
      _hideErr();
      try {
        const url = await API.oidcStart();
        // Reset button before navigating — BFCache restores page state on back,
        // so the button must already be enabled when the snapshot is taken.
        oidcBtn.disabled = false;
        oidcBtn.textContent = 'Sign in with OIDC Provider';
        window.location.href = url;
      } catch(e) {
        _showErr(e.status === 0 ? 'Server unreachable. Check that Stratum is running and try again.' : (e.message || 'Authentication service unavailable. Please try again later.'));
        oidcBtn.disabled = false;
        oidcBtn.textContent = 'Sign in with OIDC Provider';
      }
    };
  }

  /* ════════════════════════════════════════════════════════════════════════
     APP BOOT
  ════════════════════════════════════════════════════════════════════════ */

  /* per-session state tracking for notifications */
  const _seenHb   = new Set(); // sessions with at least one heartbeat (pre-seeded at boot)
  const _stateMap = new Map(); // session_id → 'alive' | 'dead'
  const _wipingIds = new Set(); // sessions currently being wiped (suppress "Agent Dead" notif)

  /* ── wipe countdown (shown to observer operators) ───────────────────────── */
  const _WIPE_SECS = 8;
  let _wipeCd = null; // { sessionId, timer }

  function _showWipeCountdown(sessionId, label, operator) {
    _closeWipeCountdown(true); // clear any previous
    if (!document.getElementById('wipe-countdown-modal')) return;

    const sess     = Sessions.getSession(sessionId);
    const barEl    = document.getElementById('wc-bar');
    const timeEl   = document.getElementById('wc-time');
    const sidEl    = document.getElementById('wc-sid');
    const folderEl = document.getElementById('wc-folder');
    const hostRowEl= document.getElementById('wc-host-row');
    const hostEl   = document.getElementById('wc-host');
    const osRowEl  = document.getElementById('wc-os-row');
    const osEl     = document.getElementById('wc-os');
    const opEl     = document.getElementById('wc-op');

    const shortId = (sess?.id || sessionId).slice(0, 8);
    const folder  = sess?.folder_path || label || sessionId;
    const host    = sess?.target_host || '';
    const os      = sess?.target_os   || '';

    if (sidEl)    sidEl.textContent    = shortId;
    if (folderEl) folderEl.textContent = folder;
    if (hostRowEl) hostRowEl.style.display = host ? '' : 'none';
    if (hostEl)   hostEl.textContent   = host;
    if (osRowEl)  osRowEl.style.display  = os   ? '' : 'none';
    if (osEl)     osEl.textContent     = os;
    if (opEl)     opEl.textContent     = operator;

    // Bar: pure CSS animation — no JS width manipulation needed
    if (barEl) {
      barEl.classList.remove('draining');
      void barEl.offsetWidth; // force reflow to restart animation
      barEl.style.setProperty('--wc-secs', `${_WIPE_SECS}s`);
      barEl.classList.add('draining');
    }

    let remaining = _WIPE_SECS;
    if (timeEl) timeEl.textContent = `${remaining}s`;

    function tick() {
      remaining = Math.max(0, remaining - 1);
      if (timeEl) timeEl.textContent = `${remaining}s`;
      if (remaining === 0) { setTimeout(() => _closeWipeCountdown(false), 800); }
    }

    Modal.open('wipe-countdown-modal', { nonDismissible: true });
    _wipeCd = { sessionId, timer: setInterval(tick, 1000) };

    const okBtn = document.getElementById('wc-ok');
    if (okBtn) { okBtn.onclick = () => _closeWipeCountdown(false); }
  }

  function _closeWipeCountdown(immediate = false) {
    if (!_wipeCd) return;
    clearInterval(_wipeCd.timer);
    _wipeCd = null;
    const barEl = document.getElementById('wc-bar');
    if (barEl) barEl.classList.remove('draining');
    if (!immediate) {
      setTimeout(() => Modal.close('wipe-countdown-modal'), 300);
    } else {
      Modal.close('wipe-countdown-modal');
    }
  }

  async function _bootApp() {
    Settings.loadServerPrefs();   // async, non-blocking — applies server prefs over localStorage
    Notif.init();                 // async, non-blocking — loads per-operator notification prefs

    const username = API.getUsername();
    const display  = API.getDisplay();

    /* operator display in topbar */
    const opName = document.getElementById('op-name');
    const opAv   = document.getElementById('op-av');
    if (opName) opName.textContent = display;
    if (opAv)   opAv.textContent  = (display || '?')[0].toUpperCase();

    /* logout */
    const logoutBtn = document.getElementById('btn-logout');
    if (logoutBtn) logoutBtn.addEventListener('click', async () => {
      WS.disconnect();
      await API.logout();
      showView('login-view');
      _initLogin();
    });

    /* help */
    const helpBtn  = document.getElementById('btn-help');
    const helpClose= document.getElementById('help-close');
    if (helpBtn)   helpBtn.addEventListener('click',  () => Modal.open('help-modal'));
    if (helpClose) helpClose.addEventListener('click', () => Modal.close('help-modal'));

    /* chat toggle + resize */
    const chatToggle  = document.getElementById('btn-chat-toggle');
    const chatPanel   = document.getElementById('chat-panel');
    const chatHandle  = document.getElementById('chat-resize-handle');

    /* restore saved chat width */
    const _savedChatW = localStorage.getItem('stratum.chatW');
    if (_savedChatW) document.documentElement.style.setProperty('--chat-w', _savedChatW + 'px');

    if (chatToggle && chatPanel) {
      chatToggle.addEventListener('click', () => {
        chatPanel.classList.toggle('hidden');
        const hidden = chatPanel.classList.contains('hidden');
        if (chatHandle) chatHandle.classList.toggle('hidden', hidden);
        chatToggle.classList.toggle('on', !hidden);
        if (!hidden) Notif.markChatRead(); // panel just became visible
      });
    }

    _initChatResize(chatPanel, chatHandle);

    /* load sessions — pre-seed _seenHb so existing sessions don't trigger first-hb */
    try {
      const list = await API.sessions();
      Sessions.setAll(list);
      (list || []).forEach(s => {
        const id = s.id || s.session_id;
        if (id) _seenHb.add(id);
      });
    } catch {}

    /* init modules */
    Sessions.init();
    Deploy.init();
    Settings.init();
    Archives.init();
    Chat.init(username);
    Tradecraft.init();

    ContextMenu.init();

    /* ws — operator list comes from server.hello, no need to pre-seed with [] */
    _initWS();
  }

  /* ════════════════════════════════════════════════════════════════════════
     WEBSOCKET DISPATCH
  ════════════════════════════════════════════════════════════════════════ */
  function _initWS() {
    WS.on('ws.connected',    () => _updateConnStatus(true));
    let _handling4009 = false;
    WS.on('ws.disconnected', (ev) => {
      if (ev.payload?.intentional) return;
      const code = ev.payload?.code;
      _updateConnStatus(false);
      if (code === 4009) {
        if (_handling4009) return;
        _handling4009 = true;
        /* account already connected from another client — stay on login page.
           Do NOT call API.logout(): the token is valid but no WS was registered
           for this client, so logout() would call disconnect_user() server-side
           and kill the legitimate session on the other tab. */
        WS.disconnect();
        showView('login-view');
        _initLogin('already_connected');
      }
    });
    WS.on('ws.reconnecting', (ev) => {
      const delay = ev.payload?.delay;
      Toast.warning('Disconnected', `Reconnecting in ${Math.round(delay/1000)}s…`, 3000);
    });

    WS.on('server.hello', (ev) => {
      const p = ev.payload;
      if (p.server_version) {
        window._serverVersion = p.server_version;
        const vLabel = `v${p.server_version}`;
        const loginVer = document.getElementById('login-version');
        if (loginVer) loginVer.textContent = `Stratum C2 ${vLabel}`;
        const aboutVer = document.getElementById('about-version');
        if (aboutVer) aboutVer.textContent = `${vLabel} — Cloud Persistence Framework`;
      }
      if (p.update && p.update.available) {
        const dismissed = localStorage.getItem('stratum_dismissed_version');
        if (dismissed !== p.update.latest) _showUpdateBanner(p.update);
      }
      _updateVersionBadge(p.server_version, p.update);
      if (p.sessions)  Sessions.setAll(p.sessions);
      if (p.operators) _updateOperators(p.operators);
    });

    WS.on('update.complete', (ev) => {
      const p = ev.payload || {};
      if (p.ok) {
        Toast.ok('Update Complete', p.message || 'Restart the server to apply changes.');
        const banner = document.getElementById('update-banner');
        if (banner) banner.style.display = 'none';
        Modal.close('update-modal');
        _pendingUpdate = null;
        _updateVersionBadge(p.new_version || window._serverVersion, null);
        _openChangelog();
      } else {
        Toast.error('Update Failed', p.error || 'Unknown error');
      }
    });

    WS.on('session.new', (ev) => {
      Sessions.upsert(ev.payload);
      const deployedBy = ev.payload.deployed_by || '';
      if (deployedBy.toLowerCase() !== (API.getUsername() || '').toLowerCase()) {
        const label = ev.payload.target_host || ev.payload.folder_path || ev.payload.id;
        Notif.trigger('session_new', 'New Session', label);
      }
    });

    WS.on('session.update', (ev) => {
      const payload = ev.payload;
      const prevSess = Sessions.getSession(payload.id);
      const prevState = prevSess?.state;
      const newState = payload.state;
      Sessions.upsert(payload);
      // Show Toast for state changes:
      // - suppress unknown→offline (first creation, agent never checked in)
      // - suppress offline when session.dead already fired (dead covers it with error Toast)
      // - suppress all state toasts while session is being wiped
      if (prevState && newState && prevState !== newState &&
          !(newState === 'offline' && prevState === 'unknown') &&
          !(newState === 'offline' && _stateMap.get(payload.id) === 'dead') &&
          !_wipingIds.has(payload.id)) {
        const stateLabel = { online: 'Online', idle: 'Idle', offline: 'Offline', unknown: 'Unknown', dead: 'Dead' }[newState] || newState;
        const who  = [payload.target_user, payload.target_host].filter(Boolean).join('@');
        const chan  = (payload.folder_path || '').replace(/^\/+|\/+$/g, '') || payload.id;
        const _pl  = (p) => ({ googledrive:'GoogleDrive', onedrive:'OneDrive', sharepoint:'SharePoint', s3:'AWS S3', dropbox:'Dropbox' })[(p||'').toLowerCase()] || p || '';
        const prov  = payload.provider ? ` [${_pl(payload.provider)}]` : '';
        const title = who ? `${who} — ${chan}${prov}` : `${chan}${prov}`;
        Notif.trigger('agent_state', title, stateLabel, { alive: newState !== 'offline' });
      }
    });

    WS.on('session.poll.stopped', (ev) => {
      const { host, by } = ev.payload;
      if ((by || '').toLowerCase() !== (API.getUsername() || '').toLowerCase())
        Toast.warning('Poll stopped', `${by} stopped polling on ${host || ev.payload.session_id}`);
    });

    WS.on('session.poll.resumed', (ev) => {
      const { host, by } = ev.payload;
      if ((by || '').toLowerCase() !== (API.getUsername() || '').toLowerCase())
        Toast.info('Poll resumed', `${by} resumed polling on ${host || ev.payload.session_id}`);
    });

    WS.on('session.locked', (ev) => {
      const { session_id, locked, by } = ev.payload;
      Sessions.setLocked(session_id, locked);
      const action = locked ? 'locked' : 'unlocked';
      if ((by || '').toLowerCase() !== (API.getUsername() || '').toLowerCase())
        Toast.info(`Session ${action}`, `${by} ${action} session ${session_id.slice(0, 6)}`);
      else
        Toast.ok(`Session ${action}`, `${session_id.slice(0, 6)} ${action}`);
    });

    WS.on('server.timezone', (ev) => {
      const { timezone, by } = ev.payload;
      Settings.applyTimezone(timezone);
      Sessions.redraw();
      if ((by || '').toLowerCase() !== (API.getUsername() || '').toLowerCase())
        Toast.info('Timezone changed', `${by} set timezone to ${timezone}`);
    });

    WS.on('session.wiping', (ev) => {
      const { session_id, label, operator } = ev.payload;
      _wipingIds.add(session_id);
      Sessions.markWiping(session_id);  // keep row visible with wiping badge for all operators
      if (operator === API.getUsername()) return; // initiating operator already sees SSE progress
      const sess = Sessions.getSession(session_id);
      const displayLabel = sess?.target_host || sess?.folder_path || label || session_id;
      _showWipeCountdown(session_id, displayLabel, operator);
    });

    WS.on('session.dead', (ev) => {
      const s  = ev.payload;
      const id = s.id || s.session_id;
      if (_stateMap.get(id) !== 'dead') {
        _stateMap.set(id, 'dead');
        const who  = [s.target_user, s.target_host].filter(Boolean).join('@');
        const chan  = (s.folder_path || '').replace(/^\/+|\/+$/g, '') || id;
        const _pl  = (p) => ({ googledrive:'GoogleDrive', onedrive:'OneDrive', sharepoint:'SharePoint', s3:'AWS S3', dropbox:'Dropbox' })[(p||'').toLowerCase()] || p || '';
        const prov  = s.provider ? ` [${_pl(s.provider)}]` : '';
        const title = who ? `${who} — ${chan}${prov}` : `${chan}${prov}`;
        Notif.trigger('agent_state', title, 'Dead — agent stopped responding', { alive: false, dead: true });
      }
      Sessions.onHeartbeat(id, { alive: false });
    });

    WS.on('session.removed', (ev) => {
      const { id, session_id, removed_by } = ev.payload;
      const sid = id || session_id;
      // If a background wipe is in progress, keep the row visible with a
      // "wiping" badge — session.wipe_done will remove it when cloud cleanup finishes.
      if (_wipingIds.has(sid)) {
        Sessions.markWiping(sid);
      } else {
        Sessions.remove(sid);
        _stateMap.delete(sid);
        _seenHb.delete(sid);
      }
      if (removed_by && removed_by !== API.getUsername()) {
        Notif.trigger('session_removed', 'Session Removed', `${removed_by} removed ${sid.slice(0, 8)}`);
      }
    });

    WS.on('session.wipe_done', (ev) => {
      const { session_id, status, detail, wait_s } = ev.payload;
      Sessions.remove(session_id);
      _stateMap.delete(session_id);
      _seenHb.delete(session_id);
      _wipingIds.delete(session_id);
      if (status === 'ok') {
        Toast.ok('Wipe complete', `Cloud cleanup done${wait_s ? ` (waited ${wait_s}s)` : ''}`);
      } else {
        Toast.error('Wipe error', detail || 'Cloud cleanup failed');
      }
    });

    WS.on('session.heartbeat', (ev) => {
      const { session_id, state } = ev.payload;
      Sessions.onHeartbeat(session_id, state);

      const sess  = Sessions.getSession(session_id);
      const label = sess?.target_host || sess?.folder_path || session_id;

      if (!_seenHb.has(session_id)) {
        _seenHb.add(session_id);
        Notif.trigger('agent_first_hb', 'Agent Check-in', `${label} first heartbeat`);
      }

      if (state.alive !== false) _stateMap.set(session_id, 'alive');
    });

    WS.on('session.output', (ev) => {
      const { cmd_id, output, content, error, session_id, remote_cwd } = ev.payload;
      Sessions.onOutput(cmd_id, output ?? content, !!error, remote_cwd, session_id);
      const activeId = Sessions.getActiveId ? Sessions.getActiveId() : null;
      if (session_id && session_id !== activeId) {
        const sess = Sessions.getSession(session_id);
        const who  = sess?.target_host || session_id.slice(0, 8);
        Notif.trigger('cmd_response', `Response — ${who}`, (output ?? content ?? '').slice(0, 80));
      }
    });

    WS.on('session.command', (ev) => {
      Sessions.onRemoteCommand(ev.payload);
    });

    WS.on('session.artifacts.changed', (ev) => {
      Sessions.onArtifactsChanged(ev.payload?.session_id);
    });

    WS.on('session.credentials.changed', (ev) => {
      Sessions.onCredentialsChanged(ev.payload?.session_id);
    });

    /* Generic notification broadcast — central notification system */
    WS.on('notification', (ev) => {
      const { level, title, message } = ev.payload || {};
      if (!title || !message) return;

      if (level === 'error') {
        Toast.error(title, message);
      } else if (level === 'warn') {
        Toast.warning(title, message);
      } else {
        Toast.info(title, message);
      }
    });

    WS.on('operator.connected',    (ev) => {
      Toast.info('Operator', `${ev.payload.username} connected`);
      Chat.onOperatorEvent('connect', ev.payload.username);
      _fetchAndUpdateOperators();
    });
    WS.on('operator.disconnected', (ev) => {
      Toast.info('Operator', `${ev.payload.username} disconnected`);
      Chat.onOperatorEvent('disconnect', ev.payload.username);
      _fetchAndUpdateOperators();
    });

    WS.on('chat.message', (ev) => {
      Chat.onMessage(ev.payload);
      // Update Chat History modal if open (new date might have been created)
      if (ChatHistory && ChatHistory.reloadList) {
        ChatHistory.reloadList();
      }
    });
    WS.on('chat.date_deleted', (ev) => {
      const { date, deleted_by } = ev.payload || {};
      if (!date) return;
      if (deleted_by && deleted_by !== API.getUsername()) {
        Toast.info('Chat Deleted', `Log for ${date} removed`);
      }
      const today = new Date().toISOString().slice(0, 10);

      // If deleted date is today, clear chat messages
      if (date === today) {
        Chat.clearMessages();
      }

      // If viewing deleted date, switch back to today
      const currentDate = Chat.getCurrentDate();
      if (currentDate === date) {
        const dateSel = document.getElementById('chat-date-sel');
        if (dateSel) {
          dateSel.value = '';
          dateSel.dispatchEvent(new Event('change'));
        }
      }

      // Update date selector
      const dateSel = document.getElementById('chat-date-sel');
      if (dateSel) {
        API.chatDates().then(dates => {
          dateSel.innerHTML = '<option value="">📅 Today</option><option value="__all__">📅 View All</option>';
          [...dates].reverse().forEach(d => {
            if (d === today) return;
            const opt = document.createElement('option');
            opt.value = d;
            opt.textContent = d;
            dateSel.appendChild(opt);
          });
        }).catch(() => {});
      }

      // Update Chat History modal if open
      if (ChatHistory && ChatHistory.reloadList) {
        ChatHistory.reloadList();
      }
    });

    WS.on('history.archive.deleted', (ev) => {
      const { filename, deleted_by } = ev.payload || {};
      if (deleted_by !== API.getUsername()) {
        Toast.info('Deleted', `${filename} removed`);
        if (Archives && Archives.removeRow) Archives.removeRow(filename);
      }
    });

    WS.on('tradecraft.deleted', (ev) => {
      const { name, deleted_by } = ev.payload || {};
      // Only show Toast if another operator deleted
      if (deleted_by !== API.getUsername()) {
        Toast.info('Deleted', `${name} removed`);
      }
      // Reload tradecraft list
      if (Tradecraft && Tradecraft.reload) {
        Tradecraft.reload();
      }
    });

    WS.on('credentials.changed', (ev) => {
      // Refresh the credentials modal if it is currently open
      if (Settings && Settings.refreshCredentialsIfOpen) {
        Settings.refreshCredentialsIfOpen();
      }
    });


    WS.connect();
  }

  /* ── update banner / modal ─────────────────────────────────────────────── */
  let _pendingUpdate = null;

  function _showUpdateBanner(info) {
    _pendingUpdate = info;
    const banner = document.getElementById('update-banner');
    const text   = document.getElementById('update-banner-text');
    const btn    = document.getElementById('update-banner-btn');
    if (!banner) return;
    if (text) text.textContent = `v${info.latest} available`;
    banner.style.display = '';
    if (btn) btn.onclick = () => _openUpdateModal(info);
    _openUpdateModal(info);
  }

  function _openUpdateModal(info) {
    _pendingUpdate = info;
    const cur   = document.getElementById('update-current');
    const lat   = document.getElementById('update-latest');
    const date  = document.getElementById('update-date');
    const notes = document.getElementById('update-notes');
    const prog  = document.getElementById('update-progress');
    const footer= document.getElementById('update-footer');

    if (cur)   cur.textContent   = `v${info.current}`;
    if (lat)   lat.textContent   = `v${info.latest}`;
    if (date)  date.textContent  = info.published_at ? `Released ${new Date(info.published_at).toLocaleDateString()}` : '';
    if (notes) notes.textContent = info.release_notes || 'No release notes available.';
    if (prog)  prog.style.display = 'none';
    if (footer) footer.style.display = '';

    const dismissBtn = document.getElementById('update-dismiss-btn');
    const laterBtn   = document.getElementById('update-later-btn');
    const applyBtn   = document.getElementById('update-apply-btn');

    if (dismissBtn) dismissBtn.onclick = () => {
      localStorage.setItem('stratum_dismissed_version', info.latest);
      Modal.close('update-modal');
      const banner = document.getElementById('update-banner');
      if (banner) banner.style.display = 'none';
    };

    if (laterBtn) laterBtn.onclick = () => {
      Modal.close('update-modal');
    };

    if (applyBtn) applyBtn.onclick = async () => {
      applyBtn.disabled = true;
      applyBtn.textContent = 'Checking…';
      try {
        const pf = await API.updatePreflight();
        if (!pf.ok) {
          Toast.error('Preflight Failed', (pf.errors || []).join('; ') || 'Cannot proceed');
          applyBtn.disabled = false;
          applyBtn.textContent = 'Update Now';
          return;
        }
        if (pf.warnings && pf.warnings.length) {
          pf.warnings.forEach(w => Toast.warning('Warning', w));
        }
        applyBtn.textContent = 'Updating…';
        if (footer) footer.style.display = 'none';
        if (prog)  prog.style.display = '';
        const result = await API.applyUpdate();
        if (result.ok) {
          const progText = document.getElementById('update-progress-text');
          if (progText) progText.textContent = result.message + ' — restart the server when ready.';
        } else {
          Toast.error('Update Failed', result.error || 'Unknown error');
          if (prog)   prog.style.display = 'none';
          if (footer) footer.style.display = '';
          applyBtn.disabled = false;
          applyBtn.textContent = 'Retry';
        }
      } catch (e) {
        Toast.error('Update Error', e.message || 'Network error');
        applyBtn.disabled = false;
        applyBtn.textContent = 'Retry';
        if (prog)   prog.style.display = 'none';
        if (footer) footer.style.display = '';
      }
    };

    Modal.open('update-modal');
  }

  /* ── version badge (bottom-right) ────────────────────────────────────── */
  function _updateVersionBadge(version, update) {
    const el = document.getElementById('version-badge');
    if (!el) return;
    const ver = version ? `v${version}` : '';
    if (update && update.available) {
      el.innerHTML = `${ver} <span class="vb-update" title="Click to view update details">· update available</span>`;
      el.querySelector('.vb-update')?.addEventListener('click', () => {
        if (_pendingUpdate) _openUpdateModal(_pendingUpdate);
      });
    } else {
      el.textContent = ver;
    }
  }

  /* ── changelog modal ─────────────────────────────────────────────────── */
  async function _openChangelog() {
    const el = document.getElementById('changelog-content');
    if (el) el.textContent = 'Loading…';
    Modal.open('changelog-modal');
    try {
      const text = await API.getChangelog();
      if (el) el.textContent = text || 'No changelog available.';
    } catch {
      if (el) el.textContent = 'Failed to load changelog.';
    }
  }
  window.openChangelog = _openChangelog;

  /* ── chat panel resize (horizontal) ────────────────────────────────────── */
  function _initChatResize(chatPanel, chatHandle) {
    if (!chatHandle || !chatPanel) return;
    const MIN_W = 160, MAX_W = 600;

    chatHandle.addEventListener('mousedown', e => {
      e.preventDefault();
      const startX = e.clientX;
      const startW = chatPanel.offsetWidth;
      chatHandle.classList.add('dragging');
      document.body.style.cursor     = 'ew-resize';
      document.body.style.userSelect = 'none';
      /* disable width transition during drag */
      chatPanel.style.transition = 'none';

      function onMove(e) {
        /* moving handle left → bigger chat (startW - delta) */
        const w = Math.max(MIN_W, Math.min(MAX_W, startW - (e.clientX - startX)));
        document.documentElement.style.setProperty('--chat-w', w + 'px');
      }
      function onUp() {
        chatHandle.classList.remove('dragging');
        document.body.style.cursor     = '';
        document.body.style.userSelect = '';
        chatPanel.style.transition     = '';
        localStorage.setItem('stratum.chatW', chatPanel.offsetWidth);
        document.removeEventListener('mousemove', onMove);
        document.removeEventListener('mouseup',   onUp);
      }
      document.addEventListener('mousemove', onMove);
      document.addEventListener('mouseup',   onUp);
    });
  }

  /* ── sessions pane resize ───────────────────────────────────────────────── */
  function _initResize() {
    const handle   = document.getElementById('resize-handle');
    const sessPane = document.getElementById('sessions-pane');
    if (!handle || !sessPane) return;

    const TOPBAR_H = 46;
    const MIN_H    = 50;

    function setH(px) {
      const max = window.innerHeight - TOPBAR_H - 80;
      const h   = Math.max(MIN_H, Math.min(px, max));
      document.documentElement.style.setProperty('--sessions-h', h + 'px');
    }

    handle.addEventListener('mousedown', e => {
      e.preventDefault();
      const startY = e.clientY;
      const startH = sessPane.offsetHeight;
      handle.classList.add('dragging');
      document.body.style.cursor      = 'ns-resize';
      document.body.style.userSelect  = 'none';

      function onMove(e) { setH(startH + (e.clientY - startY)); }
      function onUp()    {
        handle.classList.remove('dragging');
        document.body.style.cursor     = '';
        document.body.style.userSelect = '';
        document.removeEventListener('mousemove', onMove);
        document.removeEventListener('mouseup',   onUp);
      }
      document.addEventListener('mousemove', onMove);
      document.addEventListener('mouseup',   onUp);
    });
  }
  _initResize();

  /* ── topbar state ────────────────────────────────────────────────────────── */
  function _updateConnStatus(connected) {
    const dot = document.getElementById('ws-status-dot');
    if (dot) {
      dot.classList.toggle('g', connected);
      dot.classList.toggle('r', !connected);
      dot.title = connected ? 'WS connected' : 'WS disconnected';
    }
  }

  function _updateOperators(ops) {
    const statEl = document.getElementById('stat-operators-n');
    if (statEl) statEl.textContent = `${ops.length} operator${ops.length !== 1 ? 's' : ''}`;
    Chat.updateOps(ops);
  }

  async function _fetchAndUpdateOperators() {
    try {
      const data = await API.operators();
      _updateOperators(data.operators || []);
    } catch {}
  }

})();

/* ── Scrollbar visibility ────────────────────────────────────────────────────
   Adds .sb-on to the scrolling element via three signals:
   1. scroll  — fires on the element that scrolled
   2. wheel   — fires before scroll; finds scrollable ancestor under cursor
   3. mousemove — fires when mouse is within 18px of right/bottom edge of a
                  scrollable element, so the user can re-show the bar after
                  it fades. Works for Firefox (no ::-webkit-scrollbar-*:hover). */
(function () {
  const _t = new WeakMap();

  function _show(el) {
    if (!el || el === document || el === document.body || el === document.documentElement) return;
    el.classList.add('sb-on');
    clearTimeout(_t.get(el));
    _t.set(el, setTimeout(function () { el.classList.remove('sb-on'); }, 800));
  }

  function _scrollable(el) {
    while (el && el !== document.documentElement) {
      const s = window.getComputedStyle(el);
      if ((s.overflowY === 'auto' || s.overflowY === 'scroll') && el.scrollHeight > el.clientHeight) return el;
      if ((s.overflowX === 'auto' || s.overflowX === 'scroll') && el.scrollWidth > el.clientWidth) return el;
      el = el.parentElement;
    }
    return null;
  }

  /* scroll: fires after the browser has already moved content — no jank risk */
  document.addEventListener('scroll', function (e) { _show(e.target); }, { capture: true, passive: true });

  /* mousemove: throttled via rAF; detects mouse within 18px of right/bottom
     edge of any scrollable element so the bar can be re-shown after it fades */
  let _raf = null, _mx = 0, _my = 0, _mt = null;
  document.addEventListener('mousemove', function (e) {
    _mx = e.clientX; _my = e.clientY; _mt = e.target;
    if (_raf) return;
    _raf = requestAnimationFrame(function () {
      _raf = null;
      const el = _scrollable(_mt);
      if (!el) return;
      const r = el.getBoundingClientRect();
      if (_mx >= r.right - 18 || _my >= r.bottom - 18) _show(el);
    });
  }, { passive: true });
}());
