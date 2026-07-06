/* ─────────────────────────────────────────────────────────────────────────────
   settings.js — Settings menu: credentials manager, display, about
───────────────────────────────────────────────────────────────────────────── */

const Settings = (() => {

  /* ── global font size ────────────────────────────────────────────────────── */
  function _applyFontSize(px) {
    document.documentElement.style.fontSize = `${px}px`;
    localStorage.setItem('sc2_font_size', String(px));
  }

  function _savedFontSize() {
    const v = parseInt(localStorage.getItem('sc2_font_size') || '14', 10);
    return isNaN(v) ? 14 : v;
  }

  /* ── server clock ────────────────────────────────────────────────────────── */
  let _navTz           = 'UTC';
  let _navClockTimer   = null;
  let _modalClockTimer = null;

  function _tzAbbr(tz) {
    try {
      return new Intl.DateTimeFormat('en-GB', { timeZone: tz, timeZoneName: 'short' })
        .formatToParts(new Date()).find(p => p.type === 'timeZoneName')?.value || tz.split('/').pop();
    } catch { return tz.split('/').pop(); }
  }

  function _fmtNavTime(tz) {
    try {
      return new Date().toLocaleTimeString('en-GB', { timeZone: tz, hour12: false })
        .replace(/:/g, '<span class="ck">:</span>');
    } catch { return '--<span class="ck">:</span>--<span class="ck">:</span>--'; }
  }

  function _fmtPreview(tz) {
    try {
      const d    = new Date();
      const date = d.toLocaleDateString('en-GB', { timeZone: tz, weekday: 'short', day: '2-digit', month: 'short', year: 'numeric' });
      const time = d.toLocaleTimeString('en-GB', { timeZone: tz, hour12: false });
      return `${date}  ${time}`;
    } catch { return '--'; }
  }

  function _startNavClock(tz) {
    _navTz = tz || 'UTC';
    if (typeof setOpTz === 'function') setOpTz(_navTz);
    if (_navClockTimer) clearInterval(_navClockTimer);
    const timeEl = document.getElementById('srv-clock-time');
    const tzEl   = document.getElementById('srv-clock-tz');
    const tick   = () => {
      if (timeEl) timeEl.innerHTML  = _fmtNavTime(_navTz);
      if (tzEl)   tzEl.textContent  = _tzAbbr(_navTz);
    };
    tick();
    _navClockTimer = setInterval(tick, 1000);

    // Click opens Server Settings
    const el = document.getElementById('srv-clock');
    if (el && !el.dataset.clickBound) {
      el.dataset.clickBound = '1';
      el.addEventListener('click', () => openServer());
    }
  }

  /* ── server sync (debounced) ─────────────────────────────────────────────── */
  let _syncTimer = null;

  function _syncPrefs() {
    clearTimeout(_syncTimer);
    _syncTimer = setTimeout(() => {
      const data = { sc2_theme: _savedTheme(), sc2_font_size: String(_savedFontSize()) };
      _ZOOM_PANELS.forEach(({ lsKey }) => { data[lsKey] = String(_savedZoom(lsKey)); });
      API.savePrefs(data).catch(() => {});
    }, 800);
  }

  /* ── theme ───────────────────────────────────────────────────────────────── */
  const _THEMES = ['bloodcraft','phantom','specter','ghost','slate','cybervault','aurum'];

  function _savedTheme() {
    const t = localStorage.getItem('sc2_theme') || 'specter';
    return _THEMES.includes(t) ? t : 'specter';
  }

  function _applyTheme(name) {
    document.documentElement.setAttribute('data-theme', name);
    localStorage.setItem('sc2_theme', name);
  }

  /* ── per-panel zoom ──────────────────────────────────────────────────────── */
  const _ZOOM_PANELS = [
    { key: 'sessions', lsKey: 'sc2_zoom_sessions', cssVar: '--zoom-sessions' },
    { key: 'detail',   lsKey: 'sc2_zoom_detail',   cssVar: '--zoom-detail'   },
    { key: 'tabs',     lsKey: 'sc2_zoom_tabs',      cssVar: '--zoom-tabs'     },
    { key: 'chat',     lsKey: 'sc2_zoom_chat',      cssVar: '--zoom-chat'     },
  ];

  function _savedZoom(lsKey) {
    const v = parseInt(localStorage.getItem(lsKey) || '100', 10);
    return isNaN(v) ? 100 : v;
  }

  function _applyZoom(cssVar, pct) {
    document.documentElement.style.setProperty(cssVar, String(pct / 100));
  }

  /* ── load prefs from server and apply (called after login) ──────────────── */
  async function loadServerPrefs() {
    let prefs;
    try { prefs = await API.getPrefs(); } catch { return; }

    if (prefs.sc2_theme && _THEMES.includes(prefs.sc2_theme)) {
      localStorage.setItem('sc2_theme', prefs.sc2_theme);
      _applyTheme(prefs.sc2_theme);
      document.querySelectorAll('.theme-sw').forEach(sw =>
        sw.classList.toggle('active', sw.dataset.themePick === prefs.sc2_theme));
    }

    if (prefs.sc2_font_size) {
      const v = parseInt(prefs.sc2_font_size, 10);
      if (!isNaN(v)) {
        localStorage.setItem('sc2_font_size', String(v));
        _applyFontSize(v);
        const sl = document.getElementById('font-size-slider');
        const lb = document.getElementById('font-size-label');
        if (sl) sl.value = v;
        if (lb) lb.textContent = `${v}px`;
      }
    }

    _ZOOM_PANELS.forEach(({ key, lsKey, cssVar }) => {
      const raw = prefs[lsKey];
      if (raw === undefined) return;
      const pct = parseInt(raw, 10);
      if (isNaN(pct)) return;
      localStorage.setItem(lsKey, String(pct));
      _applyZoom(cssVar, pct);
      const sl = document.getElementById(`zoom-${key}-slider`);
      const lb = document.getElementById(`zoom-${key}-label`);
      if (sl) sl.value = pct;
      if (lb) lb.textContent = `${pct}%`;
    });
  }

  /* ── credential manager ──────────────────────────────────────────────────── */
  async function _renderCredManager() {
    const body = document.getElementById('creds-body');
    if (!body) return;
    body.innerHTML = '<p class="text-dim" style="padding:.4rem 0">Loading…</p>';

    /* Providers — use deploy cache if populated, else fetch fresh from server */
    let providers = Deploy.getProviders();
    if (!Object.keys(providers).length) {
      try {
        const r = await API.providers();
        providers = {};
        (r.providers || []).forEach(p => { providers[p.id] = p; });
      } catch {
        body.innerHTML = '<p class="text-dim">Failed to load providers.</p>';
        return;
      }
    }

    const pids = Object.keys(providers);

    /* Fetch all profiles in parallel (updates Deploy's internal cache) */
    await Promise.all(pids.map(pid => Deploy.fetchProfileList(pid).catch(() => {})));

    body.innerHTML = '';
    let totalCount = 0;

    pids.forEach(pid => {
      const p        = providers[pid];
      const profiles = Deploy.profilesFor(pid);
      if (!profiles.length) return;
      totalCount += profiles.length;

      /* Only show credential fields — channel fields (folder_path, input_file, etc.)
         belong to individual deployments, not to a saved credential profile */
      const credFields = (p.fields || []).filter(f => f.group !== 'channel');

      /* Provider section header */
      const hdr = document.createElement('div');
      hdr.className = 'cmgr-prov-hdr';
      hdr.innerHTML = `<span class="cmgr-pname">${escHtml(p.label || pid)}</span>
                       <span class="cmgr-pcount">${profiles.length} profile${profiles.length > 1 ? 's' : ''}</span>`;
      body.appendChild(hdr);

      profiles.forEach(prof => {
        const dt    = new Date(prof.saved_at || 0);
        const dtStr = dt.toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric' });

        const row = document.createElement('div');
        row.className = 'cred-mgr-row';

        /* Left: provider icon + profile label + date */
        const nameCell = document.createElement('div');
        nameCell.className = 'cmr-name';
        nameCell.appendChild(providerIcon(pid, 'provider-icon'));
        const meta = document.createElement('div');
        meta.innerHTML = `<div class="cmr-label">${escHtml(prof.label || 'Default')}</div>
                          <div class="cmr-date">Saved ${escHtml(dtStr)}</div>`;
        nameCell.appendChild(meta);

        /* Middle: only the primary identifier is exposed — no secrets. */
        const fieldsCell = document.createElement('div');
        fieldsCell.className = 'cmr-fields';
        const idVal = prof.identifier ? escHtml(prof.identifier) : '—';
        fieldsCell.innerHTML = `<span class="cmr-field"><span class="cmr-key">Account:</span> ${idVal}</span>`;

        /* Right: delete button */
        const delBtn = document.createElement('button');
        delBtn.className = 'btn-danger-modal';
        delBtn.textContent = 'Delete';
        delBtn.addEventListener('click', async () => {
          delBtn.disabled = true;
          delBtn.textContent = '…';
          await Deploy.removeProfile(pid, prof.id).catch(() => {});
          _renderCredManager();
        });

        row.appendChild(nameCell);
        row.appendChild(fieldsCell);
        row.appendChild(delBtn);
        body.appendChild(row);
      });
    });

    if (!totalCount) {
      body.innerHTML = `<p class="text-dim" style="padding:.4rem 0 .2rem">
        No saved credentials. Complete a deploy to save credentials automatically.</p>`;
    }
  }

  /* ── open modals ─────────────────────────────────────────────────────────── */
  function openCredentials() {
    _renderCredManager();
    Modal.open('creds-modal');
  }

  function openDisplay() {
    // reset peek state each open
    document.getElementById('display-modal')?.classList.remove('peek');
    const peekCb = document.getElementById('disp-peek');
    if (peekCb) peekCb.checked = false;

    const sz     = _savedFontSize();
    const slider = document.getElementById('font-size-slider');
    const lbl    = document.getElementById('font-size-label');
    if (slider) slider.value = sz;
    if (lbl)    lbl.textContent = `${sz}px`;

    _ZOOM_PANELS.forEach(({ key, lsKey }) => {
      const pct  = _savedZoom(lsKey);
      const sl   = document.getElementById(`zoom-${key}-slider`);
      const lb   = document.getElementById(`zoom-${key}-label`);
      if (sl) sl.value = pct;
      if (lb) lb.textContent = `${pct}%`;
    });

    const cur = _savedTheme();
    document.querySelectorAll('.theme-sw').forEach(sw => {
      sw.classList.toggle('active', sw.dataset.themePick === cur);
    });

    Modal.open('display-modal');
  }

  function openAbout() {
    Modal.open('about-modal');
  }

  function openNotifications() {
    const body = document.getElementById('notif-body');
    if (body) Notif.renderSettings(body);
    Modal.open('notif-modal');
  }

  // All supported IANA zones (browser-native, no server round-trip)
  const _ALL_ZONES = typeof Intl.supportedValuesOf === 'function'
    ? Intl.supportedValuesOf('timeZone')
    : ['UTC','Europe/London','Europe/Rome','Europe/Berlin','Europe/Paris',
       'America/New_York','America/Chicago','America/Denver','America/Los_Angeles',
       'Asia/Tokyo','Asia/Shanghai','Asia/Kolkata','Australia/Sydney'];

  function _buildTzOptions(zones, selected) {
    const sel = document.getElementById('srv-timezone');
    if (!sel) return;
    sel.innerHTML = '';
    zones.forEach(z => {
      const opt = document.createElement('option');
      opt.value = z; opt.textContent = z;
      if (z === selected) opt.selected = true;
      sel.appendChild(opt);
    });
  }

  function _stopModalClock() {
    if (_modalClockTimer) { clearInterval(_modalClockTimer); _modalClockTimer = null; }
  }

  async function openServer() {
    _stopModalClock();
    const msg = document.getElementById('srv-tz-msg');
    const flt = document.getElementById('tz-filter');
    if (msg) { msg.textContent = ''; msg.style.color = ''; }
    if (flt) flt.value = '';

    _buildTzOptions(_ALL_ZONES, _navTz);

    const prevName = document.getElementById('tz-preview-name');
    const prevTime = document.getElementById('tz-preview-time');

    function _updatePreview() {
      const sel = document.getElementById('srv-timezone');
      const tz  = sel?.value || _navTz;
      if (prevName) prevName.textContent = tz;
      if (prevTime) prevTime.textContent = _fmtPreview(tz);
    }

    const sel = document.getElementById('srv-timezone');
    if (sel) sel.addEventListener('change', _updatePreview);

    // Filter input rebuilds option list
    if (flt) {
      flt.oninput = () => {
        const q       = flt.value.trim().toLowerCase();
        const current = document.getElementById('srv-timezone')?.value || _navTz;
        _buildTzOptions(q ? _ALL_ZONES.filter(z => z.toLowerCase().includes(q)) : _ALL_ZONES, current);
        _updatePreview();
      };
    }

    Modal.open('server-modal');
    _updatePreview();
    _modalClockTimer = setInterval(_updatePreview, 1000);

    // Sync actual TZ from server (updates selection if different from cached _navTz)
    try {
      const r = await API.getServerSettings();
      const serverTz = r.timezone || 'UTC';
      if (serverTz !== _navTz) {
        if (!flt?.value) _buildTzOptions(_ALL_ZONES, serverTz);
        _updatePreview();
      }
    } catch {
      if (msg) { msg.textContent = 'Could not load current settings.'; msg.style.color = 'var(--danger)'; }
    }
  }

  /* ── init ────────────────────────────────────────────────────────────────── */
  function init() {
    _applyFontSize(_savedFontSize());
    _applyTheme(_savedTheme());

    // Restore per-panel zoom on boot
    _ZOOM_PANELS.forEach(({ lsKey, cssVar }) => {
      _applyZoom(cssVar, _savedZoom(lsKey));
    });

    const btn  = document.getElementById('btn-settings');
    const menu = document.getElementById('settings-dropdown');
    if (btn && menu) {
      btn.addEventListener('click', e => {
        e.stopPropagation();
        menu.classList.toggle('open');
      });
      document.addEventListener('click', () => menu.classList.remove('open'));
      menu.addEventListener('click', e => e.stopPropagation());
    }

    document.querySelectorAll('[data-settings-action]').forEach(item => {
      item.addEventListener('click', () => {
        menu?.classList.remove('open');
        const a = item.dataset.settingsAction;
        if      (a === 'credentials')   openCredentials();
        else if (a === 'display')       openDisplay();
        else if (a === 'server')        openServer();
        else if (a === 'archives')      Archives.open();
        else if (a === 'chat-history')  ChatHistory.open();
        else if (a === 'notifications') openNotifications();
        else if (a === 'about')         openAbout();
      });
    });

    document.getElementById('creds-close')?.addEventListener('click',   () => Modal.close('creds-modal'));
    document.getElementById('display-close')?.addEventListener('click', () => Modal.close('display-modal'));
    const _closeServer = () => { _stopModalClock(); Modal.close('server-modal'); };
    document.getElementById('server-close')?.addEventListener('click',  _closeServer);
    document.getElementById('server-close-footer')?.addEventListener('click', _closeServer);
    document.getElementById('about-close')?.addEventListener('click',   () => Modal.close('about-modal'));
    document.getElementById('notif-close')?.addEventListener('click',   () => Modal.close('notif-modal'));

    document.getElementById('srv-tz-save')?.addEventListener('click', async () => {
      const sel  = document.getElementById('srv-timezone');
      const msg  = document.getElementById('srv-tz-msg');
      const btn  = document.getElementById('srv-tz-save');
      const tz   = sel?.value?.trim();
      if (!tz) return;
      btn.disabled = true; btn.textContent = '…';
      if (msg) { msg.textContent = ''; msg.style.color = ''; }
      try {
        const r = await API.patchServerSettings({ timezone: tz });
        _startNavClock(r.timezone || tz);
        _stopModalClock();
        btn.disabled = false; btn.textContent = 'Apply Timezone';
        Modal.close('server-modal');
        Toast.success('Timezone updated', `Active: ${r.timezone}`);
      } catch (e) {
        if (msg) { msg.textContent = `Error: ${e?.message || 'Unknown'}`;  msg.style.color = 'var(--danger)'; }
        btn.disabled = false; btn.textContent = 'Apply Timezone';
      }
    });

    // Start navbar clock — fetch TZ from server on boot
    API.getServerSettings().then(r => _startNavClock(r.timezone || 'UTC')).catch(() => _startNavClock('UTC'));

    const slider = document.getElementById('font-size-slider');
    const lbl    = document.getElementById('font-size-label');
    if (slider) {
      slider.addEventListener('input', () => {
        const v = parseInt(slider.value, 10);
        if (lbl) lbl.textContent = `${v}px`;
        _applyFontSize(v);
        _syncPrefs();
      });
    }

    // Per-panel zoom sliders
    _ZOOM_PANELS.forEach(({ key, lsKey, cssVar }) => {
      const sl = document.getElementById(`zoom-${key}-slider`);
      const lb = document.getElementById(`zoom-${key}-label`);
      if (!sl) return;
      sl.addEventListener('input', () => {
        const pct = parseInt(sl.value, 10);
        if (lb) lb.textContent = `${pct}%`;
        _applyZoom(cssVar, pct);
        localStorage.setItem(lsKey, String(pct));
        _syncPrefs();
      });
    });

    // Preview (peek) checkbox — removes overlay backdrop while adjusting
    document.getElementById('disp-peek')?.addEventListener('change', e => {
      document.getElementById('display-modal')?.classList.toggle('peek', e.target.checked);
    });

    // Theme swatches
    document.querySelectorAll('.theme-sw').forEach(sw => {
      sw.addEventListener('click', () => {
        const t = sw.dataset.themePick;
        _applyTheme(t);
        document.querySelectorAll('.theme-sw').forEach(s =>
          s.classList.toggle('active', s.dataset.themePick === t));
        _syncPrefs();
      });
    });
  }

  function refreshCredentialsIfOpen() {
    const modal = document.getElementById('creds-modal');
    if (modal && modal.classList.contains('open')) {
      _renderCredManager();
    }
  }

  return { init, openCredentials, openDisplay, openServer, openAbout, loadServerPrefs, applyTimezone: _startNavClock, refreshCredentialsIfOpen };
})();

/* Apply saved display settings before first render to avoid flash */
(function () {
  const fs = parseInt(localStorage.getItem('sc2_font_size') || '14', 10);
  if (!isNaN(fs)) document.documentElement.style.fontSize = `${fs}px`;

  const theme = localStorage.getItem('sc2_theme') || 'specter';
  document.documentElement.setAttribute('data-theme', theme);

  [
    ['sc2_zoom_sessions', '--zoom-sessions'],
    ['sc2_zoom_detail',   '--zoom-detail'],
    ['sc2_zoom_tabs',     '--zoom-tabs'],
    ['sc2_zoom_chat',     '--zoom-chat'],
  ].forEach(([lsKey, cssVar]) => {
    const pct = parseInt(localStorage.getItem(lsKey) || '100', 10);
    if (!isNaN(pct)) document.documentElement.style.setProperty(cssVar, String(pct / 100));
  });
})();
