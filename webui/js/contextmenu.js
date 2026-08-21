/* ─────────────────────────────────────────────────────────────────────────────
   contextmenu.js — Right-click context menus (Cobalt Strike-style)
   Every area of the webapp is covered — the browser default never appears.
───────────────────────────────────────────────────────────────────────────── */
const ContextMenu = (() => {

  let _el = null;
  let _subEl = null;

  function init() {
    _el = document.createElement('div');
    _el.id = 'ctx-menu';
    _el.style.display = 'none';
    document.body.appendChild(_el);

    _subEl = document.createElement('div');
    _subEl.id = 'ctx-sub';
    _subEl.className = 'ctx-sub';
    _subEl.style.display = 'none';
    document.body.appendChild(_subEl);

    document.addEventListener('contextmenu', _onContext);
    document.addEventListener('click', _hide);
    document.addEventListener('keydown', e => { if (e.key === 'Escape') _hide(); });
    window.addEventListener('scroll', _hide, true);
    window.addEventListener('resize', _hide);
  }

  function _onContext(e) {
    const items = _resolveItems(e.target, e);
    if (!items || items.length === 0) {
      e.preventDefault();
      return;
    }
    e.preventDefault();
    _show(e.clientX, e.clientY, items);
  }

  function _show(x, y, items) {
    if (!_el) return;
    _hideSub();
    _el.innerHTML = '';
    items.forEach(item => {
      if (item.sep) {
        const s = document.createElement('div');
        s.className = 'ctx-sep';
        _el.appendChild(s);
        return;
      }
      const d = document.createElement('div');
      d.className = 'ctx-item' + (item.danger ? ' danger' : '') + (item.disabled ? ' disabled' : '') + (item.sub ? ' has-sub' : '');
      if (item.icon) {
        d.innerHTML = `<span class="ctx-icon">${item.icon}</span><span class="ctx-label">${_esc(item.label)}</span>`;
      } else {
        d.innerHTML = `<span class="ctx-label">${_esc(item.label)}</span>`;
      }
      if (item.hint) {
        d.innerHTML += `<span class="ctx-hint">${_esc(item.hint)}</span>`;
      }
      if (item.sub) {
        d.innerHTML += `<span class="ctx-arrow">▸</span>`;
        d.addEventListener('mouseenter', () => _showSub(d, item.sub));
        d.addEventListener('mouseleave', (e) => {
          const related = e.relatedTarget;
          if (!_subEl.contains(related)) _hideSub();
        });
      }
      if (!item.disabled && !item.sub) {
        d.addEventListener('click', e => {
          e.stopPropagation();
          _hide();
          item.action();
        });
      }
      _el.appendChild(d);
    });

    _el.style.display = 'block';
    const rect = _el.getBoundingClientRect();
    const vw = window.innerWidth, vh = window.innerHeight;
    if (x + rect.width > vw) x = vw - rect.width - 4;
    if (y + rect.height > vh) y = vh - rect.height - 4;
    if (x < 0) x = 4;
    if (y < 0) y = 4;
    _el.style.left = x + 'px';
    _el.style.top  = y + 'px';
  }

  function _showSub(parentItem, items) {
    if (!_subEl) return;
    _subEl.innerHTML = '';
    items.forEach(item => {
      if (item.sep) {
        const s = document.createElement('div');
        s.className = 'ctx-sep';
        _subEl.appendChild(s);
        return;
      }
      const d = document.createElement('div');
      d.className = 'ctx-item' + (item.danger ? ' danger' : '') + (item.disabled ? ' disabled' : '');
      if (item.icon) {
        d.innerHTML = `<span class="ctx-icon">${item.icon}</span><span class="ctx-label">${_esc(item.label)}</span>`;
      } else {
        d.innerHTML = `<span class="ctx-label">${_esc(item.label)}</span>`;
      }
      if (!item.disabled) {
        d.addEventListener('click', e => {
          e.stopPropagation();
          _hide();
          item.action();
        });
      }
      _subEl.appendChild(d);
    });

    _subEl.style.display = 'block';
    const pr = parentItem.getBoundingClientRect();
    const sr = _subEl.getBoundingClientRect();
    const vw = window.innerWidth, vh = window.innerHeight;
    let sx = pr.right + 2;
    let sy = pr.top;
    if (sx + sr.width > vw) sx = pr.left - sr.width - 2;
    if (sy + sr.height > vh) sy = vh - sr.height - 4;
    if (sy < 0) sy = 4;
    _subEl.style.left = sx + 'px';
    _subEl.style.top  = sy + 'px';

    _subEl.addEventListener('mouseleave', _hideSub, { once: true });
  }

  function _hideSub() {
    if (_subEl) _subEl.style.display = 'none';
  }

  function _hide() {
    if (_el) _el.style.display = 'none';
    _hideSub();
  }

  function _esc(s) {
    const d = document.createElement('span');
    d.textContent = s;
    return d.innerHTML;
  }

  /* ═══════════════════════════════════════════════════════════════════════════
     RESOLVE — determines which context menu to show based on click target.
     Every area is covered; the browser default menu never appears.
  ═══════════════════════════════════════════════════════════════════════════ */
  function _resolveItems(target, e) {
    // Modals — let them have basic text operations only
    if (target.closest('.modal-overlay')) return _modalItems(target);

    // Login view
    if (target.closest('#login-view')) return _loginItems(target);

    // --- App view zones (order: most specific first) ---

    // Session table row
    const row = target.closest('#sess-tbody tr');
    if (row) return _sessionRowItems(row);

    // Sessions toolbar area
    if (target.closest('#sessions-toolbar') || target.closest('#sess-table thead')) return _sessToolbarItems();

    // Sessions pane (empty area)
    if (target.closest('#sessions-pane')) return _sessPaneItems();

    // Shell input bar
    if (target.closest('#shell-input-bar')) return _shellInputItems(target);

    // Shell history
    if (target.closest('#shell-hist')) return _shellItems();

    // Tab bar
    if (target.closest('#tab-bar')) return _tabBarItems(target);

    // Pending command bar
    if (target.closest('#pending-bar')) return _pendingBarItems();

    // History tab content
    if (target.closest('#tp-history')) return _historyTabItems(target);

    // Artifacts tab content
    if (target.closest('#tp-artifacts')) return _artifactsTabItems(target);

    // Persistence tab content
    if (target.closest('#tp-persist')) return _persistTabItems(target);

    // Credentials tab content
    if (target.closest('#tp-creds')) return _credsTabItems(target);

    // Control tab content
    if (target.closest('#tp-control')) return _controlTabItems();

    // Info tab content
    if (target.closest('#tp-info')) return _infoTabItems(target);

    // Session header
    if (target.closest('#sess-header')) return _headerItems();

    // Empty state (no session selected)
    if (target.closest('#empty-state')) return _emptyStateItems();

    // Chat panel
    if (target.closest('#chat-panel')) return _chatItems(target);

    // Topbar
    if (target.closest('#topbar')) return _topbarItems();

    // Resize handles
    if (target.closest('#resize-handle') || target.closest('#chat-resize-handle')) return [];

    // Absolute fallback — generic menu for any unmatched area
    return _fallbackItems();
  }

  /* ═══════════════════════════════════════════════════════════════════════════
     CONTEXT MENUS — one function per area
  ═══════════════════════════════════════════════════════════════════════════ */

  /* ── Session table row ────────────────────────────────────────────────── */
  function _sessionRowItems(row) {
    const sid = row.dataset.id;
    if (!sid) return [];
    const s = Sessions.getSession(sid);
    if (!s) return [];

    const host = s.target_host || s.label || s.folder_path || sid.slice(0, 8);
    const locked = !!s.locked;

    return [
      { label: `Interact — ${host}`, icon: '▶', action: () => Sessions.select(sid) },
      { label: locked ? 'Unlock Session' : 'Lock Session', icon: locked ? '🔓' : '🔒', action: async () => {
        try { await API.toggleLock(sid); } catch(e) { Toast.error('Lock failed', e.message); }
      }},
      { sep: true },
      { label: 'Quick Commands', icon: '⚡', sub: [
        { label: '/sysinfo', action: () => { Sessions.select(sid); setTimeout(() => Sessions.doSysinfo(), 80); } },
        { label: '/status', action: () => _sendCmd(sid, '/status') },
        { label: '/env', action: () => _sendCmd(sid, '/env') },
        { sep: true },
        { label: '/persist probe', action: () => { Sessions.select(sid); setTimeout(() => Sessions.doPersistProbeAll(), 80); } },
        { label: '/creds harvest', action: () => _sendCmd(sid, '/creds harvest') },
        { label: '/creds harvest decrypt', action: () => _sendCmd(sid, '/creds harvest decrypt') },
      ]},
      { label: 'Beacon Config', icon: '⏱', sub: [
        { label: '/sleep…', action: () => { Sessions.select(sid); setTimeout(() => _openPromptModal('Sleep (seconds)', s.agent_sleep || 30, async v => { const n = parseInt(v, 10); if (n > 0) { try { await API.sleep(sid, n); Toast.ok('Sleep', `Set to ${n}s`); } catch(e) { Toast.error('Sleep failed', e.message); } } }), 80); } },
        { label: '/jitter…', action: () => { Sessions.select(sid); setTimeout(() => _openPromptModal('Jitter (%)', s.agent_jitter || 20, async v => { const n = parseInt(v, 10); if (n >= 0 && n <= 50) { try { await API.jitter(sid, n); Toast.ok('Jitter', `Set to ${n}%`); } catch(e) { Toast.error('Jitter failed', e.message); } } }), 80); } },
      ]},
      { label: 'File Operations', icon: '📁', sub: [
        { label: '/download…', action: () => { Sessions.select(sid); setTimeout(() => _openPromptModal('Remote path to download', '', v => { if (v) _sendCmd(sid, `/download ${v}`); }), 80); } },
        { label: '/upload…', action: () => { Sessions.select(sid); setTimeout(() => _triggerUpload(), 80); } },
        { label: '/exfil…', action: () => { Sessions.select(sid); setTimeout(() => _openPromptModal('Glob pattern to exfiltrate', '', v => { if (v) _sendCmd(sid, `/exfil ${v}`); }), 80); } },
        { sep: true },
        { label: '/timestomp…', action: () => { Sessions.select(sid); setTimeout(() => { const inp = document.getElementById('cmd-in'); if (inp) { inp.value = '/timestomp '; inp.focus(); } }, 80); } },
      ]},
      { sep: true },
      { label: 'Copy', icon: '📋', sub: [
        { label: 'Session ID', action: () => _clip(sid) },
        { label: `Internal IP — ${s.target_ip || '—'}`, action: () => _clip(s.target_ip), disabled: !s.target_ip },
        { label: `External IP — ${s.target_ip_ext || '—'}`, action: () => _clip(s.target_ip_ext), disabled: !s.target_ip_ext },
        { label: `Hostname — ${s.target_host || '—'}`, action: () => _clip(s.target_host), disabled: !s.target_host },
        { label: `User — ${s.target_user || '—'}`, action: () => _clip(s.target_user), disabled: !s.target_user },
        { label: `OS — ${s.target_os || '—'}`, action: () => _clip(s.target_os), disabled: !s.target_os },
        { label: 'Folder Path', action: () => _clip(s.folder_path), disabled: !s.folder_path },
      ]},
      { sep: true },
      { label: '/kill', icon: '💀', danger: true, disabled: locked, action: () => { if (confirm(`Kill agent on ${host}? This removes persistence and exits.`)) { Sessions.select(sid); setTimeout(() => Sessions.doKillAgent(), 80); } } },
      { label: '/stop', icon: '⏹', danger: true, disabled: locked, action: () => _sendCmd(sid, '/stop') },
      { label: 'Delete Session', icon: '🗑', danger: true, disabled: locked, action: () => { if (confirm(`Delete session ${sid.slice(0, 8)}? Data will be removed from cloud and server.`)) { Sessions.select(sid); setTimeout(() => Sessions.doWipeSession(), 80); } } },
    ];
  }

  /* ── Sessions toolbar ────────────────────────────────────────────────── */
  function _sessToolbarItems() {
    return [
      { label: 'Deploy New Agent', icon: '➕', action: () => {
        const btn = document.getElementById('btn-deploy');
        if (btn) btn.click();
      }},
      { label: 'Tradecraft Library', icon: '📦', action: () => {
        const btn = document.getElementById('btn-tradecraft');
        if (btn) btn.click();
      }},
    ];
  }

  /* ── Sessions pane empty area ────────────────────────────────────────── */
  function _sessPaneItems() {
    return [
      { label: 'Deploy New Agent', icon: '➕', action: () => {
        const btn = document.getElementById('btn-deploy');
        if (btn) btn.click();
      }},
      { label: 'Tradecraft Library', icon: '📦', action: () => {
        const btn = document.getElementById('btn-tradecraft');
        if (btn) btn.click();
      }},
    ];
  }

  /* ── Shell output ─────────────────────────────────────────────────────── */
  function _shellItems() {
    const sel = window.getSelection();
    const hasSelection = sel && sel.toString().trim().length > 0;
    const hist = document.getElementById('shell-hist');

    return [
      { label: 'Copy Selection', icon: '📋', action: () => { document.execCommand('copy'); }, disabled: !hasSelection },
      { label: 'Copy All Output', icon: '📄', action: () => { if (hist) _clip(hist.innerText); } },
      { sep: true },
      { label: 'Select All', icon: '☐', action: () => {
        if (!hist) return;
        const range = document.createRange();
        range.selectNodeContents(hist);
        const s = window.getSelection();
        s.removeAllRanges();
        s.addRange(range);
      }},
      { sep: true },
      { label: 'Search Output…', icon: '🔍', action: () => {
        _openPromptModal('Search output', '', text => {
          if (!text || !hist) return;
          const content = hist.innerText;
          const idx = content.toLowerCase().indexOf(text.toLowerCase());
          if (idx >= 0) {
            Toast.ok('Found', `Match at position ${idx}`);
            if (window.find) window.find(text, false, false, true);
          } else {
            Toast.info('Not found', `"${text}" not in output`);
          }
        });
      }},
      { label: 'Word Wrap Toggle', icon: '↩', action: () => {
        if (!hist) return;
        hist.style.whiteSpace = hist.style.whiteSpace === 'pre' ? 'pre-wrap' : 'pre';
      }},
    ];
  }

  /* ── Shell input bar ──────────────────────────────────────────────────── */
  function _shellInputItems(target) {
    const inp = document.getElementById('cmd-in');
    const hasText = inp && inp.value.trim().length > 0;
    const hasCbText = !!navigator.clipboard;

    return [
      { label: 'Paste', icon: '📋', action: async () => {
        if (!inp) return;
        try {
          const text = await navigator.clipboard.readText();
          inp.value += text;
          inp.focus();
        } catch { Toast.error('Paste failed', 'Clipboard access denied'); }
      }, disabled: !hasCbText },
      { label: 'Clear Input', icon: '✕', action: () => { if (inp) { inp.value = ''; inp.focus(); } }, disabled: !hasText },
      { sep: true },
      { label: 'Command Shortcuts', icon: '⚡', sub: [
        { label: '/sysinfo', action: () => _setInput('/sysinfo') },
        { label: '/status', action: () => _setInput('/status') },
        { label: '/env', action: () => _setInput('/env') },
        { label: '/sleep', action: () => _setInput('/sleep ') },
        { label: '/jitter', action: () => _setInput('/jitter ') },
        { sep: true },
        { label: '/download', action: () => _setInput('/download ') },
        { label: '/upload', action: () => _triggerUpload() },
        { label: '/exfil', action: () => _setInput('/exfil ') },
        { sep: true },
        { label: '/persist probe', action: () => _setInput('/persist probe') },
        { label: '/creds harvest', action: () => _setInput('/creds harvest') },
        { label: '/creds listen start smb:445', action: () => _setInput('/creds listen start smb:445') },
        { label: '/creds listen start http:80', action: () => _setInput('/creds listen start http:80') },
        { label: '/creds listen dump', action: () => _setInput('/creds listen dump') },
      ]},
    ];
  }

  /* ── Tab bar ──────────────────────────────────────────────────────────── */
  function _tabBarItems(target) {
    const items = [
      { label: 'Shell', icon: '▶', hint: '', action: () => _clickTab('shell') },
      { label: 'History', icon: '📜', action: () => _clickTab('history') },
      { label: 'Artifacts', icon: '📎', action: () => _clickTab('artifacts') },
      { label: 'Persistence', icon: '🔄', action: () => _clickTab('persist') },
      { label: 'Control', icon: '⚙', action: () => _clickTab('control') },
      { label: 'Info', icon: 'ℹ', action: () => _clickTab('info') },
    ];
    return items;
  }

  /* ── Pending command bar ──────────────────────────────────────────────── */
  function _pendingBarItems() {
    const sid = Sessions.getActiveId ? Sessions.getActiveId() : null;
    return [
      { label: 'Cancel Command', icon: '✕', danger: true, action: () => {
        if (sid) _sendCmd(sid, '/cancel');
      }, disabled: !sid },
      { label: 'Copy Pending Text', icon: '📋', action: () => {
        const el = document.getElementById('pending-cmd-text');
        if (el) _clip(el.textContent);
      }},
    ];
  }

  /* ── History tab ──────────────────────────────────────────────────────── */
  function _historyTabItems(target) {
    const row = target.closest('#hist-tbody tr');
    const sid = Sessions.getActiveId ? Sessions.getActiveId() : null;
    const items = [];

    if (row) {
      items.push(
        { label: 'View Detail', icon: '🔍', action: () => { row.click(); } },
        { label: 'Copy Command', icon: '📋', action: () => {
          const cells = row.querySelectorAll('td');
          const cmd = cells[1] ? cells[1].textContent : '';
          _clip(cmd);
        }},
        { label: 'Copy Output', icon: '📄', action: () => {
          const cells = row.querySelectorAll('td');
          const out = cells[2] ? cells[2].textContent : '';
          _clip(out);
        }},
        { label: 'Re-run Command', icon: '↺', action: () => {
          const cells = row.querySelectorAll('td');
          const cmd = cells[1] ? cells[1].textContent.trim() : '';
          if (cmd && sid) _sendCmd(sid, cmd);
        }, disabled: !sid },
        { sep: true },
      );
    }

    items.push(
      { label: 'Export XLSX', icon: '⬇', action: () => {
        const btn = document.getElementById('btn-hist-dl');
        if (btn) btn.click();
      }},
      { label: 'Search History…', icon: '🔍', action: () => {
        const inp = document.getElementById('hist-search');
        if (inp) { inp.focus(); inp.select(); }
      }},
      { label: 'Refresh History', icon: '↺', action: () => {
        if (sid) Sessions.select(sid);
      }},
    );

    return items;
  }

  /* ── Artifacts tab ────────────────────────────────────────────────────── */
  function _artifactsTabItems(target) {
    const sid = Sessions.getActiveId ? Sessions.getActiveId() : null;
    const items = [];

    // Check if we clicked on a downloads/artifacts row
    const dlRow = target.closest('#artifacts-tbody tr');
    if (dlRow) {
      const cells = dlRow.querySelectorAll('td');
      const filename = cells[0] ? cells[0].textContent.trim() : '';
      const filepath = cells[1] ? cells[1].textContent.trim() : '';

      items.push(
        { label: 'Preview File', icon: '👁', action: () => {
          const previewBtn = dlRow.querySelector('.btn-preview, [title*="Preview"]');
          if (previewBtn) previewBtn.click();
          else dlRow.click();
        }},
        { label: 'Download File', icon: '⬇', action: () => {
          const dlBtn = dlRow.querySelector('.btn-dl, a[download], [title*="Download"]');
          if (dlBtn) dlBtn.click();
        }},
        { label: 'Copy Filename', icon: '📋', action: () => _clip(filename) },
        { label: 'Copy File Path', icon: '📋', action: () => _clip(filepath), disabled: !filepath },
        { sep: true },
      );
    }

    // On-target artifact row
    const otRow = target.closest('#ontarget-tbody tr');
    if (otRow) {
      const cells = otRow.querySelectorAll('td');
      const artType = cells[0] ? cells[0].textContent.trim() : '';
      const artPath = cells[1] ? cells[1].textContent.trim() : '';
      items.push(
        { label: 'Copy Artifact Path', icon: '📋', action: () => _clip(artPath), disabled: !artPath },
        { label: `Copy Type — ${artType}`, icon: '📋', action: () => _clip(artType), disabled: !artType },
        { sep: true },
      );
    }

    // Upload row
    const ulRow = target.closest('#uploads-tbody tr');
    if (ulRow) {
      const cells = ulRow.querySelectorAll('td');
      const ulName = cells[0] ? cells[0].textContent.trim() : '';
      const ulPath = cells[2] ? cells[2].textContent.trim() : '';
      items.push(
        { label: 'Copy Filename', icon: '📋', action: () => _clip(ulName), disabled: !ulName },
        { label: 'Copy Remote Path', icon: '📋', action: () => _clip(ulPath), disabled: !ulPath },
        { sep: true },
      );
    }

    // Segment control (EXFIL / FILEPATH toggle)
    const segCtrl = target.closest('.seg-ctrl');
    if (segCtrl) {
      items.push(
        { label: 'Show Filenames', action: () => { const b = document.querySelector('.seg-btn[data-mode="name"]'); if (b) b.click(); } },
        { label: 'Show File Paths', action: () => { const b = document.querySelector('.seg-btn[data-mode="path"]'); if (b) b.click(); } },
        { sep: true },
      );
    }

    items.push(
      { label: 'Upload File…', icon: '⬆', action: () => _triggerUpload() },
      { label: 'Refresh Artifacts', icon: '↺', action: () => {
        if (sid) Sessions.select(sid);
      }},
    );

    return items;
  }

  /* ── Persistence tab ──────────────────────────────────────────────────── */
  function _persistTabItems(target) {
    const sid = Sessions.getActiveId ? Sessions.getActiveId() : null;
    if (!sid) return [];

    const techRow = target.closest('.persist-tech, .persist-row, tr[data-tech]');
    const items = [];

    if (techRow) {
      const techId = techRow.dataset.tech || techRow.dataset.id;
      if (techId) {
        items.push(
          { label: `Probe ${techId}`, icon: '🔍', action: () => Sessions.doPersistProbeSelected && Sessions.doPersistProbeSelected(techId) },
          { label: `Install ${techId}`, icon: '📌', action: () => Sessions.doPersistInstallSelected && Sessions.doPersistInstallSelected(techId) },
          { label: `Remove ${techId}`, icon: '🗑', danger: true, action: () => Sessions.doPersistRemoveSelected && Sessions.doPersistRemoveSelected(techId) },
          { label: `Status ${techId}`, icon: 'ℹ', action: () => { _sendCmd(sid, `/persist status ${techId}`); } },
          { sep: true },
        );
      }
    }

    items.push(
      { label: 'Probe All', icon: '🔍', action: () => Sessions.doPersistProbeAll() },
      { label: 'Full Status', icon: 'ℹ', action: () => Sessions.doPersistStatus && Sessions.doPersistStatus() },
      { sep: true },
      { label: 'Refresh', icon: '↺', action: () => { if (sid) Sessions.select(sid); } },
    );

    return items;
  }

  /* ── Credentials tab ────────────────────────────────────────────────── */
  function _credsTabItems(target) {
    const sid = Sessions.getActiveId ? Sessions.getActiveId() : null;
    if (!sid) return [];

    const row = target.closest('tr[data-cred-id]');
    const items = [];

    if (row) {
      const secretEl = row.querySelector('.cred-secret');
      const userEl = row.querySelector('td.hi');
      items.push(
        { label: 'Copy Secret', icon: '🔑', action: () => { if (secretEl) navigator.clipboard.writeText(secretEl.textContent); Toast.show('ok', 'Copied'); } },
        { label: 'Copy Username', icon: '👤', action: () => { if (userEl) navigator.clipboard.writeText(userEl.textContent); Toast.show('ok', 'Copied'); } },
        { sep: true },
        { label: 'Edit', icon: '✎', action: () => row.querySelector('.cred-edit')?.click() },
        { label: 'Delete', icon: '✕', danger: true, action: () => row.querySelector('.cred-del')?.click() },
        { sep: true },
      );
    }

    items.push(
      { label: 'Add Credential', icon: '+', action: () => document.getElementById('btn-cred-add')?.click() },
      { sep: true },
      { label: 'Refresh', icon: '↺', action: () => Sessions.onCredentialsChanged(sid) },
    );

    return items;
  }

  /* ── Control tab ──────────────────────────────────────────────────────── */
  function _controlTabItems() {
    const sid = Sessions.getActiveId ? Sessions.getActiveId() : null;
    if (!sid) return [];
    const s = Sessions.getSession(sid);
    if (!s) return [];

    const locked = !!s.locked;
    const host = s.target_host || sid.slice(0, 8);

    return [
      { label: '/sleep…', icon: '⏱', action: () => _openPromptModal('Sleep (seconds)', s.agent_sleep || 30, async v => { const n = parseInt(v, 10); if (n > 0) { try { await API.sleep(sid, n); Toast.ok('Sleep', `Set to ${n}s`); } catch(e) { Toast.error('Sleep failed', e.message); } } }) },
      { label: '/jitter…', icon: '📊', action: () => _openPromptModal('Jitter (%)', s.agent_jitter || 20, async v => { const n = parseInt(v, 10); if (n >= 0 && n <= 50) { try { await API.jitter(sid, n); Toast.ok('Jitter', `Set to ${n}%`); } catch(e) { Toast.error('Jitter failed', e.message); } } }) },
      { sep: true },
      { label: 'Stop Polling', icon: '■', action: async () => {
        try { await API.stopPolling(sid); Toast.ok('Polling', 'Stopped'); } catch(e) { Toast.error('Poll stop failed', e.message); }
      }},
      { label: 'Resume Polling', icon: '▶', action: async () => {
        try { await API.resumePolling(sid); Toast.ok('Polling', 'Resumed'); } catch(e) { Toast.error('Poll resume failed', e.message); }
      }},
      { sep: true },
      { label: locked ? 'Unlock Session' : 'Lock Session', icon: locked ? '🔓' : '🔒', action: async () => {
        try { await API.toggleLock(sid); } catch(e) { Toast.error('Lock failed', e.message); }
      }},
      { sep: true },
      { label: '/stop', icon: '⏹', danger: true, disabled: locked, action: () => _sendCmd(sid, '/stop') },
      { label: '/kill', icon: '💀', danger: true, disabled: locked, action: () => { if (confirm(`Kill agent on ${host}?`)) Sessions.doKillAgent(); } },
      { label: 'Delete Session', icon: '🗑', danger: true, disabled: locked, action: () => { if (confirm(`Delete session ${sid.slice(0, 8)}?`)) Sessions.doWipeSession(); } },
    ];
  }

  /* ── Info tab ─────────────────────────────────────────────────────────── */
  function _infoTabItems(target) {
    const sid = Sessions.getActiveId ? Sessions.getActiveId() : null;
    if (!sid) return [];
    const s = Sessions.getSession(sid);
    if (!s) return [];

    // Check if user clicked on a specific info value
    const cell = target.closest('td, .info-val, .info-value, dd, span');
    const cellText = cell ? cell.textContent.trim() : '';

    const items = [];
    if (cellText && cellText !== '—' && cellText !== 'N/A') {
      items.push(
        { label: `Copy: ${cellText.slice(0, 30)}${cellText.length > 30 ? '…' : ''}`, icon: '📋', action: () => _clip(cellText) },
        { sep: true },
      );
    }

    items.push(
      { label: 'Copy All Info', icon: '📄', action: () => {
        const inner = document.getElementById('info-inner');
        if (inner) _clip(inner.innerText);
      }},
      { sep: true },
      { label: 'Copy Session ID', action: () => _clip(sid) },
      { label: 'Copy Hostname', action: () => _clip(s.target_host), disabled: !s.target_host },
      { label: 'Copy Int IP', action: () => _clip(s.target_ip), disabled: !s.target_ip },
      { label: 'Copy Ext IP', action: () => _clip(s.target_ip_ext), disabled: !s.target_ip_ext },
      { label: 'Copy User', action: () => _clip(s.target_user), disabled: !s.target_user },
      { label: 'Copy OS', action: () => _clip(s.target_os), disabled: !s.target_os },
      { label: 'Copy Domain', action: () => _clip(s.target_domain), disabled: !s.target_domain },
      { label: 'Copy Folder Path', action: () => _clip(s.folder_path), disabled: !s.folder_path },
      { sep: true },
      { label: '/sysinfo (refresh)', icon: '↺', action: () => Sessions.doSysinfo() },
    );

    return items;
  }

  /* ── Session header ───────────────────────────────────────────────────── */
  function _headerItems() {
    const sid = Sessions.getActiveId ? Sessions.getActiveId() : null;
    if (!sid) return [];
    const s = Sessions.getSession(sid);
    if (!s) return [];

    return [
      { label: 'Copy Session ID', icon: '📋', action: () => _clip(sid) },
      { label: 'Copy Folder Path', icon: '📋', action: () => _clip(s.folder_path), disabled: !s.folder_path },
      { label: 'Copy Internal IP', icon: '📋', action: () => _clip(s.target_ip), disabled: !s.target_ip },
      { label: 'Copy External IP', icon: '📋', action: () => _clip(s.target_ip_ext), disabled: !s.target_ip_ext },
      { label: 'Copy Hostname', icon: '📋', action: () => _clip(s.target_host), disabled: !s.target_host },
      { sep: true },
      { label: 'Stop Polling', icon: '■', action: async () => {
        try { await API.stopPolling(sid); Toast.ok('Polling', 'Stopped'); } catch(e) { Toast.error('Poll stop failed', e.message); }
      }},
      { label: 'Resume Polling', icon: '▶', action: async () => {
        try { await API.resumePolling(sid); Toast.ok('Polling', 'Resumed'); } catch(e) { Toast.error('Poll resume failed', e.message); }
      }},
    ];
  }

  /* ── Empty state (no session selected) ────────────────────────────────── */
  function _emptyStateItems() {
    return [
      { label: 'Deploy New Agent', icon: '➕', action: () => {
        const btn = document.getElementById('btn-deploy');
        if (btn) btn.click();
      }},
      { label: 'Tradecraft Library', icon: '📦', action: () => {
        const btn = document.getElementById('btn-tradecraft');
        if (btn) btn.click();
      }},
    ];
  }

  /* ── Chat panel ───────────────────────────────────────────────────────── */
  function _chatItems(target) {
    const sel = window.getSelection();
    const hasSelection = sel && sel.toString().trim().length > 0;
    const isInput = target.closest('#chat-in');
    const msgs = document.getElementById('chat-msgs');

    if (isInput) {
      const inp = document.getElementById('chat-in');
      const hasText = inp && inp.value.trim().length > 0;
      return [
        { label: 'Paste', icon: '📋', action: async () => {
          if (!inp) return;
          try { const t = await navigator.clipboard.readText(); inp.value += t; inp.focus(); } catch {}
        }},
        { label: 'Clear Input', icon: '✕', action: () => { if (inp) { inp.value = ''; inp.focus(); } }, disabled: !hasText },
      ];
    }

    // Message area
    const msgEl = target.closest('.chat-msg');
    const items = [];
    if (msgEl) {
      const msgText = msgEl.querySelector('.chat-msg-text, .chat-msg-body');
      items.push(
        { label: 'Copy Message', icon: '📋', action: () => _clip(msgText ? msgText.textContent : msgEl.textContent) },
      );
    }
    if (hasSelection) {
      items.push(
        { label: 'Copy Selection', icon: '📋', action: () => document.execCommand('copy') },
      );
    }
    items.push(
      { label: 'Copy All Chat', icon: '📄', action: () => { if (msgs) _clip(msgs.innerText); } },
      { sep: true },
      { label: 'Scroll to Bottom', icon: '⬇', action: () => { if (msgs) msgs.scrollTop = msgs.scrollHeight; } },
    );

    return items;
  }

  /* ── Topbar ───────────────────────────────────────────────────────────── */
  function _topbarItems() {
    return [
      { label: 'Deploy New Agent', icon: '➕', action: () => {
        const btn = document.getElementById('btn-deploy');
        if (btn) btn.click();
      }},
      { label: 'Tradecraft Library', icon: '📦', action: () => {
        const btn = document.getElementById('btn-tradecraft');
        if (btn) btn.click();
      }},
      { sep: true },
      { label: 'Operator Chat', icon: '💬', action: () => {
        const btn = document.getElementById('btn-chat-toggle');
        if (btn) btn.click();
      }},
      { label: 'Settings', icon: '⚙', action: () => {
        const btn = document.getElementById('btn-settings');
        if (btn) btn.click();
      }},
      { label: 'Help', icon: '?', action: () => Modal.open('help-modal') },
      { sep: true },
      { label: 'About Stratum', icon: 'ℹ', action: () => Modal.open('about-modal') },
      { label: 'Check for Updates', icon: '↺', action: async () => {
        try {
          const r = await API.checkUpdate();
          if (r.update && r.update.available) {
            Toast.info('Update', `v${r.update.latest} available`);
          } else {
            Toast.ok('Up to date', 'No updates available');
          }
        } catch { Toast.error('Error', 'Could not check for updates'); }
      }},
      { sep: true },
      { label: 'Logout', icon: '⏻', danger: true, action: () => {
        const btn = document.getElementById('btn-logout');
        if (btn) btn.click();
      }},
    ];
  }

  /* ── Login view ───────────────────────────────────────────────────────── */
  function _loginItems(target) {
    if (target.closest('input')) {
      return [
        { label: 'Paste', icon: '📋', action: async () => {
          try {
            const text = await navigator.clipboard.readText();
            if (document.activeElement && document.activeElement.tagName === 'INPUT') {
              document.activeElement.value += text;
            }
          } catch {}
        }},
        { label: 'Clear Field', icon: '✕', action: () => {
          if (document.activeElement && document.activeElement.tagName === 'INPUT') {
            document.activeElement.value = '';
          }
        }},
      ];
    }
    return [
      { label: 'About Stratum', icon: 'ℹ', action: () => { Toast.info('Stratum C2', 'Dead-drop C2 via cloud storage'); } },
    ];
  }

  /* ── Modal content ────────────────────────────────────────────────────── */
  function _modalItems(target) {
    const sel = window.getSelection();
    const hasSelection = sel && sel.toString().trim().length > 0;

    if (target.closest('input, textarea')) {
      return [
        { label: 'Paste', icon: '📋', action: async () => {
          try {
            const text = await navigator.clipboard.readText();
            if (document.activeElement) document.activeElement.value += text;
          } catch {}
        }},
        { label: 'Select All', icon: '☐', action: () => {
          if (document.activeElement) document.activeElement.select();
        }},
        { label: 'Clear', icon: '✕', action: () => {
          if (document.activeElement) document.activeElement.value = '';
        }},
      ];
    }

    const items = [];
    if (hasSelection) {
      items.push({ label: 'Copy Selection', icon: '📋', action: () => document.execCommand('copy') });
    }

    // Pre/code blocks — offer copy entire block
    const pre = target.closest('pre, code, .cmd-detail-pre');
    if (pre) {
      items.push({ label: 'Copy Block', icon: '📄', action: () => _clip(pre.textContent) });
    }

    if (items.length === 0) {
      items.push({ label: 'Close', icon: '✕', action: () => {
        const overlay = target.closest('.modal-overlay');
        if (overlay) {
          const closeBtn = overlay.querySelector('.modal-close');
          if (closeBtn) closeBtn.click();
        }
      }});
    }

    return items;
  }

  /* ── Fallback (any unmatched area) ────────────────────────────────────── */
  function _fallbackItems() {
    const sel = window.getSelection();
    const hasSelection = sel && sel.toString().trim().length > 0;
    const items = [];

    if (hasSelection) {
      items.push({ label: 'Copy Selection', icon: '📋', action: () => document.execCommand('copy') });
      items.push({ sep: true });
    }

    items.push(
      { label: 'Deploy New Agent', icon: '➕', action: () => {
        const btn = document.getElementById('btn-deploy');
        if (btn) btn.click();
      }},
      { sep: true },
      { label: 'About Stratum', icon: 'ℹ', action: () => Modal.open('about-modal') },
    );

    return items;
  }

  /* ═══════════════════════════════════════════════════════════════════════════
     HELPERS
  ═══════════════════════════════════════════════════════════════════════════ */
  function _clip(text) {
    if (!text) return;
    navigator.clipboard.writeText(text).then(
      () => Toast.ok('Copied', text.length > 50 ? text.slice(0, 50) + '…' : text),
      () => Toast.error('Copy failed', 'Clipboard access denied')
    );
  }

  function _sendCmd(sid, cmd) {
    Sessions.select(sid);
    setTimeout(async () => {
      try { await API.sendCommand(sid, cmd, cmd); }
      catch (e) { Toast.error('Command failed', e.message); }
    }, 80);
  }

  function _setInput(text) {
    const inp = document.getElementById('cmd-in');
    if (inp) {
      inp.value = text;
      inp.focus();
      if (text.endsWith(' ')) inp.setSelectionRange(text.length, text.length);
    }
  }

  function _clickTab(name) {
    const btn = document.querySelector(`#tab-bar .tab[data-tab="${name}"]`);
    if (btn) btn.click();
  }

  function _triggerUpload() {
    const btn = document.querySelector('#shell-input-bar .btn-upload, [title*="Upload"]');
    if (btn) { btn.click(); return; }
    Modal.open('upload-modal');
  }

  function _openPromptModal(label, defaultVal, onConfirm) {
    let overlay = document.getElementById('ctx-prompt-overlay');
    if (overlay) overlay.remove();

    overlay = document.createElement('div');
    overlay.id = 'ctx-prompt-overlay';
    overlay.className = 'ctx-prompt-overlay';
    overlay.innerHTML = `
      <div class="ctx-prompt-box">
        <div class="ctx-prompt-label">${_esc(label)}</div>
        <input class="ctx-prompt-input" type="text" value="${defaultVal}" spellcheck="false" autocomplete="off">
        <div class="ctx-prompt-btns">
          <button class="ctx-prompt-cancel">Cancel</button>
          <button class="ctx-prompt-ok">OK</button>
        </div>
      </div>`;
    document.body.appendChild(overlay);

    const inp    = overlay.querySelector('.ctx-prompt-input');
    const okBtn  = overlay.querySelector('.ctx-prompt-ok');
    const cancel = overlay.querySelector('.ctx-prompt-cancel');

    function close() { overlay.remove(); }
    function conf() { const v = inp.value.trim(); close(); if (v !== '') onConfirm(v); }

    okBtn.addEventListener('click', conf);
    cancel.addEventListener('click', close);
    overlay.addEventListener('click', e => { if (e.target === overlay) close(); });
    inp.addEventListener('keydown', e => { if (e.key === 'Enter') conf(); if (e.key === 'Escape') close(); });

    inp.focus();
    inp.select();
  }

  return { init };
})();
