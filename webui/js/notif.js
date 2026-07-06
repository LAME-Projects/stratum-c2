/* ─────────────────────────────────────────────────────────────────────────────
   notif.js — Per-operator notification preferences + in-app toast routing
───────────────────────────────────────────────────────────────────────────── */

const Notif = (() => {
  const _DEFAULTS = {
    agent_state:     true,
    agent_first_hb:  true,
    chat_message:    true,
    session_new:     true,
    session_removed: true,
    cmd_response:    false,
  };

  const _META = [
    { key: 'agent_state',     label: 'Agent state change',   desc: 'Dead / reconnected transitions for any session' },
    { key: 'agent_first_hb',  label: 'Agent first check-in', desc: 'New agent checks in for the first time' },
    { key: 'chat_message',    label: 'New chat message',      desc: 'Message arrives while the chat panel is closed' },
    { key: 'session_new',     label: 'New session deployed',  desc: 'Another operator deploys a new session' },
    { key: 'session_removed', label: 'Session removed',       desc: 'A session is wiped or terminated' },
    { key: 'cmd_response',    label: 'Command response',      desc: 'Agent returns output for a sent command (noisy — off by default)' },
  ];

  let _prefs      = { ..._DEFAULTS };
  let _chatUnread = 0;
  let _saveTimer  = null;

  /* ── internal helpers ───────────────────────────────────────────────────── */
  function _isChatOpen() {
    const p = document.getElementById('chat-panel');
    return p && !p.classList.contains('hidden');
  }

  function _updateBadge() {
    const badge = document.getElementById('chat-badge');
    if (!badge) return;
    if (_chatUnread > 0) {
      badge.textContent = _chatUnread > 9 ? '9+' : String(_chatUnread);
      badge.classList.add('visible');
    } else {
      badge.textContent = '';
      badge.classList.remove('visible');
    }
  }

  function _schedSave() {
    if (_saveTimer) clearTimeout(_saveTimer);
    _saveTimer = setTimeout(async () => {
      try { await API.savePrefs({ notifications: _prefs }); } catch {}
    }, 600);
  }

  function _toastLevel(category, extra) {
    if (category === 'agent_state') return extra?.alive ? 'success' : 'warning';
    if (category === 'session_removed') return 'warning';
    if (category === 'chat_message')    return 'info';
    return 'success';
  }

  /* ── public API ─────────────────────────────────────────────────────────── */
  function trigger(category, title, msg, extra = {}) {
    if (!_prefs[category]) return;
    const level = _toastLevel(category, extra);
    Toast[level](title, msg);
    if (!document.hasFocus() && 'Notification' in window && Notification.permission === 'granted') {
      try { new Notification(`Stratum — ${title}`, { body: msg, icon: '/assets/favicon.svg' }); } catch {}
    }
  }

  function markChatUnread() {
    if (_isChatOpen()) return;
    _chatUnread++;
    _updateBadge();
  }

  function markChatRead() {
    _chatUnread = 0;
    _updateBadge();
  }

  /* ── settings UI ────────────────────────────────────────────────────────── */
  function renderSettings(container) {
    if (!container) return;
    container.innerHTML = '';

    const note = document.createElement('p');
    note.className = 'text-dim';
    note.style.cssText = 'font-size:.78rem;margin-bottom:.85rem;line-height:1.6';
    note.textContent = 'Errors and connection alerts are always shown. Configure optional event notifications below.';
    container.appendChild(note);

    _META.forEach(({ key, label, desc }) => {
      const row = document.createElement('div');
      row.className = 'notif-row';
      const chkId = `notif-chk-${key}`;
      row.innerHTML = `
        <div class="notif-info">
          <div class="notif-label">${escHtml(label)}</div>
          <div class="notif-desc">${escHtml(desc)}</div>
        </div>
        <label class="notif-toggle">
          <input type="checkbox" id="${chkId}" data-key="${key}"${_prefs[key] ? ' checked' : ''}>
          <span class="notif-slider"></span>
        </label>`;
      row.querySelector('input').addEventListener('change', e => {
        _prefs[key] = e.target.checked;
        _schedSave();
      });
      container.appendChild(row);
    });
  }

  async function init() {
    try {
      const data = await API.getPrefs();
      // API returns flat object: { sc2_theme, notifications, ... }
      if (data?.notifications && typeof data.notifications === 'object') {
        _prefs = { ..._DEFAULTS, ...data.notifications };
      }
    } catch {}
    if ('Notification' in window && Notification.permission === 'default') {
      Notification.requestPermission();
    }
  }

  return { init, trigger, markChatUnread, markChatRead, renderSettings };
})();
