/* ─────────────────────────────────────────────────────────────────────────────
   chat.js — Operator chat panel
───────────────────────────────────────────────────────────────────────────── */

const Chat = (() => {
  let _me          = null;
  let _viewingDate = null; // null = live (today), "YYYY-MM-DD" = archive


  function _msgs()  { return document.getElementById('chat-msgs'); }
  function _input() { return document.getElementById('chat-in'); }
  function _today() { return new Date().toISOString().slice(0, 10); }

  /* ── avatar color (deterministic hue from username) ─────────────────────── */
  function _hue(name) {
    let h = 0;
    for (let i = 0; i < name.length; i++) h = (h * 31 + name.charCodeAt(i)) & 0xffff;
    return h % 360;
  }

  /* ── render system event divider ─────────────────────────────────────────── */
  function _renderEvent(type, text) {
    const msgs = _msgs();
    if (!msgs) return;
    const cls = type === 'connect' ? 'ok' : type === 'disconnect' ? 'w' : 'i';
    const div = document.createElement('div');
    div.className = 'ev';
    div.innerHTML = `<span class="et ${cls}">${escHtml(text)}</span>`;
    msgs.appendChild(div);
    msgs.scrollTop = msgs.scrollHeight;
  }

  /* ── render operator chat message ────────────────────────────────────────── */
  function _render(msg) {
    const msgs = _msgs();
    if (!msgs) return;

    if (msg.event) {
      _renderEvent(msg.event, msg.text || msg.event);
      return;
    }

    const isMe    = msg.username === _me;
    const initial = (msg.username || '?')[0].toUpperCase();
    const hue     = _hue(msg.username || '?');

    const div = document.createElement('div');
    div.className = `cmsg${isMe ? ' me' : ''}`;
    div.innerHTML = `
      <div class="mh">
        <div class="mav" style="background:hsl(${hue},55%,28%);color:hsl(${hue},30%,80%)">${escHtml(initial)}</div>
        <span class="msdr">${escHtml(msg.username)}</span>
        <span class="mts">${fmtTs(msg.ts)}</span>
      </div>
      <div class="mbody">${escHtml(msg.text || msg.message || '')}</div>`;
    msgs.appendChild(div);
    msgs.scrollTop = msgs.scrollHeight;
  }

  /* ── date selector ───────────────────────────────────────────────────────── */
  function _dateDivider(dateStr) {
    const div = document.createElement('div');
    div.className = 'ev';
    div.innerHTML = `<span class="et i">📅 ${escHtml(dateStr)}</span>`;
    return div;
  }

  async function _loadDateSelector() {
    const sel = document.getElementById('chat-date-sel');
    if (!sel) return;
    try {
      const dates = await API.chatDates();
      const today = _today();
      sel.innerHTML = '<option value="">📅 Today</option><option value="__all__">📅 View All</option>';
      [...dates].reverse().forEach(d => {
        if (d === today) return;
        const opt = document.createElement('option');
        opt.value = d;
        opt.textContent = d;
        sel.appendChild(opt);
      });
    } catch {}
  }

  async function _selectDate(d) {
    const msgs = _msgs();
    if (!msgs) return;
    _viewingDate = d || null;
    msgs.innerHTML = '';

    if (!d) {
      await loadHistory();
      return;
    }

    if (d === '__all__') {
      try {
        const today = _today();
        const fetched = await API.chatDates();
        // Ensure today is always included
        const dates = [...new Set([...fetched, today])].sort();
        if (!dates.length) { _renderEvent('i', 'No chat history found'); return; }
        for (const date of dates) {
          msgs.appendChild(_dateDivider(date));
          const data = await API.chatHistory(date).catch(() => []);
          (data || []).forEach(_render);
        }
        msgs.scrollTop = msgs.scrollHeight;
      } catch {
        _renderEvent('w', 'Failed to load full history');
      }
      // Stay live — new messages keep arriving via WS
      _viewingDate = '__all__';
      return;
    }

    msgs.appendChild(_dateDivider(d));
    try {
      const data = await API.chatHistory(d);
      if (!data || !data.length) { _renderEvent('i', 'No messages on this date'); return; }
      data.forEach(_render);
    } catch {
      _renderEvent('w', 'Failed to load archive');
    }
  }

  /* ── emoji picker ────────────────────────────────────────────────────────── */
  function _initEmojiPicker() {
    const btn = document.getElementById('btn-emoji');
    const bar = document.getElementById('chat-in-bar');
    const inp = _input();
    if (!btn || !bar || !inp) return;

    const wrap = document.createElement('div');
    wrap.className = 'emoji-picker hidden';

    const picker = document.createElement('emoji-picker');
    picker.setAttribute('data-source', '/assets/emoji-data.json');
    wrap.appendChild(picker);
    bar.appendChild(wrap);

    picker.addEventListener('emoji-click', e => {
      const em = e.detail.unicode;
      const s  = inp.selectionStart ?? inp.value.length;
      const f  = inp.selectionEnd   ?? s;
      inp.value = inp.value.slice(0, s) + em + inp.value.slice(f);
      inp.setSelectionRange(s + em.length, s + em.length);
      inp.focus();
      wrap.classList.add('hidden');
    });

    btn.addEventListener('click', e => {
      e.stopPropagation();
      wrap.classList.toggle('hidden');
    });

    document.addEventListener('click', e => {
      if (!wrap.contains(e.target) && e.target !== btn) {
        wrap.classList.add('hidden');
      }
    });
  }

  /* ── load history ────────────────────────────────────────────────────────── */
  async function loadHistory() {
    const msgs = _msgs();
    if (!msgs) return;
    try {
      const data = await API.chatHistory(); // today
      msgs.innerHTML = '';
      (data || []).forEach(_render);
    } catch {}
  }

  /* ── send ─────────────────────────────────────────────────────────────────── */
  async function send() {
    const inp = _input();
    if (!inp) return;
    const text = inp.value.trim();
    if (!text) return;
    inp.value = '';
    try {
      await API.sendChat(text);
    } catch(e) {
      Toast.error('Chat', e.message);
    }
  }

  /* ── update ops-row avatars ──────────────────────────────────────────────── */
  function updateOps(ops) {
    const row = document.getElementById('ops-row');
    if (!row) return;
    row.innerHTML = '';
    (ops || []).slice(0, 6).forEach(op => {
      const initial = (op.username || '?')[0].toUpperCase();
      const hue     = _hue(op.username || '?');
      const pip = document.createElement('div');
      pip.className = 'op-pip';
      pip.title = op.username;
      pip.style.cssText = `background:hsl(${hue},55%,28%);color:hsl(${hue},30%,75%)`;
      pip.textContent = initial;
      row.appendChild(pip);
    });
  }

  /* ── WS event handlers ───────────────────────────────────────────────────── */
  function onMessage(msg) {
    if (_viewingDate && _viewingDate !== '__all__') return;
    _render(msg);
    /* notify only if chat panel is not currently visible */
    if (msg.username && msg.username !== _me && !msg.event) {
      const chatPanel = document.getElementById('chat-panel');
      const chatOpen  = chatPanel && !chatPanel.classList.contains('hidden');
      if (!chatOpen) {
        Notif.trigger('chat_message', 'New Message', msg.username);
        Notif.markChatUnread();
      }
    }
  }

  function onOperatorEvent(type, username) {
    if (_viewingDate && _viewingDate !== '__all__') return;
    _renderEvent(type, `${escHtml(username)} ${type === 'connect' ? 'connected' : 'disconnected'}`);
  }

  function setMe(username) { _me = username; }

  /* ── init ─────────────────────────────────────────────────────────────────── */
  function init(username) {
    _me = username;

    const inp = _input();
    if (inp) {
      inp.addEventListener('keydown', e => {
        if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); send(); }
      });
    }

    const sendBtn = document.getElementById('btn-chat-send');
    if (sendBtn) sendBtn.addEventListener('click', send);

    const dateSel = document.getElementById('chat-date-sel');
    if (dateSel) {
      dateSel.addEventListener('change', e => _selectDate(e.target.value));
      _loadDateSelector();
    }

    _initEmojiPicker();
    loadHistory();
  }

  function clearMessages() {
    const msgs = _msgs();
    if (msgs) msgs.innerHTML = '';
  }

  function getCurrentDate() {
    return _viewingDate;
  }

  return { init, onMessage, onOperatorEvent, updateOps, setMe, loadHistory, clearMessages, getCurrentDate };
})();
