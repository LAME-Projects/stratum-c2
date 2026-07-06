/* ─────────────────────────────────────────────────────────────────────────────
   ws.js — WebSocket client with exponential backoff reconnect
   Dispatches typed events to registered handlers.
   Envelope: { type: "namespace.event", ts: ISO, payload: {...} }
───────────────────────────────────────────────────────────────────────────── */

const WS = (() => {
  const BACKOFF_INIT  = 1000;
  const BACKOFF_MAX   = 30000;

  let _ws        = null;
  let _handlers  = {};       // type → [fn, ...]
  let _backoff   = BACKOFF_INIT;
  let _reconnTimer = null;
  let _active    = false;    // false = deliberately closed, no reconnect

  function _wsUrl() {
    const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
    return `${proto}//${location.host}/api/v1/ws`;
  }

  function _clearTimers() {
    if (_reconnTimer) { clearTimeout(_reconnTimer); _reconnTimer = null; }
  }

  function _scheduleReconnect() {
    _clearTimers();
    const delay = _backoff;
    _backoff = Math.min(_backoff * 2, BACKOFF_MAX);
    console.log(`[WS] reconnect in ${delay}ms`);
    _dispatch('ws.reconnecting', { delay });
    _reconnTimer = setTimeout(() => { if (_active) connect(); }, delay);
  }

  function _dispatch(type, payload) {
    const fns = _handlers[type] || [];
    const wildcard = _handlers['*'] || [];
    [...fns, ...wildcard].forEach(fn => {
      try { fn({ type, payload, ts: new Date().toISOString() }); } catch (e) { console.error('[WS] handler error', e); }
    });
  }

  function on(type, fn) {
    if (!_handlers[type]) _handlers[type] = [];
    _handlers[type].push(fn);
    return () => off(type, fn);
  }

  function off(type, fn) {
    if (!_handlers[type]) return;
    _handlers[type] = _handlers[type].filter(f => f !== fn);
  }

  function connect() {
    if (_ws && _ws.readyState < WebSocket.CLOSING) return;
    _active = true;

    try { _ws = new WebSocket(_wsUrl()); }
    catch (e) { _dispatch('ws.error', { message: e.message }); _scheduleReconnect(); return; }

    _ws.onopen = () => {
      console.log('[WS] connected — cookie auth on upgrade');
      _backoff = BACKOFF_INIT;
      // ws.connected is dispatched on server.hello (auth confirmed by cookie), not here
    };

    _ws.onmessage = (ev) => {
      let msg;
      try { msg = JSON.parse(ev.data); } catch { return; }
      /* respond to server keepalive pings */
      if (msg.type === 'ping') {
        if (_ws.readyState === WebSocket.OPEN)
          _ws.send(JSON.stringify({ type: 'pong' }));
        return;
      }
      if (msg.type === 'pong') return;
      // server.hello is the auth-confirmed signal — dispatch ws.connected here
      if (msg.type === 'server.hello') _dispatch('ws.connected', {});
      _dispatch(msg.type, msg.payload || {});
    };

    _ws.onclose = (ev) => {
      console.log(`[WS] closed code=${ev.code}`);
      _clearTimers();
      /* skip dispatch if we closed intentionally — disconnect() already dispatched */
      if (!_active) return;
      _dispatch('ws.disconnected', { code: ev.code, reason: ev.reason });
      /* 4001 = unauthorized, 4009 = already connected — don't retry */
      if (ev.code !== 4001 && ev.code !== 4009) _scheduleReconnect();
    };

    _ws.onerror = () => {
      _dispatch('ws.error', { message: 'WebSocket error' });
    };
  }

  function disconnect() {
    _active = false;
    _clearTimers();
    if (_ws) { _ws.close(1000); _ws = null; }
    _dispatch('ws.disconnected', { code: 1000, intentional: true });
  }

  function send(obj) {
    if (_ws && _ws.readyState === WebSocket.OPEN) {
      _ws.send(JSON.stringify(obj));
    }
  }

  function isConnected() {
    return _ws && _ws.readyState === WebSocket.OPEN;
  }

  return { connect, disconnect, on, off, send, isConnected };
})();
