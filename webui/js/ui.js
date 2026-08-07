/* ─────────────────────────────────────────────────────────────────────────────
   ui.js — DOM helpers, toast system, modal manager
───────────────────────────────────────────────────────────────────────────── */

/* ── DOM shortcuts ─────────────────────────────────────────────────────────── */
const $ = (sel, ctx = document) => ctx.querySelector(sel);
const $$ = (sel, ctx = document) => [...ctx.querySelectorAll(sel)];

function el(tag, attrs = {}, ...children) {
  const e = document.createElement(tag);
  Object.entries(attrs).forEach(([k, v]) => {
    if (k === 'class')     e.className = v;
    else if (k === 'text') e.textContent = v;
    else if (k === 'html') e.innerHTML = v;
    else e.setAttribute(k, v);
  });
  children.forEach(c => {
    if (c == null) return;
    e.append(typeof c === 'string' ? document.createTextNode(c) : c);
  });
  return e;
}

function setVisible(element, visible) {
  if (!element) return;
  if (visible) element.classList.remove('hidden');
  else element.classList.add('hidden');
}

function escHtml(s) {
  return String(s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

/* Operational timezone — set by Settings._startNavClock, read by fmtTs/fmtDateTime */
let _opTz = 'UTC';
function setOpTz(tz) { _opTz = tz || 'UTC'; }

function fmtTs(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  return d.toLocaleTimeString('en-GB', { hour12: false, timeZone: _opTz });
}

function fmtDateTime(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  const date = d.toLocaleDateString('en-GB', { day: '2-digit', month: '2-digit', year: 'numeric', timeZone: _opTz });
  const time = d.toLocaleTimeString('en-GB', { hour12: false, timeZone: _opTz });
  return `${date}  ${time}`;
}

function _tsToMs(ts) {
  if (!ts) return NaN;
  return /^\d+(\.\d+)?$/.test(String(ts)) ? parseFloat(ts) * 1000 : Date.parse(ts);
}

function _fmtDuration(secs) {
  if (secs < 60)                          return `${secs}s`;
  if (secs < 3600)                        return `${Math.floor(secs/60)}m ${secs%60}s`;
  if (secs < 86400)  { const h = Math.floor(secs/3600),   m = Math.floor((secs%3600)/60); return m ? `${h}h ${m}m` : `${h}h`; }
  if (secs < 2592000){ const d = Math.floor(secs/86400),  h = Math.floor((secs%86400)/3600); return h ? `${d}d ${h}h` : `${d}d`; }
  { const mo = Math.floor(secs/2592000), d = Math.floor((secs%2592000)/86400); return d ? `${mo}mo ${d}d` : `${mo}mo`; }
}

function fmtAge(ts) {
  if (!ts) return 'never';
  const ms   = _tsToMs(ts);
  const secs = Math.floor((Date.now() - ms) / 1000);
  if (isNaN(secs)) return 'never';
  if (secs < 0)    return 'just now';
  return _fmtDuration(secs) + ' ago';
}

function fmtUntil(futureMs) {
  if (!futureMs || isNaN(futureMs)) return '—';
  const secs = Math.floor((futureMs - Date.now()) / 1000);
  if (secs <= 0) return 'overdue';
  return 'in ' + _fmtDuration(secs);
}

/* ── Toast notifications ───────────────────────────────────────────────────── */
const Toast = (() => {
  let container = null;

  function _ensureContainer() {
    if (!container) {
      container = document.getElementById('toast-container');
      if (!container) {
        container = el('div', { id: 'toast-container' });
        document.body.appendChild(container);
      }
    }
  }

  function show(type, title, msg = '', duration = 4000) {
    _ensureContainer();
    const toast = el('div', { class: `toast ${type}` });
    toast.innerHTML = `
      <div class="toast-icon"></div>
      <div class="toast-body">
        <div class="toast-title">${escHtml(title)}</div>
        ${msg ? `<div class="toast-msg">${escHtml(msg)}</div>` : ''}
      </div>
      <button class="toast-close" title="Dismiss">×</button>`;
    container.appendChild(toast);

    const close = () => {
      toast.style.opacity = '0';
      toast.style.transform = 'translateX(20px)';
      toast.style.transition = 'opacity .2s, transform .2s';
      setTimeout(() => toast.remove(), 200);
    };

    toast.querySelector('.toast-close').addEventListener('click', close);
    if (duration > 0) setTimeout(close, duration);
    return close;
  }

  return {
    success: (t, m, d)  => show('success', t, m, d),
    error:   (t, m, d)  => show('error',   t, m, d),
    warning: (t, m, d)  => show('warning', t, m, d),
    info:    (t, m, d)  => show('info',    t, m, d),
  };
})();

/* ── Modal manager ─────────────────────────────────────────────────────────── */
const Modal = (() => {
  const _stack = [];

  function _overlay(id) { return document.getElementById(id); }

  function open(id, opts = {}) {
    const ov = _overlay(id);
    if (!ov) return;
    ov.classList.add('open');
    _stack.push(id);
    document.addEventListener('keydown', _onKey);
    if (!opts.nonDismissible) ov.addEventListener('click', _onOverlayClick);
  }

  function close(id) {
    const ov = _overlay(id || _stack[_stack.length - 1]);
    if (!ov) return;
    ov.classList.remove('open');
    const idx = _stack.indexOf(ov.id);
    if (idx !== -1) _stack.splice(idx, 1);
    if (!_stack.length) document.removeEventListener('keydown', _onKey);
    ov.removeEventListener('click', _onOverlayClick);
  }

  function closeAll() { [..._stack].forEach(id => close(id)); }

  function _onKey(e) {
    if (e.key === 'Escape' && _stack.length) close();
  }

  function _onOverlayClick(e) {
    if (e.target === e.currentTarget) close(e.currentTarget.id);
  }

  function isOpen(id) { return _stack.includes(id); }

  return { open, close, closeAll, isOpen };
})();

/* ── Confirmation dialog ───────────────────────────────────────────────────── */
function confirm(title, msg) {
  return new Promise(resolve => {
    const ov = document.getElementById('confirm-modal');
    if (!ov) { resolve(window.confirm(msg)); return; }
    $('#confirm-title', ov).textContent = title;
    $('#confirm-msg',   ov).innerText = msg;

    const yes = $('#confirm-yes', ov);
    const no  = $('#confirm-no',  ov);

    function done(val) {
      Modal.close('confirm-modal');
      yes.removeEventListener('click', onYes);
      no.removeEventListener('click',  onNo);
      resolve(val);
    }
    const onYes = () => done(true);
    const onNo  = () => done(false);
    yes.addEventListener('click', onYes);
    no.addEventListener('click',  onNo);
    Modal.open('confirm-modal');
  });
}

/* ── Typed confirmation dialog ─────────────────────────────────────────────── */
/* checkboxes: [{ id, label, defaultChecked }]
   resolves to { ok: bool, [id]: bool, ... } */
function confirmTyped(title, msg, phrase, checkboxes = []) {
  return new Promise(resolve => {
    const ov = document.getElementById('confirm-typed-modal');
    if (!ov) {
      const ok = window.prompt(`Type "${phrase}" to confirm`) === phrase;
      const res = { ok };
      checkboxes.forEach(c => { res[c.id] = c.defaultChecked ?? false; });
      resolve(res);
      return;
    }

    $('#ct-title',  ov).textContent = title;
    $('#ct-msg',    ov).textContent = msg;
    $('#ct-phrase', ov).textContent = phrase;

    // Render checkboxes
    const chkWrap = $('#ct-checkboxes', ov);
    chkWrap.innerHTML = checkboxes.map(c => `
      <label class="ct-chk-row">
        <input type="checkbox" id="ct-chk-${c.id}" ${c.defaultChecked ? 'checked' : ''}>
        <span>${c.label}</span>
      </label>`).join('');

    const input = $('#ct-input', ov);
    const yes   = $('#ct-yes',   ov);
    const no    = $('#ct-no',    ov);

    input.value = '';
    yes.disabled = true;

    function done(ok) {
      Modal.close('confirm-typed-modal');
      input.removeEventListener('input', onInput);
      document.removeEventListener('keydown', onKeydown);
      yes.removeEventListener('click', onYes);
      no.removeEventListener('click',  onNo);
      const res = { ok };
      checkboxes.forEach(c => {
        const el = document.getElementById(`ct-chk-${c.id}`);
        res[c.id] = el ? el.checked : (c.defaultChecked ?? false);
      });
      resolve(res);
    }
    function onInput() {
      const match = input.value === phrase;
      yes.disabled = !match;
      input.classList.toggle('ct-input-match', match);
    }
    const onKeydown = (e) => {
      if (e.key === 'Enter' && !yes.disabled) { e.preventDefault(); done(true); }
    };
    const onYes = () => { if (!yes.disabled) done(true); };
    const onNo  = () => done(false);

    input.addEventListener('input', onInput);
    document.addEventListener('keydown', onKeydown);
    yes.addEventListener('click', onYes);
    no.addEventListener('click',  onNo);

    Modal.open('confirm-typed-modal');
    setTimeout(() => input.focus(), 80);
  });
}

/* ── Provider icon helper ──────────────────────────────────────────────────── */
const PROVIDER_ICONS = {
  dropbox:     '/assets/icons/dropbox.svg',
  onedrive:    '/assets/icons/onedrive.svg',
  s3:          '/assets/icons/s3.svg',
  sharepoint:  '/assets/icons/sharepoint.svg',
  googledrive: '/assets/icons/googledrive.svg',
};

function providerIcon(name, cls = 'provider-icon') {
  const src = PROVIDER_ICONS[name] || '';
  if (!src) return el('span', { class: cls, text: name[0].toUpperCase() });
  const img = el('img', { class: cls, src, alt: name });
  return img;
}

/* ── Status helpers ────────────────────────────────────────────────────────── */
function agentStatus(state, agentSleep) {
  if (!state) return 'unknown';
  if (state.alive === false) return 'dead';
  const ms    = _tsToMs(state.last_heartbeat);
  const age   = isNaN(ms) ? Infinity : (Date.now() - ms) / 1000;
  const sleep = agentSleep || 30;
  if (age > sleep * 4) return 'dead';
  if (age > sleep * 2) return 'idle';
  return 'alive';
}

/* ── Show / switch view ────────────────────────────────────────────────────── */
function showView(id) {
  $$('.view').forEach(v => v.classList.remove('active'));
  const v = document.getElementById(id);
  if (v) v.classList.add('active');
}
