/* ─────────────────────────────────────────────────────────────────────────────
   graph.js — P2P Network Topology Graph (SVG force-directed layout)
   Cobalt Strike-style: red icons for privileged, cloud badge on egress,
   protocol:port labels on edges, drag/zoom/pan, real-time WS updates.
───────────────────────────────────────────────────────────────────────────── */

const Graph = (() => {
  let _container = null;
  let _svg       = null;
  let _gZoom     = null;   // top-level <g> for zoom/pan transform
  let _gEdges    = null;
  let _gNodes    = null;
  let _tooltip   = null;
  let _nodes     = [];     // { id, hostname, ip, os, username, is_admin, is_egress, link_type, status, last_seen, x, y, vx, vy, fx, fy }
  let _edges     = [];     // { source, target, link_type, link_port, link_address, status }
  let _sim       = null;   // simulation timer
  let _active    = false;
  let _zoomState = { k: 1, x: 0, y: 0 };
  let _dragging  = null;
  let _dragOff   = { x: 0, y: 0 };
  let _didDrag   = false;

  const NODE_R   = 22;
  const CLOUD_ICON = '☁';  // ☁
  const _ARROW_TYPES = ['tcp', 'smb', 'cloud', 'default',
    'cloud-dropbox', 'cloud-s3', 'cloud-onedrive', 'cloud-googledrive', 'cloud-sharepoint'];

  /* ── init ────────────────────────────────────────────────────────────────── */
  function init() {
    _container = document.getElementById('graph-container');
    if (!_container) return;

    _svg = _svgEl('svg', { id: 'graph-svg' });
    _container.appendChild(_svg);

    _gZoom = _svgEl('g', { class: 'g-zoom' });
    _svg.appendChild(_gZoom);

    _gEdges = _svgEl('g', { class: 'g-edges' });
    _gZoom.appendChild(_gEdges);

    _gNodes = _svgEl('g', { class: 'g-nodes' });
    _gZoom.appendChild(_gNodes);

    // tooltip
    _tooltip = document.createElement('div');
    _tooltip.className = 'graph-tooltip';
    _tooltip.style.display = 'none';
    _container.appendChild(_tooltip);

    // defs for arrowheads + OS icons
    const defs = _svgEl('defs');
    _ARROW_TYPES.forEach(t => {
      const marker = _svgEl('marker', {
        id: `arrow-${t}`, markerWidth: '8', markerHeight: '6',
        refX: '8', refY: '3', orient: 'auto', markerUnits: 'strokeWidth',
      });
      const path = _svgEl('path', { d: 'M0,0 L8,3 L0,6', fill: _edgeColor(t) });
      marker.appendChild(path);
      defs.appendChild(marker);
    });

    // OS icon SVGs are in /assets/icons/os-{type}.svg
    _svg.insertBefore(defs, _gZoom);

    _initZoomPan();
    _initResize();

    // WS events
    WS.on('p2p.link_established',  () => _reload());
    WS.on('p2p.link_lost',         () => _reload());
    WS.on('topology_changed',      () => _reload());
    WS.on('session.new',           () => { if (_active) _reload(); });
    WS.on('session.removed',       () => { if (_active) _reload(); });
    let _softTimer = null;
    const _debouncedSoft = () => {
      if (!_active) return;
      if (_softTimer) clearTimeout(_softTimer);
      _softTimer = setTimeout(() => { _softTimer = null; _softUpdate(); }, 500);
    };
    WS.on('session.update',        _debouncedSoft);
    WS.on('session.heartbeat',     _debouncedSoft);
    WS.on('session.dead',          _debouncedSoft);
  }

  /* ── show / hide (called by app.js view toggle) ──────────────────────── */
  function show() {
    _active = true;
    if (_container) _container.style.display = '';
    _reload();
  }

  function hide() {
    _active = false;
    if (_container) _container.style.display = 'none';
    _stopSim();
  }

  /* ── data loading ───────────────────────────────────────────────────────── */
  async function _reload() {
    if (!_active) return;
    try {
      const data = await API.topology();
      _mergeData(data.nodes || [], data.edges || []);
      _render();
      _startSim();
      // toggle empty state
      const emptyEl = document.getElementById('graph-empty');
      const hasRealNodes = _nodes.some(n => !n._isCloud);
      if (emptyEl) emptyEl.style.display = hasRealNodes ? 'none' : '';
    } catch (e) {
      console.error('[Graph] topology fetch failed', e);
    }
  }

  function _mergeData(newNodes, newEdges) {
    const oldMap = {};
    _nodes.forEach(n => { oldMap[n.id] = n; });

    _nodes = newNodes.map(n => {
      const old = oldMap[n.guid];
      return {
        id: n.guid,
        label: n.label || '',
        hostname: n.hostname,
        ip: n.ip,
        os: n.os,
        username: n.username,
        is_admin: n.is_admin,
        is_egress: n.is_egress,
        link_type: n.link_type,
        status: n.status,
        last_seen: n.last_seen,
        provider: n.provider || '',
        folder_path: n.folder_path || '',
        input_file: n.input_file || '',
        output_file: n.output_file || '',
        heartbeat_file: n.heartbeat_file || '',
        x:  old ? old.x  : null,
        y:  old ? old.y  : null,
        vx: old ? old.vx : 0,
        vy: old ? old.vy : 0,
        fx: old ? old.fx : null,
        fy: old ? old.fy : null,
      };
    });

    _edges = newEdges.map(e => ({
      source: e.source,
      target: e.target,
      link_type: e.link_type || '',
      link_port: e.link_port,
      link_address: e.link_address || '',
      status: e.status || 'up',
    }));

    // add implicit cloud edges for egress nodes — one cloud node per provider
    const _providerGroups = {};
    _nodes.forEach(n => {
      if (n.is_egress) {
        const hasParent = _edges.some(e => e.target === n.id);
        if (!hasParent) {
          const prov = n.provider || 'cloud';
          const cloudId = `__cloud_${prov}__`;
          if (!_providerGroups[prov]) _providerGroups[prov] = [];
          _providerGroups[prov].push(n);
          const edgeType = prov !== 'cloud' ? `cloud-${prov}` : 'cloud';
          _edges.push({
            source: cloudId,
            target: n.id,
            link_type: edgeType,
            link_port: null,
            link_address: 'HTTPS',
            status: n.status === 'online' || n.status === 'alive' ? 'up' : 'down',
          });
        }
      }
    });

    // create one cloud node per provider
    Object.entries(_providerGroups).forEach(([prov, egressNodes]) => {
      const cloudId = `__cloud_${prov}__`;
      if (_nodes.find(n => n.id === cloudId)) return;
      const old = oldMap[cloudId];
      const channels = egressNodes.map(n => ({
        session: n.hostname || n.label || n.id.slice(0, 8),
        provider: n.provider,
        folder: n.folder_path,
        files: [n.input_file, n.output_file, n.heartbeat_file].filter(Boolean),
      }));
      _nodes.push({
        id: cloudId, hostname: _providerLabel(prov), ip: '', os: '', username: '',
        is_admin: false, is_egress: false, link_type: 'cloud', status: 'online',
        last_seen: null, _isCloud: true, _providers: [prov], _channels: channels,
        x: old ? old.x : null, y: old ? old.y : null,
        vx: 0, vy: 0,
        fx: old ? old.fx : null, fy: old ? old.fy : null,
      });
    });

    // assign initial positions for nodes without coords
    const w = _svg.clientWidth  || 800;
    const h = _svg.clientHeight || 600;
    const cx = w / 2, cy = h / 2;
    _nodes.forEach((n, i) => {
      if (n.x == null) {
        const angle = (2 * Math.PI * i) / _nodes.length;
        const r = Math.min(w, h) * 0.3;
        n.x = cx + r * Math.cos(angle);
        n.y = cy + r * Math.sin(angle);
      }
    });
  }

  async function _softUpdate() {
    if (!_active) return;
    try {
      const data = await API.topology();
      const nMap = {};
      (data.nodes || []).forEach(n => { nMap[n.guid] = n; });
      _nodes.forEach(n => {
        const fresh = nMap[n.id];
        if (fresh) {
          n.status   = fresh.status;
          n.label    = fresh.label || n.label;
          n.hostname = fresh.hostname;
          n.ip       = fresh.ip;
          n.username = fresh.username;
          n.is_admin = fresh.is_admin;
          n.os       = fresh.os;
        }
      });
      _edges.forEach(e => {
        if (e.link_type.startsWith('cloud')) {
          const tgt = _nodes.find(n => n.id === e.target);
          e.status = tgt && (tgt.status === 'online' || tgt.status === 'alive') ? 'up' : 'down';
        }
      });
      _updateVisuals();
    } catch {}
  }

  /* ── SVG rendering ──────────────────────────────────────────────────────── */
  function _render() {
    _gEdges.innerHTML = '';
    _gNodes.innerHTML = '';

    const nodeMap = {};
    _nodes.forEach(n => { nodeMap[n.id] = n; });

    // edges
    _edges.forEach(e => {
      const src = nodeMap[e.source];
      const tgt = nodeMap[e.target];
      if (!src || !tgt) return;

      const g = _svgEl('g', { class: 'edge', 'data-src': e.source, 'data-tgt': e.target });

      const et = e.link_type || 'default';
      const arrowId = _ARROW_TYPES.includes(et) ? et : (et.startsWith('cloud') ? 'cloud' : 'default');
      const line = _svgEl('line', {
        class: `edge-line edge-${et}`,
        'marker-end': `url(#arrow-${arrowId})`,
      });
      g.appendChild(line);

      // label
      const label = _edgeLabel(e);
      if (label) {
        const txt = _svgEl('text', { class: 'edge-label', 'text-anchor': 'middle' });
        txt.textContent = label;
        g.appendChild(txt);
      }

      _gEdges.appendChild(g);
    });

    // nodes
    _nodes.forEach(n => {
      const g = _svgEl('g', {
        class: 'node',
        'data-id': n.id,
        transform: `translate(${n.x},${n.y})`,
      });

      if (n._isCloud) {
        const cR = NODE_R + 4;
        const provCls = (n._providers && n._providers.length === 1) ? ` node-cloud-${n._providers[0]}` : '';
        const circle = _svgEl('circle', { r: cR, class: `node-bg node-cloud${provCls}` });
        g.appendChild(circle);

        const providers = n._providers || [];
        if (providers.length === 1) {
          const img = _svgEl('image', {
            href: `/assets/icons/${providers[0]}.svg`,
            x: -12, y: -12, width: 24, height: 24,
          });
          g.appendChild(img);
        } else if (providers.length > 1) {
          const step = 20;
          const startX = -((providers.length - 1) * step) / 2;
          providers.forEach((p, i) => {
            const img = _svgEl('image', {
              href: `/assets/icons/${p}.svg`,
              x: startX + i * step - 8, y: -8, width: 16, height: 16,
            });
            g.appendChild(img);
          });
        } else {
          const icon = _svgEl('text', { class: 'cloud-icon', 'text-anchor': 'middle', dy: '.38em' });
          icon.textContent = CLOUD_ICON;
          g.appendChild(icon);
        }

        const label = _svgEl('text', { class: 'node-label', 'text-anchor': 'middle', dy: cR + 14 });
        label.textContent = providers.length === 1
          ? _providerLabel(providers[0])
          : (providers.length > 1 ? providers.map(_providerLabel).join(' + ') : 'C2 Server');
        g.appendChild(label);
      } else {
        // session node — OS-specific computer icon (CS/Adaptix style)
        const statusCls = _statusClass(n.status);
        const adminCls  = n.is_admin ? ' node-admin' : '';
        const osKind = _osType(n.os);

        // Background circle (status ring)
        const circle = _svgEl('circle', { r: NODE_R, class: `node-bg ${statusCls}${adminCls}` });
        g.appendChild(circle);

        // OS icon from /assets/icons/os-{type}.svg
        const iconSize = 26;
        const iconFile = osKind === 'mac' ? 'os-apple' : `os-${osKind}`;
        const icon = _svgEl('image', {
          href: `/assets/icons/${iconFile}.svg`,
          x: -(iconSize / 2), y: -(iconSize / 2),
          width: iconSize, height: iconSize,
          class: `node-os-icon${adminCls}`,
        });
        g.appendChild(icon);

        // egress badge (cloud)
        if (n.is_egress) {
          const badge = _svgEl('text', {
            class: 'egress-badge', x: NODE_R - 4, y: -(NODE_R - 4),
            'text-anchor': 'middle',
          });
          badge.textContent = CLOUD_ICON;
          g.appendChild(badge);
        }

        // hostname label below
        const label = _svgEl('text', { class: 'node-label', 'text-anchor': 'middle', dy: NODE_R + 14 });
        label.textContent = n.hostname || n.label || n.ip || n.id.slice(0, 8);
        g.appendChild(label);

        // username label below hostname
        if (n.username) {
          const uLabel = _svgEl('text', {
            class: `node-user${adminCls}`, 'text-anchor': 'middle', dy: NODE_R + 26,
          });
          uLabel.textContent = n.username;
          g.appendChild(uLabel);
        }
      }

      // interaction
      g.addEventListener('mousedown', e => _onNodeMouseDown(e, n));
      g.addEventListener('click',     e => _onNodeClick(e, n));
      g.addEventListener('dblclick',  e => _onNodeDblClick(e, n));
      g.addEventListener('mouseover', e => _showTooltip(e, n));
      g.addEventListener('mouseout',  () => _hideTooltip());
      g.addEventListener('contextmenu', e => _onNodeContext(e, n));

      _gNodes.appendChild(g);
    });

    _updatePositions();
  }

  function _updateVisuals() {
    _gNodes.querySelectorAll('.node').forEach(g => {
      const id = g.getAttribute('data-id');
      const n  = _nodes.find(nd => nd.id === id);
      if (!n || n._isCloud) return;

      const adminCls = n.is_admin ? ' node-admin' : '';
      const circle = g.querySelector('.node-bg');
      if (circle) {
        circle.setAttribute('class', `node-bg ${_statusClass(n.status)}${adminCls}`);
      }
      const osIcon = g.querySelector('.node-os-icon');
      if (osIcon) {
        osIcon.setAttribute('class', `node-os-icon${adminCls}`);
      }
    });
  }

  function _updatePositions() {
    const nodeMap = {};
    _nodes.forEach(n => { nodeMap[n.id] = n; });

    _gNodes.querySelectorAll('.node').forEach(g => {
      const id = g.getAttribute('data-id');
      const n  = nodeMap[id];
      if (n) g.setAttribute('transform', `translate(${n.x},${n.y})`);
    });

    _gEdges.querySelectorAll('.edge').forEach(g => {
      const src = nodeMap[g.getAttribute('data-src')];
      const tgt = nodeMap[g.getAttribute('data-tgt')];
      if (!src || !tgt) return;

      const line = g.querySelector('line');
      if (line) {
        // shorten line to not overlap node circles
        const dx = tgt.x - src.x, dy = tgt.y - src.y;
        const dist = Math.sqrt(dx * dx + dy * dy) || 1;
        const srcR = src._isCloud ? NODE_R + 4 : NODE_R;
        const tgtR = tgt._isCloud ? NODE_R + 4 : NODE_R;
        const ux = dx / dist, uy = dy / dist;

        line.setAttribute('x1', src.x + ux * (srcR + 2));
        line.setAttribute('y1', src.y + uy * (srcR + 2));
        line.setAttribute('x2', tgt.x - ux * (tgtR + 10));
        line.setAttribute('y2', tgt.y - uy * (tgtR + 10));
      }

      const txt = g.querySelector('text');
      if (txt) {
        txt.setAttribute('x', (src.x + tgt.x) / 2);
        txt.setAttribute('y', (src.y + tgt.y) / 2 - 6);
      }
    });
  }

  /* ── force simulation ───────────────────────────────────────────────────── */
  let _alpha = 1.0;
  const ALPHA_DECAY  = 0.02;
  const ALPHA_MIN    = 0.001;
  const VELOCITY_DECAY = 0.4;
  const LINK_DIST = 180;
  const REPULSE   = -800;
  const CENTER_STRENGTH = 0.03;

  function _startSim() {
    _alpha = 1.0;
    _stopSim();
    _sim = setInterval(_tick, 16);
  }

  function _stopSim() {
    if (_sim) { clearInterval(_sim); _sim = null; }
  }

  function _tick() {
    if (_alpha < ALPHA_MIN) { _stopSim(); return; }

    const w = _svg.clientWidth  || 800;
    const h = _svg.clientHeight || 600;
    const cx = w / 2, cy = h / 2;

    const nodeMap = {};
    _nodes.forEach(n => { nodeMap[n.id] = n; });

    // repulsion (charge)
    for (let i = 0; i < _nodes.length; i++) {
      const a = _nodes[i];
      if (a.fx != null) continue;
      for (let j = i + 1; j < _nodes.length; j++) {
        const b = _nodes[j];
        let dx = b.x - a.x, dy = b.y - a.y;
        let d2 = dx * dx + dy * dy;
        if (d2 < 1) { dx = (Math.random() - 0.5) * 2; dy = (Math.random() - 0.5) * 2; d2 = dx * dx + dy * dy; }
        const d = Math.sqrt(d2);
        const f = (REPULSE * _alpha) / d2;
        const fx = (dx / d) * f, fy = (dy / d) * f;
        a.vx -= fx; a.vy -= fy;
        if (b.fx == null) { b.vx += fx; b.vy += fy; }
      }
    }

    // link attraction
    _edges.forEach(e => {
      const src = nodeMap[e.source], tgt = nodeMap[e.target];
      if (!src || !tgt) return;
      const dx = tgt.x - src.x, dy = tgt.y - src.y;
      const d = Math.sqrt(dx * dx + dy * dy) || 1;
      const f = (d - LINK_DIST) * 0.05 * _alpha;
      const fx = (dx / d) * f, fy = (dy / d) * f;
      if (src.fx == null) { src.vx += fx; src.vy += fy; }
      if (tgt.fx == null) { tgt.vx -= fx; tgt.vy -= fy; }
    });

    // centering
    _nodes.forEach(n => {
      if (n.fx != null) return;
      n.vx += (cx - n.x) * CENTER_STRENGTH * _alpha;
      n.vy += (cy - n.y) * CENTER_STRENGTH * _alpha;
    });

    // integrate
    _nodes.forEach(n => {
      if (n.fx != null) { n.x = n.fx; n.y = n.fy; n.vx = 0; n.vy = 0; return; }
      n.vx *= VELOCITY_DECAY;
      n.vy *= VELOCITY_DECAY;
      n.x += n.vx;
      n.y += n.vy;
    });

    _alpha -= ALPHA_DECAY * _alpha;
    _updatePositions();
  }

  /* ── zoom & pan ─────────────────────────────────────────────────────────── */
  function _initZoomPan() {
    let panning = false;
    let panStart = { x: 0, y: 0 };

    _svg.addEventListener('wheel', e => {
      e.preventDefault();
      const rect = _svg.getBoundingClientRect();
      const mx = e.clientX - rect.left;
      const my = e.clientY - rect.top;

      const raw = -e.deltaY * 0.002;
      const delta = Math.pow(2, raw);
      const newK = Math.max(0.1, Math.min(5, _zoomState.k * delta));
      const ratio = newK / _zoomState.k;

      _zoomState.x = mx - ratio * (mx - _zoomState.x);
      _zoomState.y = my - ratio * (my - _zoomState.y);
      _zoomState.k = newK;
      _applyZoom();
    }, { passive: false });

    _svg.addEventListener('mousedown', e => {
      if (_dragging) return;
      if (e.button !== 0) return;
      if (e.target === _svg || e.target === _gZoom || e.target.closest('.g-edges')) {
        panning = true;
        panStart.x = e.clientX - _zoomState.x;
        panStart.y = e.clientY - _zoomState.y;
        _svg.style.cursor = 'grabbing';
        e.preventDefault();
      }
    });

    const _onMouseMove = e => {
      if (_dragging) {
        e.preventDefault();
        const rect = _svg.getBoundingClientRect();
        const svgX = (e.clientX - rect.left - _zoomState.x) / _zoomState.k;
        const svgY = (e.clientY - rect.top  - _zoomState.y) / _zoomState.k;
        _dragging.fx = svgX - _dragOff.x;
        _dragging.fy = svgY - _dragOff.y;
        _dragging.x  = _dragging.fx;
        _dragging.y  = _dragging.fy;
        _didDrag = true;
        _updatePositions();
        return;
      }
      if (panning) {
        _zoomState.x = e.clientX - panStart.x;
        _zoomState.y = e.clientY - panStart.y;
        _applyZoom();
      }
    };

    const _onMouseUp = () => {
      if (_dragging) {
        _dragging = null;
        _svg.style.cursor = '';
      }
      if (panning) {
        panning = false;
        _svg.style.cursor = '';
      }
    };

    window.addEventListener('mousemove', _onMouseMove);
    window.addEventListener('mouseup', _onMouseUp);
    window.addEventListener('mouseleave', _onMouseUp);
  }

  function _applyZoom() {
    _gZoom.setAttribute('transform', `translate(${_zoomState.x},${_zoomState.y}) scale(${_zoomState.k})`);
  }

  function _initResize() {
    const ro = new ResizeObserver(() => {
      if (!_active) return;
      if (_svg) {
        _svg.setAttribute('width',  _container.clientWidth);
        _svg.setAttribute('height', _container.clientHeight);
      }
    });
    if (_container) ro.observe(_container);
  }

  /* ── interaction ────────────────────────────────────────────────────────── */
  function _onNodeMouseDown(e, n) {
    if (e.button !== 0) return;
    e.stopPropagation();
    e.preventDefault();
    _dragging = n;
    const rect = _svg.getBoundingClientRect();
    const svgX = (e.clientX - rect.left - _zoomState.x) / _zoomState.k;
    const svgY = (e.clientY - rect.top  - _zoomState.y) / _zoomState.k;
    _dragOff.x = svgX - n.x;
    _dragOff.y = svgY - n.y;
    n.fx = n.x;
    n.fy = n.y;
    _didDrag = false;
    _svg.style.cursor = 'grabbing';
  }

  function _onNodeClick(e, n) {
    e.stopPropagation();
    if (_didDrag) return;
    if (n._isCloud) {
      _showCloudDetail(e, n);
      return;
    }
    if (Sessions && Sessions.select) Sessions.select(n.id);
  }

  function _onNodeDblClick(e, n) {
    e.stopPropagation();
    if (n.fx != null) {
      n.fx = null;
      n.fy = null;
      _alpha = Math.max(_alpha, 0.3);
      if (!_sim) _startSim();
    }
  }

  function _onNodeContext(e, n) {
    if (n._isCloud) return;
    e.preventDefault();
    e.stopPropagation();
    // trigger context menu via ContextMenu if available
    if (typeof ContextMenu !== 'undefined' && ContextMenu.showForSession) {
      ContextMenu.showForSession(e.clientX, e.clientY, n.id);
    }
  }

  function _showTooltip(e, n) {
    if (!_tooltip) return;
    const lines = [];
    if (n._isCloud) {
      const providers = (n._providers || []).map(_providerLabel);
      lines.push('<b>C2 Server</b>');
      lines.push(providers.length ? providers.join(', ') : 'Cloud dead-drop channel');
      if (n._channels && n._channels.length) lines.push(`<span class="gt-hint">${n._channels.length} channel(s) — click for details</span>`);
    } else {
      if (n.hostname) lines.push(`<b>${escHtml(n.hostname)}</b>`);
      if (n.username) lines.push(`User: ${escHtml(n.username)}${n.is_admin ? ' <span class="gt-admin">[ADMIN]</span>' : ''}`);
      if (n.ip)       lines.push(`IP: ${escHtml(n.ip)}`);
      if (n.os)       lines.push(`OS: ${escHtml(n.os)}`);
      lines.push(`Status: ${n.status}`);
      lines.push(`ID: ${n.id.slice(0, 12)}`);
      if (n.is_egress) lines.push('Egress beacon');
      if (n.link_type && n.link_type !== 'cloud') lines.push(`Link: ${n.link_type.toUpperCase()}`);
    }
    _tooltip.innerHTML = lines.join('<br>');
    _tooltip.style.display = 'block';
    _posTooltip(e);
  }

  function _posTooltip(e) {
    if (!_tooltip || !_container) return;
    const cr = _container.getBoundingClientRect();
    let x = e.clientX - cr.left + 14;
    let y = e.clientY - cr.top  + 14;
    if (x + 200 > cr.width)  x = e.clientX - cr.left - 210;
    if (y + 100 > cr.height) y = e.clientY - cr.top  - 110;
    _tooltip.style.left = x + 'px';
    _tooltip.style.top  = y + 'px';
  }

  function _hideTooltip() {
    if (_tooltip) _tooltip.style.display = 'none';
  }

  /* ── cloud detail panel ─────────────────────────────────────────────────── */
  let _cloudPanel = null;

  function _showCloudDetail(e, n) {
    _hideCloudDetail();
    const channels = n._channels || [];
    if (!channels.length) return;

    _cloudPanel = document.createElement('div');
    _cloudPanel.className = 'graph-cloud-panel';

    let html = '<div class="gcp-header"><b>Cloud Channels</b><span class="gcp-close">&times;</span></div>';
    channels.forEach(ch => {
      const pLabel = _providerLabel(ch.provider);
      html += `<div class="gcp-channel">`;
      html += `<div class="gcp-provider">${ch.provider ? `<img src="/assets/icons/${escHtml(ch.provider)}.svg" class="gcp-icon"> ` : ''}${escHtml(pLabel)} &mdash; <span class="gcp-session">${escHtml(ch.session)}</span></div>`;
      html += `<div class="gcp-folder">Folder: <code>${escHtml(ch.folder || '—')}</code></div>`;
      if (ch.files.length) {
        html += '<div class="gcp-files">Files:';
        ch.files.forEach(f => { html += ` <code>${escHtml(f)}</code>`; });
        html += '</div>';
      }
      html += '</div>';
    });

    _cloudPanel.innerHTML = html;
    _container.appendChild(_cloudPanel);

    _cloudPanel.querySelector('.gcp-close').addEventListener('click', _hideCloudDetail);
    document.addEventListener('mousedown', _cloudPanelOutsideClick);
  }

  function _hideCloudDetail() {
    if (_cloudPanel) { _cloudPanel.remove(); _cloudPanel = null; }
    document.removeEventListener('mousedown', _cloudPanelOutsideClick);
  }

  function _cloudPanelOutsideClick(e) {
    if (_cloudPanel && !_cloudPanel.contains(e.target)) _hideCloudDetail();
  }

  /* ── helpers ─────────────────────────────────────────────────────────────── */
  function _svgEl(tag, attrs = {}) {
    const el = document.createElementNS('http://www.w3.org/2000/svg', tag);
    Object.entries(attrs).forEach(([k, v]) => el.setAttribute(k, v));
    return el;
  }

  function _osType(os) {
    if (!os) return 'unknown';
    const l = os.toLowerCase();
    if (l.includes('windows') || l.includes('win32') || l.includes('win64')) return 'windows';
    if (l.includes('linux') || l.includes('ubuntu') || l.includes('debian') ||
        l.includes('centos') || l.includes('fedora') || l.includes('kali') ||
        l.includes('rhel') || l.includes('arch') || l.includes('suse')) return 'linux';
    if (l.includes('darwin') || l.includes('macos') || l.includes('mac os') ||
        l.includes('osx')) return 'mac';
    return 'unknown';
  }

  function _statusClass(status) {
    if (status === 'online' || status === 'alive') return 'node-alive';
    if (status === 'idle')   return 'node-idle';
    if (status === 'dead' || status === 'offline') return 'node-dead';
    return 'node-unknown';
  }

  function _providerLabel(p) {
    return ({ dropbox: 'Dropbox', onedrive: 'OneDrive', googledrive: 'Google Drive', sharepoint: 'SharePoint', s3: 'AWS S3' })[p] || p || 'Cloud';
  }

  function _edgeColor(type) {
    if (type === 'tcp')   return '#3b82f6';
    if (type === 'smb')   return '#22c55e';
    if (type === 'cloud') return '#a855f7';
    if (type === 'cloud-dropbox')     return '#0061fe';
    if (type === 'cloud-s3')          return '#ff9900';
    if (type === 'cloud-onedrive')    return '#0078d4';
    if (type === 'cloud-googledrive') return '#34a853';
    if (type === 'cloud-sharepoint')  return '#038387';
    return '#6b7280';
  }

  function _edgeLabel(e) {
    if (e.link_type.startsWith('cloud')) return 'HTTPS:443';
    if (e.link_type === 'tcp')   return `TCP:${e.link_port || '?'}`;
    if (e.link_type === 'smb') {
      if (e.link_address) {
        const m = e.link_address.match(/\\\\[^\\]+\\pipe\\(.+)/i);
        return m ? `SMB:${m[1]}` : 'SMB:445';
      }
      return 'SMB:445';
    }
    return '';
  }

  /* ── public ─────────────────────────────────────────────────────────────── */
  return { init, show, hide };
})();
