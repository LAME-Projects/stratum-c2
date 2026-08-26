/* ─────────────────────────────────────────────────────────────────────────────
   tradecraft.js — Deployment package browser modal
   Lists all deployment packages from  deployments/  grouped by provider.
   Each package can be downloaded as a ZIP or deleted.
───────────────────────────────────────────────────────────────────────────── */

const Tradecraft = (() => {

  let _deployments = [];

  const _PROV_NAMES = {
    dropbox:     'Dropbox',
    onedrive:    'OneDrive',
    googledrive: 'Google Drive',
    s3:          'AWS S3',
    sharepoint:  'SharePoint',
  };

  const _MODE_META = {
    'staged-enc':      { label: 'Staged Enc',      cls: 'badge-staged' },
    'stageless-enc':   { label: 'Stageless Enc',   cls: 'badge-bk'     },
    'stageless-plain': { label: 'Stageless Plain',  cls: 'badge-plain'  },
    'p2p listener':    { label: 'P2P Listener',     cls: 'badge-p2p'    },
  };

  function _fmtDate(iso) {
    if (!iso) return '—';
    try {
      const d = new Date(iso.includes('T') ? iso : iso.replace(' ', 'T'));
      return d.toLocaleDateString('en-GB', {
        day: 'numeric', month: 'short', year: 'numeric',
        hour: '2-digit', minute: '2-digit',
      });
    } catch { return iso; }
  }

  /* ── data loading ─────────────────────────────────────────────────────────── */
  async function _load() {
    const body = document.getElementById('tc-body');
    if (!body) return;
    body.innerHTML = '<p class="text-dim tc-empty">Loading…</p>';
    try {
      const r = await API.tradecraftList();
      _deployments = r.deployments || [];
      _render();
    } catch (e) {
      body.innerHTML = `<p class="text-dim tc-empty">Failed to load: ${escHtml(e.message || String(e))}</p>`;
    }
  }

  /* ── rendering ────────────────────────────────────────────────────────────── */
  function _render() {
    const body = document.getElementById('tc-body');
    if (!body) return;
    body.innerHTML = '';

    if (!_deployments.length) {
      body.innerHTML = '<p class="text-dim tc-empty">No deployment packages found.</p>';
      return;
    }

    /* Group by provider, preserving newest-first order within each group */
    const order  = [];
    const groups = {};
    _deployments.forEach(d => {
      const pid = d.provider || 'unknown';
      if (!groups[pid]) { groups[pid] = []; order.push(pid); }
      groups[pid].push(d);
    });

    order.forEach(pid => {
      const items = groups[pid];
      const pname = _PROV_NAMES[pid] || items[0]?.provider_label || pid;

      const sec = document.createElement('div');
      sec.className = 'tc-section';

      /* Section header with provider icon */
      const hdr = document.createElement('div');
      hdr.className = 'tc-section-hdr';
      const iconEl = providerIcon(pid, 'tc-prov-icon');
      if (iconEl) hdr.appendChild(iconEl);
      hdr.insertAdjacentHTML('beforeend',
        `<span class="tc-prov-name">${escHtml(pname)}</span>
         <span class="tc-prov-count">${items.length} package${items.length !== 1 ? 's' : ''}</span>`);
      sec.appendChild(hdr);

      items.forEach(dep => sec.appendChild(_buildRow(dep)));
      body.appendChild(sec);
    });
  }

  function _buildRow(dep) {
    const row  = document.createElement('div');
    row.className = 'tc-row';
    row.dataset.name = dep.name;

    const mode        = _MODE_META[dep.mode] || _MODE_META[(dep.mode || '').toLowerCase()] || { label: dep.mode || '—', cls: 'badge-plain' };
    const date        = _fmtDate(dep.generated || dep.created_at);
    const folderName  = (dep.folder || '').replace(/^\/+/, '');
    const label       = dep.label || folderName || dep.name;
    const sid         = dep.session_id || '';

    row.innerHTML = `
      <div class="tc-meta">
        <span class="tc-name">${escHtml(label)}</span>
        ${sid ? `<span class="tc-sid" title="Session ID">${escHtml(sid)}</span>` : ''}
        <span class="tc-badge ${escHtml(mode.cls)}">${escHtml(mode.label)}</span>
        <span class="tc-meta-item">📅 ${escHtml(date)}</span>
        <span class="tc-meta-item">📦 ${escHtml(dep.total_size_str || '—')}</span>
        ${dep.sleep ? `<span class="tc-meta-item">⏱ ${escHtml(dep.sleep)}</span>` : ''}
      </div>
      <div class="tc-actions">
        <button class="tc-btn-dl" title="Download ZIP">↓ Download</button>
        <button class="tc-btn-del" title="Delete">✕</button>
      </div>`;

    /* Download — fetch with auth header, then trigger via blob URL */
    const dlBtn = row.querySelector('.tc-btn-dl');
    dlBtn.addEventListener('click', async () => {
      dlBtn.disabled = true;
      dlBtn.textContent = '↓ …';
      try {
        const res = await fetch(
          `/api/v1/tradecraft/${encodeURIComponent(dep.name)}/zip`,
          { credentials: 'same-origin' }
        );
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const blob = await res.blob();
        const url  = URL.createObjectURL(blob);
        const a    = Object.assign(document.createElement('a'), { href: url, download: dep.name + '.zip' });
        document.body.appendChild(a);
        a.click();
        a.remove();
        URL.revokeObjectURL(url);
      } catch (e) {
        Toast.error('Download failed', e.message || String(e));
      } finally {
        dlBtn.disabled = false;
        dlBtn.textContent = '↓ Download';
      }
    });

    /* Delete — two-click confirm */
    const delBtn = row.querySelector('.tc-btn-del');
    delBtn.addEventListener('click', async () => {
      if (delBtn.dataset.confirm !== '1') {
        delBtn.dataset.confirm = '1';
        delBtn.textContent = '?';
        delBtn.title = 'Click again to confirm';
        delBtn.classList.add('tc-btn-del-confirm');
        setTimeout(() => {
          delBtn.dataset.confirm = '';
          delBtn.textContent = '✕';
          delBtn.title = 'Delete';
          delBtn.classList.remove('tc-btn-del-confirm');
        }, 3000);
        return;
      }
      delBtn.disabled = true;
      try {
        await API.tradecraftDelete(dep.name);
        Toast.info('Deleted', `${dep.name} removed`);
        _deployments = _deployments.filter(d => d.name !== dep.name);
        _render();
      } catch (e) {
        Toast.error('Delete failed', e.message || String(e));
        delBtn.disabled = false;
      }
    });

    return row;
  }

  /* ── public ───────────────────────────────────────────────────────────────── */
  function open() {
    _load();
    Modal.open('tradecraft-modal');
  }

  function reload() {
    _load();
  }

  function init() {
    document.getElementById('btn-tradecraft')?.addEventListener('click', open);
    document.getElementById('tc-close')?.addEventListener('click', () => Modal.close('tradecraft-modal'));
    document.getElementById('tc-refresh')?.addEventListener('click', _load);
  }

  return { init, open, reload };
})();
