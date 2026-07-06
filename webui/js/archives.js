/* ─────────────────────────────────────────────────────────────────────────────
   archives.js — History Archives browser
   Two-level modal: file list → history table → cmd-detail-modal (shared)
───────────────────────────────────────────────────────────────────────────── */

const Archives = (() => {
  function _fmtBytes(n) {
    if (n < 1024) return `${n} B`;
    if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
    return `${(n / 1024 / 1024).toFixed(2)} MB`;
  }

  function _fmtTs(iso) {
    if (!iso) return '—';
    const d = new Date(typeof iso === 'number' ? iso * 1000 : iso);
    return isNaN(d) ? iso : d.toLocaleString();
  }

  function _sessionIdFromFilename(name) {
    // Pattern: {label}_{6hex}.csv
    const m = name.match(/_([0-9a-f]{6,})\.csv$/i);
    return m ? m[1] : '—';
  }

  /* ── List view ───────────────────────────────────────────────────────────── */
  function _showListView() {
    document.getElementById('arch-list-view').style.display = 'flex';
    document.getElementById('arch-hist-view').style.display = 'none';
    document.getElementById('arch-back').style.display = 'none';
    document.getElementById('arch-title').textContent = '📂 History Archives';
  }

  function _switchArchTab(name) {
    document.querySelectorAll('.arch-tab').forEach(t => t.classList.toggle('on', t.dataset.archTab === name));
    document.querySelectorAll('.arch-tab-pane').forEach(p => p.classList.toggle('on', p.id === `arch-pane-${name}`));
  }

  function _showHistView(filename) {
    document.getElementById('arch-list-view').style.display = 'none';
    document.getElementById('arch-hist-view').style.display = 'flex';
    document.getElementById('arch-back').style.display = '';
    document.getElementById('arch-title').textContent = filename.replace(/\.csv$/i, '');
    _switchArchTab('commands');
    _loadHistView(filename);
    _loadArtifactsView(filename);
  }

  function _loadList() {
    const tbody  = document.getElementById('arch-tbody');
    const search = document.getElementById('arch-search');
    if (!tbody) return;

    tbody.innerHTML = '<tr><td colspan="5" class="arch-empty">Loading…</td></tr>';
    if (search) { search.value = ''; search.oninput = null; }

    API.listArchives().then(files => {
      if (!files || !files.length) {
        tbody.innerHTML = '<tr><td colspan="5" class="arch-empty">No archived history files found.</td></tr>';
        return;
      }
      tbody.innerHTML = '';
      files.forEach(f => {
        const tr = document.createElement('tr');
        tr.className = 'clickable';
        tr.dataset.filename = f.filename;
        const xlsxName = f.filename.replace(/\.csv$/i, '.xlsx');
        const dlUrl = `/api/v1/history/archives/${encodeURIComponent(f.filename)}/xlsx`;
        tr.innerHTML = `
          <td class="arch-filename">${escHtml(xlsxName)}</td>
          <td class="ts">${escHtml(_sessionIdFromFilename(f.filename))}</td>
          <td class="ts">${escHtml(_fmtBytes(f.size_bytes))}</td>
          <td class="ts">${escHtml(_fmtTs(f.modified_at))}</td>
          <td style="text-align:right;padding-right:.6rem;white-space:nowrap">
            <a class="arch-dl-btn" href="${escHtml(dlUrl)}" download="${escHtml(xlsxName)}" title="Download XLSX">⬇</a>
            <button class="arch-del-btn" title="Delete archive">✕</button>
          </td>`;
        tr.addEventListener('click', () => _showHistView(f.filename));
        tr.querySelector('.arch-dl-btn').addEventListener('click', e => e.stopPropagation());

        const delBtn = tr.querySelector('.arch-del-btn');
        let _delTimer = null;
        delBtn.addEventListener('click', e => {
          e.stopPropagation();
          if (!delBtn.classList.contains('confirm')) {
            delBtn.classList.add('confirm');
            delBtn.textContent = 'Delete?';
            _delTimer = setTimeout(() => {
              delBtn.classList.remove('confirm');
              delBtn.textContent = '✕';
            }, 3000);
            return;
          }
          clearTimeout(_delTimer);
          delBtn.disabled = true;
          delBtn.textContent = '…';
          API.deleteArchive(f.filename)
            .then(() => {
              tr.remove();
              Toast.info('Deleted', `${f.filename} removed`);
              if (!tbody.querySelector('tr')) {
                tbody.innerHTML = '<tr><td colspan="5" class="arch-empty">No archived history files found.</td></tr>';
              }
            })
            .catch(err => {
              delBtn.disabled = false;
              delBtn.classList.remove('confirm');
              delBtn.textContent = '✕';
              Toast.error('Delete failed', err?.message || 'Unknown error');
            });
        });

        tbody.appendChild(tr);
      });

      if (search) {
        search.oninput = () => {
          const q = search.value.trim().toLowerCase();
          tbody.querySelectorAll('tr').forEach(tr => {
            tr.style.display = !q || tr.textContent.toLowerCase().includes(q) ? '' : 'none';
          });
        };
      }
    }).catch(() => {
      tbody.innerHTML = '<tr><td colspan="5" class="arch-empty">Failed to load archives.</td></tr>';
    });
  }

  /* ── History view ────────────────────────────────────────────────────────── */
  function _loadHistView(filename) {
    const tbody  = document.getElementById('arch-hist-tbody');
    const search = document.getElementById('arch-hist-search');
    if (!tbody) return;

    tbody.innerHTML = '<tr><td colspan="5" class="arch-empty">Loading…</td></tr>';
    if (search) { search.value = ''; search.oninput = null; }

    API.readArchive(filename).then(entries => {
      if (!entries || !entries.length) {
        tbody.innerHTML = '<tr><td colspan="5" class="arch-empty">No commands recorded in this file.</td></tr>';
        return;
      }
      tbody.innerHTML = '';
      [...entries].reverse().forEach(h => {
        const tr      = document.createElement('tr');
        tr.className  = 'clickable';
        const raw     = h.response || '';
        const preview = raw.length > 120 ? raw.slice(0, 120) + '…' : raw;
        tr.innerHTML  = `
          <td class="ts" style="white-space:nowrap">${escHtml(_fmtTs(h.timestamp))}</td>
          <td class="ts">${escHtml((h.cmd_id || '—').slice(0, 8))}</td>
          <td class="ts">${escHtml(h.operator || '—')}</td>
          <td class="hi"><code>${escHtml(h.command || '')}</code></td>
          <td class="ts" style="max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${escHtml(preview)}</td>`;
        tr.addEventListener('click', () => _showDetail(h));
        tbody.appendChild(tr);
      });

      if (search) {
        search.oninput = () => {
          const q = search.value.trim().toLowerCase();
          tbody.querySelectorAll('tr').forEach(tr => {
            tr.style.display = !q || tr.textContent.toLowerCase().includes(q) ? '' : 'none';
          });
        };
      }
    }).catch(() => {
      tbody.innerHTML = '<tr><td colspan="5" class="arch-empty">Failed to load history.</td></tr>';
    });
  }

  /* ── Artifacts / Uploads view ───────────────────────────────────────────── */
  function _fmtSize(n) {
    if (!n && n !== 0) return '—';
    if (n < 1024) return `${n} B`;
    if (n < 1048576) return `${(n / 1024).toFixed(1)} KB`;
    return `${(n / 1048576).toFixed(1)} MB`;
  }

  function _loadArtifactsView(filename) {
    const otbody = document.getElementById('arch-ontarget-tbody');
    const ulbody = document.getElementById('arch-uploads-tbody');
    if (!otbody || !ulbody) return;

    otbody.innerHTML = '<tr><td colspan="4" class="arch-empty">Loading…</td></tr>';
    ulbody.innerHTML = '<tr><td colspan="5" class="arch-empty">Loading…</td></tr>';

    API.archiveArtifacts(filename).then(data => {
      // On-target artifacts
      const arts = data.on_target || [];
      if (!arts.length) {
        otbody.innerHTML = '<tr><td colspan="4" class="arch-empty">No artifacts recorded</td></tr>';
      } else {
        otbody.innerHTML = '';
        arts.forEach(a => {
          const tr   = document.createElement('tr');
          const slug = (a.type || '').replace(/[^a-z0-9]/gi, '_').toLowerCase();
          const removed = a.status === 'removed';
          tr.innerHTML =
            `<td><span class="art-badge art-badge-${escHtml(slug)}">${escHtml(a.type)}</span></td>` +
            `<td class="hi"><code style="word-break:break-all;font-size:.75rem">${escHtml(a.path)}</code></td>` +
            `<td class="ts" style="white-space:nowrap">${escHtml(_fmtTs(a.recorded_at))}</td>` +
            `<td class="ts">${removed ? '<span class="ul-badge ul-badge-removed">✕ removed</span>' : '<span class="ul-badge ul-badge-live">● on target</span>'}</td>`;
          otbody.appendChild(tr);
        });
      }

      // Uploads
      const uploads = data.uploads || [];
      if (!uploads.length) {
        ulbody.innerHTML = '<tr><td colspan="5" class="arch-empty">No uploads confirmed for this session</td></tr>';
      } else {
        ulbody.innerHTML = '';
        uploads.forEach(u => {
          const tr = document.createElement('tr');
          const removed = u.status === 'removed';
          tr.innerHTML =
            `<td class="hi"><code>${escHtml(u.filename || '—')}</code></td>` +
            `<td class="ts">${_fmtSize(u.size)}</td>` +
            `<td class="ts" style="word-break:break-all"><code style="font-size:.75rem">${escHtml(u.remote_path || '—')}</code></td>` +
            `<td class="ts" style="white-space:nowrap">${escHtml(_fmtTs(u.timestamp))}</td>` +
            `<td class="ts">${removed ? '<span class="ul-badge ul-badge-removed">✕ removed</span>' : '<span class="ul-badge ul-badge-live">● on target</span>'}</td>`;
          ulbody.appendChild(tr);
        });
      }
    }).catch(() => {
      otbody.innerHTML = '<tr><td colspan="4" class="arch-empty">Failed to load artifacts</td></tr>';
      ulbody.innerHTML = '<tr><td colspan="5" class="arch-empty">Failed to load uploads</td></tr>';
    });
  }

  /* ── Command detail — reuse shared cmd-detail-modal ─────────────────────── */
  function _showDetail(h) {
    const meta = document.getElementById('cmd-detail-meta');
    const cmd  = document.getElementById('cmd-detail-cmd');
    const out  = document.getElementById('cmd-detail-out');
    if (!meta || !cmd || !out) return;

    meta.innerHTML = [
      h.timestamp ? `<span class="cmd-detail-kv"><span class="k">Time</span><span class="v">${escHtml(_fmtTs(h.timestamp))}</span></span>` : '',
      h.cmd_id    ? `<span class="cmd-detail-kv"><span class="k">ID</span><span class="v">${escHtml(h.cmd_id)}</span></span>` : '',
      h.operator  ? `<span class="cmd-detail-kv"><span class="k">Operator</span><span class="v">${escHtml(h.operator)}</span></span>` : '',
      h.session_id? `<span class="cmd-detail-kv"><span class="k">Session</span><span class="v">${escHtml(h.session_id)}</span></span>` : '',
    ].join('');
    cmd.textContent = h.command  || '';
    out.textContent = h.response || '(no output)';
    Modal.open('cmd-detail-modal');
  }

  /* ── Public ──────────────────────────────────────────────────────────────── */
  function open() {
    _showListView();
    _loadList();
    Modal.open('archives-modal');
  }

  function init() {
    document.querySelectorAll('.arch-tab').forEach(tab => {
      tab.addEventListener('click', () => _switchArchTab(tab.dataset.archTab));
    });

    document.getElementById('arch-back')?.addEventListener('click', () => {
      _showListView();
      _loadList();
    });
    document.getElementById('arch-refresh')?.addEventListener('click', () => {
      if (document.getElementById('arch-hist-view').style.display !== 'none') {
        _loadHistView(document.getElementById('arch-title').textContent);
      } else {
        _loadList();
      }
    });
  }

  function removeRow(filename) {
    const tbody = document.getElementById('arch-tbody');
    if (!tbody) return;
    const row = tbody.querySelector(`tr[data-filename="${CSS.escape(filename)}"]`);
    if (!row) return;
    row.remove();
    if (!tbody.querySelector('tr')) {
      tbody.innerHTML = '<tr><td colspan="5" class="arch-empty">No archived history files found.</td></tr>';
    }
  }

  return { init, open, removeRow };
})();
