/* ─────────────────────────────────────────────────────────────────────────────
   chat-history.js — Chat history browser
   Two-level modal: date list → messages detail view
───────────────────────────────────────────────────────────────────────────── */

const ChatHistory = (() => {
  function _fmtTs(iso) {
    if (!iso) return '—';
    const d = new Date(typeof iso === 'number' ? iso * 1000 : iso);
    return isNaN(d) ? iso : d.toLocaleTimeString([], {hour:'2-digit', minute:'2-digit', second:'2-digit'});
  }

  function _showListView() {
    document.getElementById('chat-list-view').style.display = 'flex';
    document.getElementById('chat-detail-view').style.display = 'none';
    document.getElementById('chat-back').style.display = 'none';
    _loadList();
  }

  function _showDetailView(date) {
    document.getElementById('chat-list-view').style.display = 'none';
    document.getElementById('chat-detail-view').style.display = 'flex';
    document.getElementById('chat-back').style.display = '';
    document.getElementById('chat-detail-title').textContent = date;
    _loadDetail(date);
  }

  function _fmtSize(bytes) {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
  }

  function _fmtLastActivity(iso) {
    if (!iso) return '—';
    const d = new Date(typeof iso === 'number' ? iso * 1000 : iso);
    if (isNaN(d)) return iso;
    return d.toLocaleString([], {year:'numeric', month:'2-digit', day:'2-digit', hour:'2-digit', minute:'2-digit'});
  }

  function _loadList() {
    const listView = document.getElementById('chat-list-view');
    if (!listView) return;

    const tbody = document.getElementById('chat-dates-tbody');
    if (tbody) {
      tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;padding:1.4rem;color:var(--text-muted);font-size:.82rem">Loading…</td></tr>';
    }

    API.listChatHistoryDatesWithInfo().then(datesInfo => {
      if (!datesInfo || !datesInfo.length) {
        listView.innerHTML = '<div style="display:flex;align-items:center;justify-content:center;flex:1;min-height:300px;color:var(--text-muted);font-size:.95rem">No chat history</div>';
        return;
      }
      listView.innerHTML = '<div class="arch-table-wrap"><table class="arch-table"><thead><tr><th>Date</th><th style="text-align:right">Messages</th><th>Last Activity</th><th style="text-align:right">Size</th><th></th></tr></thead><tbody id="chat-dates-tbody"></tbody></table></div>';
      const newTbody = document.getElementById('chat-dates-tbody');
      datesInfo.forEach(entry => {
        const tr = document.createElement('tr');
        tr.className = 'clickable';
        tr.style.cursor = 'pointer';
        const d = entry.date;

        tr.innerHTML = `
          <td style="font-family:var(--mono);font-weight:600;color:var(--text)">${escHtml(d)}</td>
          <td style="text-align:right;color:var(--text-dim);font-size:.78rem">${entry.message_count} msg${entry.message_count !== 1 ? 's' : ''}</td>
          <td style="color:var(--text-dim);font-size:.78rem">${_fmtLastActivity(entry.last_activity)}</td>
          <td style="text-align:right;color:var(--text-dim);font-size:.78rem">${_fmtSize(entry.size_bytes)}</td>
          <td style="text-align:right;padding-right:.6rem;white-space:nowrap">
            <button class="arch-dl-btn" data-date="${escHtml(d)}" title="Download">⬇</button>
            <button class="arch-del-btn" data-date="${escHtml(d)}" title="Delete">✕</button>
          </td>`;

        tr.addEventListener('click', () => _showDetailView(d));

        const dlBtn = tr.querySelector('.arch-dl-btn');
        dlBtn.addEventListener('click', e => {
          e.stopPropagation();
          API.exportChatDate(d).then(() => {
            Toast.success('Downloaded', `chat_${d}.jsonl`);
          }).catch(err => Toast.error('Error', err.message));
        });

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
          API.deleteChatDate(d)
            .then(() => {
              Toast.info('Chat Deleted', `Log for ${d} removed`);
              tr.remove();
              if (!newTbody.querySelector('tr')) {
                listView.innerHTML = '<div style="display:flex;align-items:center;justify-content:center;flex:1;min-height:300px;color:var(--text-muted);font-size:.95rem">No chat history</div>';
              }
            })
            .catch(err => {
              Toast.error('Error', err.message);
              delBtn.disabled = false;
              delBtn.textContent = '✕';
            });
        });
        newTbody.appendChild(tr);
      });
    }).catch(err => {
      listView.innerHTML = `<div style="display:flex;align-items:center;justify-content:center;height:100%;color:var(--accent);font-size:.95rem">Error: ${escHtml(err.message)}</div>`;
    });
  }

  function _loadDetail(date) {
    const msgsList = document.getElementById('chat-msgs-list');
    const countEl = document.getElementById('chat-detail-count');
    if (!msgsList) return;

    msgsList.innerHTML = '<div style="color:var(--text-muted);font-size:.82rem">Loading…</div>';
    countEl.textContent = '';

    API.getChatForDate(date).then(msgs => {
      if (!msgs || !msgs.length) {
        msgsList.innerHTML = '<div style="display:flex;align-items:center;justify-content:center;flex:1;color:var(--text-muted);font-size:.85rem">No messages on this date</div>';
        countEl.textContent = '0 messages';
        return;
      }

      countEl.textContent = `${msgs.length} message${msgs.length !== 1 ? 's' : ''}`;
      msgsList.innerHTML = '';

      msgs.forEach(msg => {
        const msgEl = document.createElement('div');
        msgEl.style.cssText = `
          background: var(--panel);
          border: 1px solid var(--border);
          border-radius: 5px;
          padding: .6rem .8rem;
          display: flex;
          flex-direction: column;
          gap: .3rem;
          font-size: .78rem;
        `;

        const header = document.createElement('div');
        header.style.cssText = `
          display: flex;
          gap: .8rem;
          align-items: center;
          margin-bottom: .25rem;
          border-bottom: 1px solid var(--border);
          padding-bottom: .4rem;
        `;

        const username = document.createElement('span');
        username.style.cssText = `
          font-weight: 600;
          color: var(--accent);
          min-width: 80px;
        `;
        username.textContent = msg.username || '—';

        const ts = document.createElement('span');
        ts.style.cssText = `
          color: var(--text-muted);
          font-size: .7rem;
          font-family: var(--mono);
          margin-left: auto;
        `;
        ts.textContent = _fmtTs(msg.ts);

        header.appendChild(username);
        header.appendChild(ts);

        const text = document.createElement('div');
        text.style.cssText = `
          color: var(--text);
          word-break: break-word;
          white-space: pre-wrap;
        `;
        text.textContent = msg.text;

        msgEl.appendChild(header);
        msgEl.appendChild(text);
        msgsList.appendChild(msgEl);
      });
    }).catch(err => {
      msgsList.innerHTML = `<div style="color:var(--accent)">Error: ${escHtml(err.message)}</div>`;
    });
  }

  return {
    open() {
      Modal.open('chat-history-modal');
      _showListView();

      document.getElementById('chat-back').addEventListener('click', _showListView);
      document.getElementById('chat-refresh').addEventListener('click', _loadList);
    },
    reloadList() {
      _loadList();
    }
  };
})();
