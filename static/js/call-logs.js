/**
 * Call Logs Module – Unified call history UI for doctors, patients, and admin.
 * Provides a modal-based interface with search, filters, statistics, details,
 * and browser notifications for missed calls.
 *
 * Public API:  CallLogs.init(cfg)
 *              CallLogs.refresh()
 *              CallLogs.showDetails(callId)
 */
;(function () {
  'use strict';

  /* ── state ─────────────────────────────────────────────── */
  const S = {
    calls: [],
    filtered: [],
    filter: 'all',        // all | incoming | outgoing | missed | declined
    callType: '',         // '' | voice | video
    search: '',
    page: 1,
    perPage: 25,
    total: 0,
    loading: false,
    stats: null,
    lastPoll: null,       // ISO string for missed-call polling
    cfg: {}               // userId, userRole, csrfToken
  };

  /* ── helpers ───────────────────────────────────────────── */
  function esc(s) {
    const m = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
    return String(s || '').replace(/[&<>"']/g, c => m[c]);
  }

  function fmtDuration(sec) {
    if (!sec || sec <= 0) return '—';
    const s = Math.floor(Math.max(0, sec));
    const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), ss = s % 60;
    if (h > 0) return `${h}h ${m}m ${ss}s`;
    if (m > 0) return `${m}m ${ss}s`;
    return `${ss}s`;
  }

  function timeAgo(iso) {
    try {
      const d = new Date(iso);
      if (isNaN(d)) return '—';
      const diff = Math.floor((Date.now() - d) / 1000);
      if (diff < 60) return diff + 's ago';
      if (diff < 3600) return Math.floor(diff / 60) + 'm ago';
      if (diff < 86400) return Math.floor(diff / 3600) + 'h ago';
      if (diff < 172800) return 'Yesterday';
      if (diff < 604800) return Math.floor(diff / 86400) + 'd ago';
      return d.toLocaleDateString();
    } catch (_) { return '—'; }
  }

  function fullDate(iso) {
    try { return new Date(iso).toLocaleString(); } catch (_) { return '—'; }
  }

  function statusBadge(status, endReason) {
    const s = (status || '').toLowerCase();
    const r = (endReason || '').toLowerCase();
    if (s === 'missed' || r === 'missed' || r === 'unanswered' || r === 'timeout')
      return '<span class="cl-badge cl-badge-danger">Missed</span>';
    if (s === 'declined' || s === 'rejected' || r === 'callee_declined' || r === 'declined')
      return '<span class="cl-badge cl-badge-warning">Declined</span>';
    if (r === 'busy')
      return '<span class="cl-badge cl-badge-warning">Busy</span>';
    if (s === 'ended' || s === 'connected' || r === 'user_hangup' || r === 'completed')
      return '<span class="cl-badge cl-badge-success">Completed</span>';
    if (r === 'connection_failed' || r === 'network_error' || r === 'failed_network')
      return '<span class="cl-badge cl-badge-danger">Failed</span>';
    if (s === 'ringing' || s === 'initiated')
      return '<span class="cl-badge cl-badge-info">No Answer</span>';
    return `<span class="cl-badge cl-badge-secondary">${esc(s || 'Unknown')}</span>`;
  }

  function directionIcon(dir) {
    if (dir === 'outgoing')
      return '<i class="fas fa-arrow-up text-primary" title="Outgoing"></i>';
    if (dir === 'incoming')
      return '<i class="fas fa-arrow-down text-success" title="Incoming"></i>';
    return '<i class="fas fa-minus text-muted"></i>';
  }

  function callTypeIcon(t) {
    return t === 'video'
      ? '<i class="fas fa-video text-info" title="Video call"></i>'
      : '<i class="fas fa-phone text-primary" title="Voice call"></i>';
  }

  function initials(name) {
    return (name || 'U').split(' ').map(p => p.charAt(0)).slice(0, 2).join('').toUpperCase();
  }

  /* ── API calls ─────────────────────────────────────────── */
  async function apiFetch(url) {
    const resp = await fetch(url, {
      headers: { 'Accept': 'application/json', 'X-CSRFToken': S.cfg.csrfToken || '' },
      credentials: 'same-origin'
    });
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    return resp.json();
  }

  async function fetchCallLogs(force) {
    if (S.loading) return;
    S.loading = true;
    _showLoading();
    try {
      let url = `/api/call-logs?page=${S.page}&per_page=${S.perPage}`;
      if (S.filter && S.filter !== 'all') url += `&filter=${S.filter}`;
      if (S.callType) url += `&call_type=${S.callType}`;

      const data = await apiFetch(url);
      if (!data.success) throw new Error(data.error || 'Server error');

      S.calls = data.call_logs || [];
      S.total = data.total || 0;
      _applySearch();
      _render();
      _updateSummary();
    } catch (err) {
      console.error('CallLogs fetch error:', err);
      _showError(err.message);
    } finally {
      S.loading = false;
    }
  }

  async function fetchStats() {
    try {
      const data = await apiFetch('/api/call-statistics?period=30d');
      if (data.success) {
        S.stats = data.statistics;
        _renderStats();
      }
    } catch (e) { console.warn('Stats load failed:', e); }
  }

  async function fetchCallDetail(callId) {
    try {
      const data = await apiFetch(`/api/call-logs/${callId}`);
      if (data.success && data.call) {
        _showDetailModal(data.call);
      }
    } catch (e) { console.error('Detail fetch error:', e); }
  }

  /* ── missed-call polling & notifications ────────────────── */
  function startMissedCallPolling() {
    if (!('Notification' in window)) return;
    S.lastPoll = new Date().toISOString();
    setInterval(async () => {
      try {
        const data = await apiFetch(`/api/missed-calls?since=${encodeURIComponent(S.lastPoll)}`);
        S.lastPoll = new Date().toISOString();
        if (!data.success || !data.missed_calls) return;
        data.missed_calls.forEach(c => {
          const tag = `missed-${c.id}`;
          if (sessionStorage.getItem(tag)) return;
          sessionStorage.setItem(tag, '1');
          _notify('Missed Call', `${c.remote_user_name || 'Unknown'} (${c.call_type})`, tag);
        });
      } catch (_) {}
    }, 30000);
  }

  function _notify(title, body, tag) {
    if (Notification.permission === 'granted') {
      new Notification(title, { body, tag, icon: '/static/img/favicon.png' });
    } else if (Notification.permission !== 'denied') {
      Notification.requestPermission().then(p => {
        if (p === 'granted') new Notification(title, { body, tag, icon: '/static/img/favicon.png' });
      });
    }
  }

  /* ── DOM helpers ────────────────────────────────────────── */
  function $(id) { return document.getElementById(id); }

  function _showLoading() {
    const el = $('clList');
    if (el) el.innerHTML = `
      <div class="cl-loading">
        <div class="spinner-border spinner-border-sm text-primary"></div>
        <span>Loading call logs...</span>
      </div>`;
  }

  function _showError(msg) {
    const el = $('clList');
    if (el) el.innerHTML = `
      <div class="cl-empty">
        <i class="fas fa-exclamation-triangle text-danger" style="font-size:24px"></i>
        <div class="mt-2">${esc(msg)}</div>
        <button class="btn btn-sm btn-primary mt-2" onclick="CallLogs.refresh()">Retry</button>
      </div>`;
  }

  function _updateSummary() {
    const el = $('clSummary');
    if (!el) return;
    if (S.total === 0) {
      el.textContent = 'No calls yet';
    } else {
      el.textContent = `${S.filtered.length} of ${S.total} calls`;
    }
  }

  /* ── search & filter ───────────────────────────────────── */
  function _applySearch() {
    const q = S.search.toLowerCase().trim();
    if (!q) { S.filtered = [...S.calls]; return; }
    S.filtered = S.calls.filter(c => {
      const haystack = [
        c.remote_user_name || '',
        c.caller_name || '',
        c.callee_name || '',
        c.call_type || '',
        c.status || ''
      ].join(' ').toLowerCase();
      return haystack.includes(q);
    });
  }

  /* ── grouping ──────────────────────────────────────────── */
  function _groupByDate(items) {
    const now = new Date(); now.setHours(0, 0, 0, 0);
    const groups = { 'Today': [], 'Yesterday': [], 'This Week': [], 'Earlier': [] };
    items.forEach(c => {
      const d = new Date(c.initiated_at || c.created_at);
      d.setHours(0, 0, 0, 0);
      const diff = Math.floor((now - d) / 86400000);
      if (diff === 0) groups['Today'].push(c);
      else if (diff === 1) groups['Yesterday'].push(c);
      else if (diff < 7) groups['This Week'].push(c);
      else groups['Earlier'].push(c);
    });
    return groups;
  }

  /* ── render call list ──────────────────────────────────── */
  function _render() {
    const el = $('clList');
    if (!el) return;

    if (!S.filtered.length) {
      el.innerHTML = `
        <div class="cl-empty">
          <i class="fas fa-phone-slash" style="font-size:32px;opacity:.3"></i>
          <div class="mt-2">No calls match your filters</div>
        </div>`;
      return;
    }

    const groups = _groupByDate(S.filtered);
    let html = '';

    for (const [label, items] of Object.entries(groups)) {
      if (!items.length) continue;
      html += `<div class="cl-group">
        <div class="cl-group-header">
          <span>${label}</span>
          <span class="cl-group-count">${items.length}</span>
        </div>`;
      items.forEach(c => {
        const ini = initials(c.remote_user_name);
        html += `
          <div class="cl-item" data-id="${c.id}">
            <div class="cl-avatar" title="${esc(c.remote_user_name)}">
              ${c.remote_user_avatar
                ? `<img src="${esc(c.remote_user_avatar)}" alt="${esc(c.remote_user_name)}"
                     onerror="this.parentElement.innerHTML='<span class=cl-initials>${ini}</span>'">`
                : `<span class="cl-initials">${ini}</span>`}
            </div>
            <div class="cl-info">
              <div class="cl-row-top">
                <span class="cl-name">${esc(c.remote_user_name || 'Unknown')}</span>
                ${statusBadge(c.status, c.end_reason)}
              </div>
              <div class="cl-row-bottom">
                <span class="cl-meta">
                  ${directionIcon(c.direction)}
                  ${callTypeIcon(c.call_type)}
                  <span class="cl-time">${timeAgo(c.initiated_at || c.created_at)}</span>
                  <span class="cl-dur">${fmtDuration(c.duration)}</span>
                </span>
                <span class="cl-actions">
                  <button class="cl-btn cl-btn-detail" data-id="${c.id}" title="Details">
                    <i class="fas fa-info-circle"></i>
                  </button>
                  <button class="cl-btn cl-btn-call" data-uid="${c.remote_user_id || ''}"
                          data-name="${esc(c.remote_user_name)}" title="Call back">
                    <i class="fas fa-phone"></i>
                  </button>
                </span>
              </div>
            </div>
          </div>`;
      });
      html += '</div>';
    }

    el.innerHTML = html;

    // Attach event listeners
    el.querySelectorAll('.cl-btn-detail').forEach(btn => {
      btn.addEventListener('click', e => {
        e.stopPropagation();
        fetchCallDetail(parseInt(btn.dataset.id, 10));
      });
    });
    el.querySelectorAll('.cl-btn-call').forEach(btn => {
      btn.addEventListener('click', e => {
        e.stopPropagation();
        _initiateCall(btn.dataset.uid, btn.dataset.name);
      });
    });
  }

  /* ── stats rendering ───────────────────────────────────── */
  function _renderStats() {
    const el = $('clStats');
    if (!el || !S.stats) return;
    const s = S.stats;
    el.innerHTML = `
      <div class="cl-stat"><span class="cl-stat-num">${s.total_calls}</span><span class="cl-stat-label">Total</span></div>
      <div class="cl-stat"><span class="cl-stat-num cl-stat-success">${s.completed_calls}</span><span class="cl-stat-label">Completed</span></div>
      <div class="cl-stat"><span class="cl-stat-num cl-stat-danger">${s.missed_calls}</span><span class="cl-stat-label">Missed</span></div>
      <div class="cl-stat"><span class="cl-stat-num">${fmtDuration(s.average_duration)}</span><span class="cl-stat-label">Avg Duration</span></div>
      <div class="cl-stat"><span class="cl-stat-num">${fmtDuration(s.total_talk_time)}</span><span class="cl-stat-label">Total Talk</span></div>`;
  }

  /* ── detail modal ──────────────────────────────────────── */
  function _showDetailModal(call) {
    let existing = $('clDetailModal');
    if (existing) existing.remove();

    const html = `
    <div class="modal fade" id="clDetailModal" tabindex="-1">
      <div class="modal-dialog modal-dialog-centered">
        <div class="modal-content">
          <div class="modal-header">
            <h6 class="modal-title">Call Details</h6>
            <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
          </div>
          <div class="modal-body">
            <div class="cl-detail-grid">
              <div class="cl-detail-row"><span class="cl-detail-label">Caller</span><span>${esc(call.caller_name || 'Unknown')}</span></div>
              <div class="cl-detail-row"><span class="cl-detail-label">Callee</span><span>${esc(call.callee_name || 'Unknown')}</span></div>
              <div class="cl-detail-row"><span class="cl-detail-label">Type</span><span>${callTypeIcon(call.call_type)} ${call.call_type === 'video' ? 'Video' : 'Voice'}</span></div>
              <div class="cl-detail-row"><span class="cl-detail-label">Direction</span><span>${directionIcon(call.direction)} ${esc(call.direction || '—')}</span></div>
              <div class="cl-detail-row"><span class="cl-detail-label">Status</span><span>${statusBadge(call.status, call.end_reason)}</span></div>
              <div class="cl-detail-row"><span class="cl-detail-label">Duration</span><span>${fmtDuration(call.duration)}</span></div>
              <div class="cl-detail-row"><span class="cl-detail-label">Started</span><span>${fullDate(call.initiated_at)}</span></div>
              <div class="cl-detail-row"><span class="cl-detail-label">Connected</span><span>${call.connected_at ? fullDate(call.connected_at) : '—'}</span></div>
              <div class="cl-detail-row"><span class="cl-detail-label">Ended</span><span>${call.ended_at ? fullDate(call.ended_at) : '—'}</span></div>
              ${call.end_reason ? `<div class="cl-detail-row"><span class="cl-detail-label">End Reason</span><span>${esc(call.end_reason)}</span></div>` : ''}
            </div>
            ${call.quality_metrics_detailed && call.quality_metrics_detailed.length ? `
            <h6 class="mt-3 mb-2" style="font-size:14px">Quality Metrics</h6>
            <div class="cl-quality-grid">
              ${call.quality_metrics_detailed.map(m => `
                <div class="cl-quality-item">
                  <span>RTT: ${m.rtt || '—'}ms</span>
                  <span>Loss: ${m.packet_loss || '—'}%</span>
                  <span>Jitter: ${m.jitter || '—'}ms</span>
                  <span>Audio: ${m.audio_quality || '—'}</span>
                  <span>Video: ${m.video_quality || '—'}</span>
                </div>
              `).join('')}
            </div>` : ''}
          </div>
        </div>
      </div>
    </div>`;

    document.body.insertAdjacentHTML('beforeend', html);
    const modal = new bootstrap.Modal($('clDetailModal'));
    $('clDetailModal').addEventListener('hidden.bs.modal', () => {
      $('clDetailModal').remove();
    });
    modal.show();
  }

  /* ── call-back ─────────────────────────────────────────── */
  function _initiateCall(userId, userName) {
    if (!userId) return;
    if (window.socket && window.socket.connected) {
      window.socket.emit('initiate_video_call', {
        caller_id: S.cfg.userId,
        callee_id: userId,
        appointment_id: null,
        caller_name: document.getElementById('currentUserName')?.textContent || 'User'
      });
      if (window.InpageToasts) {
        window.InpageToasts.show('Call', `Calling ${userName || 'user'}...`);
      }
    } else {
      alert('Not connected. Please refresh the page.');
    }
  }

  /* ── pagination ────────────────────────────────────────── */
  function _renderPagination() {
    const el = $('clPagination');
    if (!el) return;
    const pages = Math.ceil(S.total / S.perPage);
    if (pages <= 1) { el.innerHTML = ''; return; }

    let html = '';
    if (S.page > 1) html += `<button class="cl-page-btn" data-page="${S.page - 1}">‹</button>`;
    for (let i = 1; i <= pages; i++) {
      if (pages > 7 && i > 2 && i < pages - 1 && Math.abs(i - S.page) > 1) {
        if (i === 3 || i === pages - 2) html += '<span class="cl-page-dots">…</span>';
        continue;
      }
      html += `<button class="cl-page-btn${i === S.page ? ' active' : ''}" data-page="${i}">${i}</button>`;
    }
    if (S.page < pages) html += `<button class="cl-page-btn" data-page="${S.page + 1}">›</button>`;

    el.innerHTML = html;
    el.querySelectorAll('.cl-page-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        S.page = parseInt(btn.dataset.page, 10);
        fetchCallLogs();
      });
    });
  }

  /* ── init ──────────────────────────────────────────────── */
  function init(cfg) {
    S.cfg = cfg || {};

    const modal = $('callLogsModal');
    if (!modal) return;

    // Search
    const searchEl = $('clSearch');
    if (searchEl) {
      let t;
      searchEl.addEventListener('input', () => {
        clearTimeout(t);
        t = setTimeout(() => {
          S.search = searchEl.value;
          _applySearch();
          _render();
          _updateSummary();
        }, 250);
      });
    }

    // Filter buttons
    document.querySelectorAll('.cl-filter-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        document.querySelectorAll('.cl-filter-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        S.filter = btn.dataset.filter || 'all';
        S.page = 1;
        fetchCallLogs();
      });
    });

    // Call type filter
    const typeEl = $('clTypeFilter');
    if (typeEl) {
      typeEl.addEventListener('change', () => {
        S.callType = typeEl.value;
        S.page = 1;
        fetchCallLogs();
      });
    }

    // Refresh
    const refreshBtn = $('clRefresh');
    if (refreshBtn) {
      refreshBtn.addEventListener('click', () => fetchCallLogs(true));
    }

    // Modal open => fetch
    if (modal) {
      modal.addEventListener('shown.bs.modal', () => {
        fetchCallLogs();
        fetchStats();
      });
    }

    // Missed-call notifications
    startMissedCallPolling();
  }

  /* ── public API ────────────────────────────────────────── */
  window.CallLogs = {
    init,
    refresh: () => fetchCallLogs(true),
    showDetails: fetchCallDetail
  };

})();
