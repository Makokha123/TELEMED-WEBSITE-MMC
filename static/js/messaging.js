/**
 * Messaging Module – Doctor ↔ Patient real-time chat
 * ===================================================
 * Socket.IO-first with HTTP fallback. Optimistic UI.
 * Live message status: sending → sent → delivered → read.
 */
const Messaging = (() => {
  'use strict';

  // ── Config ───────────────────────────────────────────────
  let _cfg = { appointmentId: null, userId: null, userRole: '', csrfToken: '', socketUrl: '' };
  let _socket = null;
  let _connected = false;
  let _pendingMessages = [];      // { clientMsgId, payload, ts }
  const SEND_TIMEOUT = 8000;      // ms before HTTP fallback
  const TYPING_DEBOUNCE = 2500;
  const TYPING_HIDE_DELAY = 4000;
  let _typingTimer = null;
  let _typingHideTimer = null;
  let _isTyping = false;
  let _replyTo = null;            // { id, senderName, preview }
  let _loadingMore = false;
  let _hasMore = true;
  let _atBottom = true;
  let _emojiOpen = false;
  let _recording = false;
  let _mediaRecorder = null;
  let _audioChunks = [];

  // ── DOM refs (cached on init) ────────────────────────────
  let $chatBody, $msgInput, $sendBtn, $typingIndicator, $replyBar;
  let $presenceDot, $presenceText, $connStatus, $scrollBtn;
  let $emojiBtn, $fileInput, $recordBtn;

  // ═════════════════════════════════════════════════════════
  //  INIT
  // ═════════════════════════════════════════════════════════
  function init(cfg) {
    _cfg = { ..._cfg, ...cfg };
    _cacheDom();
    _bindUI();
    _initSocket();
    _initVoicePlayers(); // init voice player UIs for server-rendered messages
    if (_cfg.appointmentId) {
      _loadUnreadCounts();
      _loadPresence(_cfg.appointmentId);
    }
  }

  function _cacheDom() {
    $chatBody        = document.getElementById('chat-body');
    $msgInput        = document.getElementById('msg-input');
    $sendBtn         = document.getElementById('send-btn');
    $typingIndicator = document.getElementById('typing-indicator');
    $replyBar        = document.getElementById('reply-bar');
    $presenceDot     = document.getElementById('presence-dot');
    $presenceText    = document.getElementById('presence-text');
    $connStatus      = document.getElementById('connection-status');
    $scrollBtn       = document.getElementById('scroll-down-btn');
    $emojiBtn        = document.getElementById('emoji-btn');
    $fileInput       = document.getElementById('file-input');
    $recordBtn       = document.getElementById('record-btn');
  }

  // ═════════════════════════════════════════════════════════
  //  UI BINDINGS
  // ═════════════════════════════════════════════════════════
  function _bindUI() {
    if ($sendBtn) $sendBtn.addEventListener('click', _sendMessage);
    if ($msgInput) {
      $msgInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); _sendMessage(); }
      });
      $msgInput.addEventListener('input', _onInputChange);
    }
    if ($chatBody) $chatBody.addEventListener('scroll', _onScroll);
    if ($scrollBtn) $scrollBtn.addEventListener('click', () => _scrollToBottom(true));
    if ($fileInput) $fileInput.addEventListener('change', _handleFileUpload);
    if ($emojiBtn) $emojiBtn.addEventListener('click', _toggleEmojiPicker);
    if ($recordBtn) $recordBtn.addEventListener('click', _toggleRecording);

    // Close reply bar
    const closeReply = document.getElementById('close-reply');
    if (closeReply) closeReply.addEventListener('click', clearReply);

    // Sidebar appointment switching
    const apptList = document.getElementById('appointments-list');
    if (apptList) {
      apptList.addEventListener('click', (e) => {
        const item = e.target.closest('[data-appointment-id]');
        if (item) {
          const newId = parseInt(item.dataset.appointmentId, 10);
          if (newId && newId !== _cfg.appointmentId) switchAppointment(newId);
        }
      });
    }

    // Sidebar search
    const sidebarSearch = document.getElementById('sidebar-search');
    if (sidebarSearch) {
      sidebarSearch.addEventListener('input', (e) => {
        const q = e.target.value.toLowerCase();
        document.querySelectorAll('.appt-item').forEach(el => {
          const name = (el.dataset.name || '').toLowerCase();
          el.style.display = name.includes(q) ? '' : 'none';
        });
      });
    }

    // Search messages
    const searchInput = document.getElementById('search-input');
    if (searchInput) {
      searchInput.addEventListener('input', (e) => {
        const q = e.target.value.toLowerCase();
        document.querySelectorAll('.message-bubble').forEach(el => {
          const text = el.textContent.toLowerCase();
          el.style.display = text.includes(q) || !q ? '' : 'none';
        });
      });
    }
  }

  // ═════════════════════════════════════════════════════════
  //  SOCKET.IO
  // ═════════════════════════════════════════════════════════
  function _initSocket() {
    if (typeof io === 'undefined') {
      console.warn('Socket.IO not loaded, HTTP-only mode');
      return;
    }
    _socket = io(_cfg.socketUrl, {
      transports: ['websocket', 'polling'],
      reconnection: true,
      reconnectionDelay: 1000,
      reconnectionDelayMax: 5000,
      reconnectionAttempts: Infinity,
    });
    // Expose socket globally for call infrastructure reuse
    window._msgSocket = _socket;

    _socket.on('connect', () => {
      _connected = true;
      _updateConnectionUI(true);
      if (_cfg.appointmentId) _joinRoom(_cfg.appointmentId);
      _retrySendPending();
    });

    _socket.on('disconnect', () => {
      _connected = false;
      _updateConnectionUI(false);
    });

    _socket.on('reconnect', () => {
      _connected = true;
      _updateConnectionUI(true);
      if (_cfg.appointmentId) _joinRoom(_cfg.appointmentId);
      _retrySendPending();
    });

    // ── Message events ──
    _socket.on('msg:ack', _onAck);
    _socket.on('new_message', _onNewMessage);
    _socket.on('message_status_update', _onStatusUpdate);

    // ── Typing ──
    _socket.on('msg:typing', _showTyping);
    _socket.on('msg:stop_typing', _hideTyping);

    // ── Presence ──
    _socket.on('msg:user_joined', (d) => _updatePresenceUI(true, d.user_name));
    _socket.on('msg:user_left', () => _updatePresenceUI(false));

    // ── Recording state ──
    _socket.on('msg:recording', (d) => {
      if (d.recording) {
        _showTyping({ user_name: d.user_name, _recording: true });
      } else {
        _hideTyping();
      }
    });

    // ── Errors ──
    _socket.on('msg:error', (d) => {
      console.error('msg:error', d);
      if (d.client_msg_id) _markPendingFailed(d.client_msg_id);
      if (d.error === 'payment_required') {
        _showToast('Payment required to send messages', 'warning');
      }
    });
  }

  function _joinRoom(appointmentId) {
    if (_socket && _connected) {
      _socket.emit('msg:join', { appointment_id: appointmentId });
    }
  }

  function _leaveRoom(appointmentId) {
    if (_socket && _connected) {
      _socket.emit('msg:leave', { appointment_id: appointmentId });
    }
  }

  // ═════════════════════════════════════════════════════════
  //  SEND MESSAGE
  // ═════════════════════════════════════════════════════════
  function _sendMessage() {
    if (!$msgInput) return;
    const content = $msgInput.value.trim();
    if (!content || !_cfg.appointmentId) return;

    const clientMsgId = _uuid();
    const payload = {
      appointment_id: _cfg.appointmentId,
      content,
      message_type: 'text',
      client_msg_id: clientMsgId,
      reply_to_message_id: _replyTo ? _replyTo.id : null,
    };

    // Optimistic UI
    _renderPending(clientMsgId, content);
    $msgInput.value = '';
    $msgInput.style.height = 'auto';
    _scrollToBottom(true);
    clearReply();
    _stopTypingEmit();

    // Track pending
    _pendingMessages.push({ clientMsgId, payload, ts: Date.now() });

    // Send via socket
    if (_socket && _connected) {
      _socket.emit('msg:send', payload);
    }

    // Timeout → HTTP fallback
    setTimeout(() => _checkPendingTimeout(clientMsgId), SEND_TIMEOUT);
  }

  function _checkPendingTimeout(clientMsgId) {
    const idx = _pendingMessages.findIndex(p => p.clientMsgId === clientMsgId);
    if (idx === -1) return; // already acked
    const pending = _pendingMessages[idx];
    // Try HTTP fallback
    _sendViaHttp(pending.payload).then(res => {
      if (res && res.success) {
        _replacePending(clientMsgId, res.message);
        _removePending(clientMsgId);
      } else {
        _markPendingFailed(clientMsgId);
        _removePending(clientMsgId);
      }
    }).catch(() => {
      _markPendingFailed(clientMsgId);
      _removePending(clientMsgId);
    });
  }

  async function _sendViaHttp(payload) {
    try {
      const resp = await fetch('/api/messaging/send', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRFToken': _cfg.csrfToken,
        },
        body: JSON.stringify(payload),
      });
      return await resp.json();
    } catch (err) {
      console.error('HTTP send failed', err);
      return null;
    }
  }

  function _retrySendPending() {
    const pending = [..._pendingMessages];
    pending.forEach(p => {
      if (_socket && _connected) {
        _socket.emit('msg:send', p.payload);
      }
    });
  }

  function _removePending(clientMsgId) {
    _pendingMessages = _pendingMessages.filter(p => p.clientMsgId !== clientMsgId);
  }

  // ═════════════════════════════════════════════════════════
  //  RECEIVE HANDLERS
  // ═════════════════════════════════════════════════════════
  function _onAck(data) {
    const cid = data.client_msg_id;
    if (cid) {
      _replacePending(cid, data);
      _removePending(cid);
    }
  }

  function _onNewMessage(data) {
    if (!data || data.appointment_id !== _cfg.appointmentId) {
      // Different appointment → update unread badge
      _incrementUnread(data.appointment_id);
      return;
    }
    // Skip if it's our own message (already rendered optimistically)
    if (data.sender_id === _cfg.userId) return;

    _renderMessage(data);
    _playNotification();
    if (_atBottom) _scrollToBottom(true);

    // Auto mark as read if window focused
    if (document.hasFocus()) {
      _markReadSocket([data.id]);
    }
  }

  function _onStatusUpdate(data) {
    if (!data || !data.message_ids) return;
    data.message_ids.forEach(id => {
      const el = document.querySelector(`[data-msg-status="${id}"]`);
      if (el) el.innerHTML = _statusIcon(data.status);
    });
  }

  // ═════════════════════════════════════════════════════════
  //  RENDER
  // ═════════════════════════════════════════════════════════
  function _renderMessage(msg, prepend) {
    if (!$chatBody) return;
    // Duplicate guard
    if (document.querySelector(`[data-message-id="${msg.id}"]`)) return;

    const isMine = msg.sender_id === _cfg.userId;
    const bubble = document.createElement('div');
    bubble.className = `message-bubble ${isMine ? 'sent' : 'received'}`;
    bubble.dataset.messageId = msg.id;
    bubble.dataset.senderId = msg.sender_id;

    let html = '';

    // Reply preview
    if (msg.reply_to_message_id && msg.reply_preview) {
      html += `<div class="reply-preview" onclick="Messaging.scrollToMessage(${msg.reply_to_message_id})">
        <span class="reply-sender">${_esc(msg.reply_sender_name || '')}</span>
        <span class="reply-text">${_esc(msg.reply_preview)}</span>
      </div>`;
    }

    if (!isMine) {
      html += `<div class="msg-sender">${_esc(msg.sender_name || '')}</div>`;
    }

    // Content by type
    if (msg.message_type === 'system') {
      bubble.className = 'system-message';
      const content = _esc(msg.content || '');
      // Detect call-related system messages and make them interactive
      const isCallMsg = /📵|📞|call/i.test(msg.content || '');
      if (isCallMsg && typeof CallLogs !== 'undefined') {
        bubble.innerHTML = `<span class="system-call-event" style="cursor:pointer" title="View call logs">${content}</span>`;
        bubble.querySelector('.system-call-event')?.addEventListener('click', () => {
          const modal = document.getElementById('callLogsModal');
          if (modal) new bootstrap.Modal(modal).show();
        });
      } else {
        bubble.innerHTML = content;
      }
      if (prepend) $chatBody.prepend(bubble);
      else $chatBody.appendChild(bubble);
      return;
    } else if (msg.message_type === 'image' && msg.has_file) {
      const src = `/api/messaging/file/${msg.id}`;
      html += `<div class="msg-image"><img src="${src}" alt="Image" loading="lazy" onclick="Messaging.viewImage('${src}')"></div>`;
    } else if (msg.message_type === 'voice_note' && msg.has_file) {
      const vnId = 'vn_' + msg.id;
      html += `<div class="msg-voice-player" data-vn-id="${vnId}" data-src="/api/messaging/file/${msg.id}">
        <button class="vn-play-btn" title="Play"><i class="fas fa-play"></i></button>
        <div class="vn-wave-wrap"><canvas class="vn-wave-canvas" height="28"></canvas><div class="vn-progress"></div></div>
        <span class="vn-duration">--:--</span>
      </div>`;
    } else if (msg.message_type === 'prescription' && msg.content) {
      let rx;
      try { rx = JSON.parse(msg.content); } catch(e) { rx = null; }
      if (rx && rx.prescription_id) {
        html += `<div class="msg-prescription-card">
          <div class="rx-header"><i class="fas fa-prescription"></i> Prescription</div>
          <div class="rx-med">${_esc(rx.medication || '')}</div>
          <div class="rx-dosage"><strong>Dosage:</strong> ${_esc(rx.dosage || '')}</div>
          ${rx.instructions ? `<div class="rx-inst"><strong>Instructions:</strong> ${_esc(rx.instructions)}</div>` : ''}
          <div class="rx-actions">
            <a href="/prescription/${rx.prescription_id}" class="btn btn-sm btn-outline-primary" target="_blank"><i class="fas fa-eye me-1"></i>View</a>
            <a href="/prescription/${rx.prescription_id}/print" class="btn btn-sm btn-outline-secondary" target="_blank"><i class="fas fa-print me-1"></i>Print</a>
            <a href="/prescription/${rx.prescription_id}/download" class="btn btn-sm btn-outline-success" target="_blank"><i class="fas fa-download me-1"></i>Download</a>
          </div>
        </div>`;
      } else {
        html += `<div class="msg-text">${_linkify(_esc(msg.content || ''))}</div>`;
      }
    } else if (msg.message_type === 'document' && msg.has_file) {
      html += `<div class="msg-file"><i class="fas fa-file"></i><a href="/api/messaging/file/${msg.id}" target="_blank">${_esc(msg.content || 'Download')}</a></div>`;
    } else {
      html += `<div class="msg-text">${_linkify(_esc(msg.content || ''))}</div>`;
    }

    // Meta: time + status
    html += `<div class="msg-meta"><span class="msg-time">${_formatTime(msg.timestamp)}</span>`;
    if (isMine) {
      html += `<span class="msg-status" data-msg-status="${msg.id}">${_statusIcon(msg.status)}</span>`;
    }
    html += `</div>`;

    // Reply button
    const preview = _esc((msg.content || '').substring(0, 80));
    html += `<div class="msg-actions"><button class="btn-reply" onclick="Messaging.setReply(${msg.id},'${_esc(msg.sender_name || '')}','${preview}')" title="Reply"><i class="fas fa-reply"></i></button></div>`;

    bubble.innerHTML = html;
    if (prepend) $chatBody.prepend(bubble);
    else $chatBody.appendChild(bubble);

    // Init custom voice players for any new voice note bubbles
    _initVoicePlayers();
  }

  function _renderPending(clientMsgId, content) {
    if (!$chatBody) return;
    const bubble = document.createElement('div');
    bubble.className = 'message-bubble sent pending';
    bubble.dataset.clientMsgId = clientMsgId;

    let replyHtml = '';
    if (_replyTo) {
      replyHtml = `<div class="reply-preview" onclick="Messaging.scrollToMessage(${_replyTo.id})">
        <span class="reply-sender">${_esc(_replyTo.senderName)}</span>
        <span class="reply-text">${_esc(_replyTo.preview)}</span>
      </div>`;
    }

    bubble.innerHTML = `${replyHtml}
      <div class="msg-text">${_linkify(_esc(content))}</div>
      <div class="msg-meta">
        <span class="msg-time">${_formatTime(new Date().toISOString())}</span>
        <span class="pending-icon"><i class="far fa-clock"></i></span>
      </div>`;
    $chatBody.appendChild(bubble);
  }

  function _replacePending(clientMsgId, msg) {
    const el = document.querySelector(`[data-client-msg-id="${clientMsgId}"]`);
    if (el) {
      el.classList.remove('pending');
      el.removeAttribute('data-client-msg-id');
      el.dataset.messageId = msg.id;
      el.dataset.senderId = msg.sender_id;
      // Update meta with real ID and status
      const meta = el.querySelector('.msg-meta');
      if (meta) {
        meta.innerHTML = `<span class="msg-time">${_formatTime(msg.timestamp)}</span>
          <span class="msg-status" data-msg-status="${msg.id}">${_statusIcon(msg.status)}</span>`;
      }
    }
  }

  function _markPendingFailed(clientMsgId) {
    const el = document.querySelector(`[data-client-msg-id="${clientMsgId}"]`);
    if (el) {
      el.classList.remove('pending');
      el.classList.add('failed');
      const meta = el.querySelector('.msg-meta');
      if (meta) {
        meta.innerHTML += `<button class="btn btn-sm btn-link retry-btn text-danger" onclick="Messaging._retryFailed(this)">
          <i class="fas fa-redo-alt"></i> Retry
        </button>`;
      }
    }
  }

  function _retryFailed(btn) {
    const bubble = btn.closest('.message-bubble');
    if (!bubble) return;
    const text = bubble.querySelector('.msg-text');
    if (!text) return;
    const content = text.textContent;
    bubble.remove();
    $msgInput.value = content;
    _sendMessage();
  }

  // ═════════════════════════════════════════════════════════
  //  LOAD MESSAGES (pagination)
  // ═════════════════════════════════════════════════════════
  function _loadMessages(appointmentId, beforeId) {
    if (_loadingMore) return;
    _loadingMore = true;
    let url = `/api/messaging/messages/${appointmentId}?limit=50`;
    if (beforeId) url += `&before_id=${beforeId}`;

    fetch(url, { headers: { 'X-CSRFToken': _cfg.csrfToken } })
      .then(r => r.json())
      .then(data => {
        if (data.success && data.messages) {
          _hasMore = data.has_more;
          const prevTop = $chatBody ? $chatBody.scrollTop : 0;
          const prevHeight = $chatBody ? $chatBody.scrollHeight : 0;
          data.messages.forEach(m => _renderMessage(m, !!beforeId));
          // Maintain scroll position when prepending
          if (beforeId && $chatBody) {
            $chatBody.scrollTop = prevTop + ($chatBody.scrollHeight - prevHeight);
          }
        }
      })
      .catch(err => console.error('Load messages failed', err))
      .finally(() => { _loadingMore = false; });
  }

  // ═════════════════════════════════════════════════════════
  //  TYPING INDICATORS
  // ═════════════════════════════════════════════════════════
  function _onInputChange() {
    if (!_isTyping && _socket && _connected) {
      _isTyping = true;
      _socket.emit('msg:typing', { appointment_id: _cfg.appointmentId });
    }
    clearTimeout(_typingTimer);
    _typingTimer = setTimeout(_stopTypingEmit, TYPING_DEBOUNCE);
  }

  function _stopTypingEmit() {
    if (_isTyping && _socket && _connected) {
      _isTyping = false;
      _socket.emit('msg:stop_typing', { appointment_id: _cfg.appointmentId });
    }
  }

  function _showTyping(data) {
    if (!$typingIndicator || data.user_id === _cfg.userId) return;
    const nameEl = $typingIndicator.querySelector('.typing-name');
    const textEl = $typingIndicator.querySelector('.typing-text');
    if (nameEl) nameEl.textContent = data.user_name || '';
    if (textEl) textEl.textContent = data._recording ? 'is recording' : 'is typing';
    $typingIndicator.classList.remove('d-none');
    clearTimeout(_typingHideTimer);
    _typingHideTimer = setTimeout(_hideTyping, TYPING_HIDE_DELAY);
  }

  function _hideTyping() {
    if ($typingIndicator) $typingIndicator.classList.add('d-none');
    clearTimeout(_typingHideTimer);
  }

  // ═════════════════════════════════════════════════════════
  //  FILE UPLOAD
  // ═════════════════════════════════════════════════════════
  function _handleFileUpload() {
    if (!$fileInput || !$fileInput.files.length) return;
    const file = $fileInput.files[0];
    $fileInput.value = '';

    // Determine type
    let msgType = 'document';
    if (file.type.startsWith('image/')) msgType = 'image';

    const clientMsgId = _uuid();
    _renderPending(clientMsgId, `📎 ${file.name}`);
    _scrollToBottom(true);

    const form = new FormData();
    form.append('file', file);
    form.append('appointment_id', _cfg.appointmentId);
    form.append('message_type', msgType);
    form.append('client_msg_id', clientMsgId);
    if (_replyTo) form.append('reply_to_message_id', _replyTo.id);
    clearReply();

    fetch('/api/messaging/upload', {
      method: 'POST',
      headers: { 'X-CSRFToken': _cfg.csrfToken },
      body: form,
    })
      .then(r => r.json())
      .then(data => {
        if (data.success) {
          _replacePending(clientMsgId, data.message);
          // Re-render with proper file display
          const el = document.querySelector(`[data-message-id="${data.message.id}"]`);
          if (el) el.remove();
          _renderMessage(data.message);
          _scrollToBottom(true);
        } else {
          _markPendingFailed(clientMsgId);
        }
      })
      .catch(() => _markPendingFailed(clientMsgId));
  }

  // ═════════════════════════════════════════════════════════
  //  VOICE RECORDING  (rebuilt – waveform, timer, quality)
  // ═════════════════════════════════════════════════════════
  const MAX_RECORDING_SEC = 120; // 2 min cap
  let _recStream = null;
  let _recTimer = null;
  let _recSeconds = 0;
  let _recAnalyser = null;
  let _recAnimFrame = null;

  function _toggleRecording() {
    if (_recording) _stopRecording();
    else _startRecording();
  }

  async function _startRecording() {
    try {
      _recStream = await navigator.mediaDevices.getUserMedia({ audio: { echoCancellation: true, noiseSuppression: true, sampleRate: 48000 } });
      // Prefer opus in ogg/webm for quality+size; fall back gracefully
      const mimeType = MediaRecorder.isTypeSupported('audio/webm;codecs=opus')
        ? 'audio/webm;codecs=opus'
        : MediaRecorder.isTypeSupported('audio/ogg;codecs=opus')
          ? 'audio/ogg;codecs=opus'
          : 'audio/webm';

      _mediaRecorder = new MediaRecorder(_recStream, { mimeType });
      _audioChunks = [];
      _mediaRecorder.ondataavailable = (e) => { if (e.data.size) _audioChunks.push(e.data); };
      _mediaRecorder.onstop = () => {
        _recStream.getTracks().forEach(t => t.stop());
        const blob = new Blob(_audioChunks, { type: mimeType });
        _uploadVoiceNote(blob);
        _destroyRecordingUI();
      };
      _mediaRecorder.start(250); // collect in 250ms chunks for timely waveform
      _recording = true;

      // Build recording overlay UI
      _buildRecordingUI();

      // Notify other party
      if (_socket && _connected) {
        _socket.emit('msg:recording', { appointment_id: _cfg.appointmentId, recording: true });
      }
    } catch (err) {
      console.error('Mic access denied', err);
      _showToast('Microphone access denied. Please allow microphone access.', 'error');
    }
  }

  function _stopRecording() {
    if (_mediaRecorder && _mediaRecorder.state !== 'inactive') {
      _mediaRecorder.stop();
    }
    _recording = false;
    clearInterval(_recTimer);
    cancelAnimationFrame(_recAnimFrame);
    if (_socket && _connected) {
      _socket.emit('msg:recording', { appointment_id: _cfg.appointmentId, recording: false });
    }
  }

  function _cancelRecording() {
    if (_mediaRecorder && _mediaRecorder.state !== 'inactive') {
      _mediaRecorder.ondataavailable = null;
      _mediaRecorder.onstop = null;
      _mediaRecorder.stop();
    }
    if (_recStream) _recStream.getTracks().forEach(t => t.stop());
    _recording = false;
    _audioChunks = [];
    clearInterval(_recTimer);
    cancelAnimationFrame(_recAnimFrame);
    _destroyRecordingUI();
    if (_socket && _connected) {
      _socket.emit('msg:recording', { appointment_id: _cfg.appointmentId, recording: false });
    }
  }

  /* ── Recording overlay (replaces input bar while recording) ── */
  function _buildRecordingUI() {
    const chatInput = document.querySelector('.chat-input');
    if (!chatInput) return;

    // Hide normal input elements
    chatInput.querySelectorAll(':scope > *').forEach(el => el.style.display = 'none');

    const overlay = document.createElement('div');
    overlay.id = 'recording-overlay';
    overlay.style.cssText = 'display:flex;align-items:center;gap:10px;width:100%;padding:0 4px;';
    overlay.innerHTML = `
      <button id="rec-cancel" title="Cancel recording" style="background:none;border:none;color:#e74c3c;font-size:20px;cursor:pointer;padding:6px"><i class="fas fa-trash-alt"></i></button>
      <div style="flex:1;display:flex;align-items:center;gap:8px;background:#fff;border-radius:20px;padding:6px 12px;">
        <span id="rec-dot" style="width:10px;height:10px;border-radius:50%;background:#e74c3c;animation:pulse 1s infinite;flex-shrink:0"></span>
        <canvas id="rec-waveform" height="32" style="flex:1;min-width:100px;height:32px"></canvas>
        <span id="rec-timer" style="font-family:monospace;font-size:14px;color:#111b21;min-width:44px;text-align:right">0:00</span>
      </div>
      <button id="rec-send" title="Send voice note" style="background:#00a884;color:#fff;border:none;border-radius:50%;width:44px;height:44px;font-size:18px;cursor:pointer;display:flex;align-items:center;justify-content:center;flex-shrink:0"><i class="fas fa-paper-plane"></i></button>
    `;
    chatInput.appendChild(overlay);

    // Timer
    _recSeconds = 0;
    _recTimer = setInterval(() => {
      _recSeconds++;
      const m = Math.floor(_recSeconds / 60);
      const s = _recSeconds % 60;
      const timerEl = document.getElementById('rec-timer');
      if (timerEl) timerEl.textContent = `${m}:${s.toString().padStart(2, '0')}`;
      if (_recSeconds >= MAX_RECORDING_SEC) _stopRecording();
    }, 1000);

    // Waveform visualizer
    _startWaveform();

    // Button handlers
    document.getElementById('rec-cancel').addEventListener('click', _cancelRecording);
    document.getElementById('rec-send').addEventListener('click', _stopRecording);
  }

  function _destroyRecordingUI() {
    const overlay = document.getElementById('recording-overlay');
    if (overlay) {
      const chatInput = overlay.parentElement;
      overlay.remove();
      chatInput.querySelectorAll(':scope > *').forEach(el => el.style.display = '');
    }
    cancelAnimationFrame(_recAnimFrame);
    _recAnalyser = null;
  }

  function _startWaveform() {
    try {
      const ctx = new (window.AudioContext || window.webkitAudioContext)();
      const source = ctx.createMediaStreamSource(_recStream);
      _recAnalyser = ctx.createAnalyser();
      _recAnalyser.fftSize = 256;
      source.connect(_recAnalyser);
      const bufLen = _recAnalyser.frequencyBinCount;
      const dataArr = new Uint8Array(bufLen);

      const canvas = document.getElementById('rec-waveform');
      if (!canvas) return;
      const cCtx = canvas.getContext('2d');
      canvas.width = canvas.offsetWidth * (window.devicePixelRatio || 1);
      canvas.height = 32 * (window.devicePixelRatio || 1);
      cCtx.scale(window.devicePixelRatio || 1, window.devicePixelRatio || 1);

      function draw() {
        _recAnimFrame = requestAnimationFrame(draw);
        _recAnalyser.getByteFrequencyData(dataArr);
        const w = canvas.offsetWidth;
        const h = 32;
        cCtx.clearRect(0, 0, w, h);

        const barW = 3, gap = 2, total = barW + gap;
        const bars = Math.floor(w / total);
        const step = Math.max(1, Math.floor(bufLen / bars));

        for (let i = 0; i < bars; i++) {
          const v = dataArr[i * step] / 255;
          const barH = Math.max(2, v * h * 0.9);
          const x = i * total;
          const y = (h - barH) / 2;
          cCtx.fillStyle = '#00a884';
          cCtx.fillRect(x, y, barW, barH);
        }
      }
      draw();
    } catch (e) {
      console.warn('Waveform visualizer unavailable', e);
    }
  }

  function _uploadVoiceNote(blob) {
    const clientMsgId = _uuid();
    _renderPending(clientMsgId, '🎤 Voice note');
    _scrollToBottom(true);

    const form = new FormData();
    form.append('file', blob, 'voice_note.webm');
    form.append('appointment_id', _cfg.appointmentId);
    form.append('message_type', 'voice_note');
    form.append('client_msg_id', clientMsgId);

    fetch('/api/messaging/upload', {
      method: 'POST',
      headers: { 'X-CSRFToken': _cfg.csrfToken },
      body: form,
    })
      .then(r => r.json())
      .then(data => {
        if (data.success) {
          _replacePending(clientMsgId, data.message);
          const el = document.querySelector(`[data-message-id="${data.message.id}"]`);
          if (el) el.remove();
          _renderMessage(data.message);
          _scrollToBottom(true);
        } else {
          _markPendingFailed(clientMsgId);
        }
      })
      .catch(() => _markPendingFailed(clientMsgId));
  }

  // ═════════════════════════════════════════════════════════
  //  REPLY
  // ═════════════════════════════════════════════════════════
  function setReply(id, senderName, preview) {
    _replyTo = { id, senderName, preview };
    if ($replyBar) {
      $replyBar.classList.remove('d-none');
      const nameEl = $replyBar.querySelector('.reply-bar-name');
      const textEl = $replyBar.querySelector('.reply-bar-text');
      if (nameEl) nameEl.textContent = senderName;
      if (textEl) textEl.textContent = preview;
    }
    if ($msgInput) $msgInput.focus();
  }

  function clearReply() {
    _replyTo = null;
    if ($replyBar) $replyBar.classList.add('d-none');
  }

  // ═════════════════════════════════════════════════════════
  //  APPOINTMENT SWITCHING
  // ═════════════════════════════════════════════════════════
  function switchAppointment(newId) {
    if (_cfg.appointmentId) _leaveRoom(_cfg.appointmentId);
    _cfg.appointmentId = newId;
    _hasMore = true;
    clearReply();
    _hideTyping();

    // Update sidebar active
    document.querySelectorAll('.appt-item').forEach(el => {
      el.classList.toggle('active', parseInt(el.dataset.appointmentId, 10) === newId);
    });
    _clearUnread(newId);

    // Load via page navigation for clean state
    window.location.href = `/communication/${newId}`;
  }

  // ═════════════════════════════════════════════════════════
  //  SCROLL
  // ═════════════════════════════════════════════════════════
  function _onScroll() {
    if (!$chatBody) return;
    const threshold = 60;
    _atBottom = ($chatBody.scrollHeight - $chatBody.scrollTop - $chatBody.clientHeight) < threshold;

    if ($scrollBtn) {
      $scrollBtn.classList.toggle('d-none', _atBottom);
    }

    // Load more on scroll to top
    if ($chatBody.scrollTop < 50 && _hasMore && !_loadingMore) {
      const firstMsg = $chatBody.querySelector('[data-message-id]');
      const beforeId = firstMsg ? parseInt(firstMsg.dataset.messageId, 10) : null;
      if (beforeId) _loadMessages(_cfg.appointmentId, beforeId);
    }
  }

  function _scrollToBottom(force) {
    if (!$chatBody) return;
    if (force || _atBottom) {
      $chatBody.scrollTop = $chatBody.scrollHeight;
    }
  }

  function scrollToMessage(id) {
    const el = document.querySelector(`[data-message-id="${id}"]`);
    if (el) {
      el.scrollIntoView({ behavior: 'smooth', block: 'center' });
      el.classList.add('highlight');
      setTimeout(() => el.classList.remove('highlight'), 2000);
    }
  }

  // ═════════════════════════════════════════════════════════
  //  EMOJI
  // ═════════════════════════════════════════════════════════
  function _toggleEmojiPicker() {
    let panel = document.getElementById('emoji-panel');
    if (panel) {
      panel.remove();
      _emojiOpen = false;
      return;
    }
    const emojis = ['😀','😂','😍','👍','❤️','🙏','😊','🎉','😢','🔥','👋','💪','😷','🤒','💊','🏥','📋','✅','⏰','🩺'];
    panel = document.createElement('div');
    panel.id = 'emoji-panel';
    panel.className = 'emoji-picker-panel';
    emojis.forEach(e => {
      const btn = document.createElement('button');
      btn.className = 'emoji-item';
      btn.textContent = e;
      btn.onclick = () => {
        if ($msgInput) { $msgInput.value += e; $msgInput.focus(); }
        panel.remove();
        _emojiOpen = false;
      };
      panel.appendChild(btn);
    });
    const wrapper = $emojiBtn ? $emojiBtn.parentElement : document.body;
    wrapper.style.position = 'relative';
    wrapper.appendChild(panel);
    _emojiOpen = true;
  }

  // ═════════════════════════════════════════════════════════
  //  READ RECEIPTS
  // ═════════════════════════════════════════════════════════
  function _markReadSocket(ids) {
    if (!ids.length || !_cfg.appointmentId) return;
    if (_socket && _connected) {
      _socket.emit('msg:read', { appointment_id: _cfg.appointmentId, message_ids: ids });
    } else {
      // HTTP fallback
      fetch('/api/messaging/status', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-CSRFToken': _cfg.csrfToken },
        body: JSON.stringify({ message_ids: ids, status: 'read' }),
      }).catch(() => {});
    }
  }

  // Auto mark visible messages as read on focus
  document.addEventListener('visibilitychange', () => {
    if (!document.hidden && _cfg.appointmentId) {
      const unread = [];
      document.querySelectorAll('.message-bubble.received').forEach(el => {
        const id = parseInt(el.dataset.messageId, 10);
        if (id) unread.push(id);
      });
      if (unread.length) _markReadSocket(unread);
    }
  });

  // ═════════════════════════════════════════════════════════
  //  UNREAD COUNTS
  // ═════════════════════════════════════════════════════════
  function _loadUnreadCounts() {
    fetch('/api/messaging/unread-counts', { headers: { 'X-CSRFToken': _cfg.csrfToken } })
      .then(r => r.json())
      .then(counts => {
        Object.entries(counts).forEach(([apptId, count]) => {
          _setUnreadBadge(parseInt(apptId, 10), count);
        });
      })
      .catch(() => {});
  }

  function _setUnreadBadge(appointmentId, count) {
    const item = document.querySelector(`[data-appointment-id="${appointmentId}"]`);
    if (!item) return;
    const badge = item.querySelector('[data-badge]');
    if (!badge) return;
    if (count > 0) {
      badge.textContent = count > 99 ? '99+' : count;
      badge.classList.remove('d-none');
    } else {
      badge.classList.add('d-none');
    }
  }

  function _clearUnread(appointmentId) {
    _setUnreadBadge(appointmentId, 0);
  }

  function _incrementUnread(appointmentId) {
    const item = document.querySelector(`[data-appointment-id="${appointmentId}"]`);
    if (!item) return;
    const badge = item.querySelector('[data-badge]');
    if (!badge) return;
    const current = parseInt(badge.textContent, 10) || 0;
    _setUnreadBadge(appointmentId, current + 1);
  }

  // ═════════════════════════════════════════════════════════
  //  PRESENCE
  // ═════════════════════════════════════════════════════════
  function _loadPresence(appointmentId) {
    fetch(`/api/messaging/presence/${appointmentId}`, { headers: { 'X-CSRFToken': _cfg.csrfToken } })
      .then(r => r.json())
      .then(data => {
        if (data.success) _updatePresenceUI(data.online);
      })
      .catch(() => {});
  }

  function _updatePresenceUI(online, name) {
    if ($presenceDot) {
      $presenceDot.classList.toggle('online', online);
      $presenceDot.classList.toggle('offline', !online);
    }
    if ($presenceText) {
      $presenceText.textContent = online ? 'Online' : 'Offline';
    }
  }

  function _updateConnectionUI(connected) {
    if ($connStatus) {
      if (connected) {
        $connStatus.textContent = '';
        $connStatus.classList.add('connected');
      } else {
        $connStatus.textContent = 'Connecting...';
        $connStatus.classList.remove('connected');
      }
    }
  }

  // ═════════════════════════════════════════════════════════
  //  IMAGE VIEWER
  // ═════════════════════════════════════════════════════════
  function viewImage(src) {
    let viewer = document.getElementById('image-viewer');
    if (!viewer) {
      viewer = document.createElement('div');
      viewer.id = 'image-viewer';
      viewer.className = 'image-viewer';
      viewer.innerHTML = `<div class="image-viewer-backdrop" onclick="Messaging.closeImage()"></div>
        <img class="image-viewer-img" src="">
        <button class="image-viewer-close" onclick="Messaging.closeImage()"><i class="fas fa-times"></i></button>`;
      document.body.appendChild(viewer);
    }
    viewer.querySelector('.image-viewer-img').src = src;
    viewer.classList.remove('d-none');
  }

  function closeImage() {
    const viewer = document.getElementById('image-viewer');
    if (viewer) viewer.classList.add('d-none');
  }

  // ═════════════════════════════════════════════════════════
  //  CUSTOM VOICE PLAYER
  // ═════════════════════════════════════════════════════════
  let _vnPlayers = {}; // { vnId: { audio, ctx, analyser, animFrame, playing } }

  function _initVoicePlayers() {
    document.querySelectorAll('.msg-voice-player:not([data-vn-init])').forEach(el => {
      el.setAttribute('data-vn-init', '1');
      const vnId = el.dataset.vnId;
      const src = el.dataset.src;
      const playBtn = el.querySelector('.vn-play-btn');
      const progress = el.querySelector('.vn-progress');
      const durEl = el.querySelector('.vn-duration');
      const canvas = el.querySelector('.vn-wave-canvas');

      const audio = new Audio();
      audio.preload = 'metadata';
      audio.src = src;
      _vnPlayers[vnId] = { audio, playing: false };

      audio.addEventListener('loadedmetadata', () => {
        if (audio.duration && isFinite(audio.duration)) {
          durEl.textContent = _fmtDur(audio.duration);
        }
      });
      audio.addEventListener('timeupdate', () => {
        if (audio.duration && isFinite(audio.duration)) {
          const pct = (audio.currentTime / audio.duration) * 100;
          progress.style.width = pct + '%';
          durEl.textContent = _fmtDur(audio.duration - audio.currentTime);
        }
      });
      audio.addEventListener('ended', () => {
        _vnPlayers[vnId].playing = false;
        playBtn.innerHTML = '<i class="fas fa-play"></i>';
        progress.style.width = '0%';
        durEl.textContent = _fmtDur(audio.duration);
      });

      // Draw static waveform from random seed (deterministic per message id)
      _drawStaticWave(canvas, vnId);

      // Seek on click
      const waveWrap = el.querySelector('.vn-wave-wrap');
      waveWrap.addEventListener('click', (e) => {
        if (!audio.duration || !isFinite(audio.duration)) return;
        const rect = waveWrap.getBoundingClientRect();
        const pct = (e.clientX - rect.left) / rect.width;
        audio.currentTime = pct * audio.duration;
        if (!_vnPlayers[vnId].playing) {
          _playVN(vnId);
        }
      });

      playBtn.addEventListener('click', () => {
        if (_vnPlayers[vnId].playing) _pauseVN(vnId);
        else _playVN(vnId);
      });
    });
  }

  function _playVN(vnId) {
    // Pause any other playing
    Object.keys(_vnPlayers).forEach(k => { if (k !== vnId && _vnPlayers[k].playing) _pauseVN(k); });
    const p = _vnPlayers[vnId];
    if (!p) return;
    p.audio.play();
    p.playing = true;
    const el = document.querySelector(`[data-vn-id="${vnId}"]`);
    if (el) el.querySelector('.vn-play-btn').innerHTML = '<i class="fas fa-pause"></i>';
  }

  function _pauseVN(vnId) {
    const p = _vnPlayers[vnId];
    if (!p) return;
    p.audio.pause();
    p.playing = false;
    const el = document.querySelector(`[data-vn-id="${vnId}"]`);
    if (el) el.querySelector('.vn-play-btn').innerHTML = '<i class="fas fa-play"></i>';
  }

  function _drawStaticWave(canvas, seed) {
    if (!canvas) return;
    const w = canvas.offsetWidth || 200;
    const h = 28;
    canvas.width = w * (window.devicePixelRatio || 1);
    canvas.height = h * (window.devicePixelRatio || 1);
    const ctx = canvas.getContext('2d');
    ctx.scale(window.devicePixelRatio || 1, window.devicePixelRatio || 1);

    // Simple seeded pseudo-random
    let s = 0;
    for (let i = 0; i < seed.length; i++) s = ((s << 5) - s + seed.charCodeAt(i)) | 0;
    const rand = () => { s = (s * 16807 + 0) % 2147483647; return (s & 0x7fffffff) / 2147483647; };

    const barW = 2, gap = 1.5, total = barW + gap;
    const bars = Math.floor(w / total);
    for (let i = 0; i < bars; i++) {
      const v = 0.15 + rand() * 0.7;
      const barH = Math.max(2, v * h * 0.85);
      const x = i * total;
      const y = (h - barH) / 2;
      ctx.fillStyle = '#8696a0';
      ctx.fillRect(x, y, barW, barH);
    }
  }

  function _fmtDur(sec) {
    if (!sec || !isFinite(sec)) return '--:--';
    const m = Math.floor(sec / 60);
    const s = Math.floor(sec % 60);
    return `${m}:${s.toString().padStart(2, '0')}`;
  }

  // ═════════════════════════════════════════════════════════
  //  PRESCRIPTION SEND  (doctor only)
  // ═════════════════════════════════════════════════════════
  function sendPrescriptionMessage(prescriptionId) {
    if (!_cfg.appointmentId || !prescriptionId) return;
    if (_socket && _connected) {
      _socket.emit('msg:prescription', {
        appointment_id: _cfg.appointmentId,
        prescription_id: prescriptionId,
      });
    } else {
      _showToast('Not connected. Please try again.', 'error');
    }
  }

  // ═════════════════════════════════════════════════════════
  //  NOTIFICATION
  // ═════════════════════════════════════════════════════════
  function _playNotification() {
    try {
      const ctx = new (window.AudioContext || window.webkitAudioContext)();
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();
      osc.connect(gain);
      gain.connect(ctx.destination);
      osc.frequency.value = 800;
      gain.gain.value = 0.1;
      osc.start();
      osc.stop(ctx.currentTime + 0.15);
    } catch (e) {}
  }

  function _showToast(message, type) {
    // Use existing toast system if available
    if (typeof showToast === 'function') {
      showToast(message, type);
      return;
    }
    console.log(`[${type}] ${message}`);
  }

  // ═════════════════════════════════════════════════════════
  //  HELPERS
  // ═════════════════════════════════════════════════════════
  function _uuid() { return 'msg_' + Date.now().toString(36) + '_' + Math.random().toString(36).substring(2, 8); }

  function _esc(str) {
    const d = document.createElement('div');
    d.textContent = str;
    return d.innerHTML;
  }

  function _linkify(text) {
    return text.replace(/(https?:\/\/[^\s<]+)/g, '<a href="$1" target="_blank" rel="noopener noreferrer">$1</a>');
  }

  function _formatTime(iso) {
    if (!iso) return '';
    try {
      const d = new Date(iso);
      return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    } catch { return ''; }
  }

  function _statusIcon(status) {
    switch (status) {
      case 'read':      return '<i class="fas fa-check-double msg-tick-read"></i>';
      case 'delivered':  return '<i class="fas fa-check-double msg-tick"></i>';
      case 'sent':       return '<i class="fas fa-check msg-tick"></i>';
      default:           return '<i class="far fa-clock pending-icon"></i>';
    }
  }

  // ═════════════════════════════════════════════════════════
  //  PUBLIC API
  // ═════════════════════════════════════════════════════════
  return {
    init,
    setReply,
    clearReply,
    scrollToMessage,
    switchAppointment,
    viewImage,
    closeImage,
    sendPrescriptionMessage,
    _retryFailed,
  };
})();
