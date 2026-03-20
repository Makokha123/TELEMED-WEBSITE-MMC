/**
 * Voice Call Module
 * Full-featured WebRTC voice call with Socket.IO signaling.
 * Features: call initiation, accept/reject, mute, hold, speaker toggle,
 * live duration timer, audio level visualisation, reconnection, quality
 * monitoring, network indicator, and call-end feedback.
 */
;(function () {
  'use strict';

  /* ================================================================
   *  STATE
   * ================================================================ */
  const State = {
    IDLE:        'idle',
    INITIATING:  'initiating',
    RINGING:     'ringing',
    CONNECTING:  'connecting',
    CONNECTED:   'connected',
    ON_HOLD:     'on_hold',
    RECONNECTING:'reconnecting',
    ENDED:       'ended',
  };

  let _state       = State.IDLE;
  let _socket      = null;
  let _pc          = null;   // RTCPeerConnection
  let _localStream = null;
  let _remoteStream= null;
  let _remoteAudio = null;   // <audio> element for remote audio
  let _callId      = null;
  let _appointmentId = null;
  let _localUserId = null;
  let _remoteUserId= null;
  let _isInitiator = false;
  let _isMuted     = false;
  let _onHold      = false;
  let _speakerOn   = true;
  let _timerInterval= null;
  let _callStart   = null;   // Date when connected
  let _iceServers  = [{ urls: 'stun:stun.l.google.com:19302' }];
  let _qualityInterval = null;
  let _reconnectAttempts = 0;
  const MAX_RECONNECT = 5;
  const RECONNECT_DELAY = 2000;
  let _ringTimeoutTimer = null;
  const RING_TIMEOUT_MS = 65000; // 65s frontend safety (server fires at 60s)
  let _audioCtx    = null;
  let _analyser    = null;
  let _levelFrameId= null;

  /* UI callback hooks — set by the page */
  const _callbacks = {
    onStateChange: null,    // (state, detail) => {}
    onDuration: null,       // (seconds, formatted) => {}
    onRemoteMute: null,     // (muted) => {}
    onRemoteHold: null,     // (onHold) => {}
    onAudioLevel: null,     // (level 0-1) => {}
    onQuality: null,        // ({rtt, packetLoss, jitter, bitrate}) => {}
    onError: null,          // (message) => {}
  };

  /* ================================================================
   *  PUBLIC API
   * ================================================================ */
  const VoiceCall = window.VoiceCall = {
    State,

    /** Initialise with references the page already has */
    init(opts) {
      _localUserId  = opts.userId;
      _appointmentId= opts.appointmentId;
      _remoteUserId = opts.remoteUserId;
      _socket       = opts.socket || window._msgSocket;
      Object.assign(_callbacks, opts.callbacks || {});
      _loadIceServers();
      _bindSocketEvents();
    },

    /** Start an outgoing voice call */
    call() {
      if (_state !== State.IDLE && _state !== State.ENDED) return;
      _isInitiator = true;
      _setState(State.INITIATING);
      _socket.emit('initiate_voice_call', {
        appointment_id: _appointmentId,
        call_type: 'voice',
      });
      // Frontend safety timeout — if server doesn't end the call within 65s, end it here
      _clearRingTimeout();
      _ringTimeoutTimer = setTimeout(function() {
        if (_state === State.INITIATING || _state === State.RINGING) {
          _socket.emit('end_voice_call', {
            call_id: _callId,
            appointment_id: _appointmentId,
            reason: 'unanswered',
          });
          _cleanup('unanswered');
        }
      }, RING_TIMEOUT_MS);
    },

    /** Accept an incoming call */
    accept(callId) {
      _callId = callId || _callId;
      _socket.emit('accept_voice_call', {
        call_id: _callId,
        appointment_id: _appointmentId,
      });
      _isInitiator = false;
      _setState(State.CONNECTING);
      _startWebRTC(false);
    },

    /** Reject / decline an incoming call */
    reject(callId) {
      _callId = callId || _callId;
      _socket.emit('reject_voice_call', {
        call_id: _callId,
        appointment_id: _appointmentId,
        reason: 'rejected',
      });
      _cleanup();
    },

    /** End (hang up) an active call */
    hangup(reason) {
      _socket.emit('end_voice_call', {
        call_id: _callId,
        appointment_id: _appointmentId,
        reason: reason || 'completed',
      });
      _cleanup();
    },

    /** Toggle mute */
    toggleMute() {
      _isMuted = !_isMuted;
      if (_localStream) {
        _localStream.getAudioTracks().forEach(t => { t.enabled = !_isMuted; });
      }
      _socket.emit('voice:mute', { appointment_id: _appointmentId, muted: _isMuted });
      return _isMuted;
    },

    /** Toggle speaker (loudspeaker) */
    toggleSpeaker() {
      _speakerOn = !_speakerOn;
      if (_remoteAudio) {
        _remoteAudio.volume = _speakerOn ? 1.0 : 0.3;
        // Use setSinkId for device switching if available
        if (_remoteAudio.setSinkId && !_speakerOn) {
          _remoteAudio.setSinkId('default').catch(() => {});
        }
      }
      _socket.emit('voice:speaker', { appointment_id: _appointmentId, speaker_on: _speakerOn });
      return _speakerOn;
    },

    /** Toggle hold */
    toggleHold() {
      _onHold = !_onHold;
      if (_localStream) {
        _localStream.getAudioTracks().forEach(t => { t.enabled = !_onHold; });
      }
      _socket.emit('voice:hold', { appointment_id: _appointmentId, on_hold: _onHold });
      if (_onHold) {
        _setState(State.ON_HOLD);
      } else if (_state === State.ON_HOLD) {
        _setState(State.CONNECTED);
      }
      return _onHold;
    },

    /** Current state */
    getState()    { return _state; },
    isMuted()     { return _isMuted; },
    isOnHold()    { return _onHold; },
    isSpeakerOn() { return _speakerOn; },
    getCallId()   { return _callId; },

    /** Destroy / cleanup completely */
    destroy() { _cleanup(); },
  };

  /* ================================================================
   *  SOCKET EVENT BINDINGS
   * ================================================================ */
  function _bindSocketEvents() {
    if (!_socket) return;

    _socket.on('call_ringing', (d) => {
      if (d.appointment_id == _appointmentId) {
        _callId = d.call_id || _callId;
        if (_isInitiator) _setState(State.RINGING);
      }
    });

    _socket.on('incoming_voice_call', (d) => {
      if (d.appointment_id == _appointmentId) {
        _callId = d.call_id;
        _remoteUserId = d.caller_id;
        if (_callbacks.onStateChange) {
          _callbacks.onStateChange('incoming', d);
        }
      }
    });

    _socket.on('voice_call_accepted', (d) => {
      if (d.appointment_id == _appointmentId || d.call_id === _callId) {
        _clearRingTimeout();
        _setState(State.CONNECTING);
        _startWebRTC(true);
      }
    });

    _socket.on('call_connected', (d) => {
      if (d.appointment_id == _appointmentId || d.call_id === _callId) {
        _setState(State.CONNECTED);
        _callStart = new Date();
        _startTimer();
        _startQualityMonitor();
      }
    });

    _socket.on('voice_call_ended', (d) => {
      if (d.appointment_id == _appointmentId || d.call_id === _callId) {
        _cleanup(d.reason || 'ended');
      }
    });
    _socket.on('call_ended', (d) => {
      if (d.appointment_id == _appointmentId || d.call_id === _callId) {
        _cleanup(d.reason || 'ended');
      }
    });

    _socket.on('voice_call_unanswered', (d) => {
      if (d.appointment_id == _appointmentId || d.call_id === _callId) {
        _cleanup('unanswered');
      }
    });
    _socket.on('voice_call_connection_failed', (d) => {
      if (d.appointment_id == _appointmentId || d.call_id === _callId) {
        _cleanup('connection_failed');
      }
    });
    _socket.on('call_failed_busy', (d) => {
      if (d.appointment_id == _appointmentId || d.call_id === _callId) {
        _cleanup('busy');
      }
    });
    _socket.on('call_rejected', (d) => {
      if (d.appointment_id == _appointmentId || d.call_id === _callId) {
        _cleanup('rejected');
      }
    });

    // Remote mute/hold indicators
    _socket.on('voice:mute_changed', (d) => {
      if (d.appointment_id == _appointmentId && d.user_id != _localUserId) {
        if (_callbacks.onRemoteMute) _callbacks.onRemoteMute(d.muted);
      }
    });
    _socket.on('voice:hold_changed', (d) => {
      if (d.appointment_id == _appointmentId && d.user_id != _localUserId) {
        if (_callbacks.onRemoteHold) _callbacks.onRemoteHold(d.on_hold);
      }
    });

    // WebRTC signaling
    _socket.on('webrtc_offer', _handleOffer);
    _socket.on('webrtc_answer', _handleAnswer);
    _socket.on('webrtc_ice_candidate', _handleIce);
  }

  /* ================================================================
   *  WEBRTC
   * ================================================================ */
  async function _loadIceServers() {
    try {
      const r = await fetch('/api/ice', { credentials: 'same-origin' });
      if (r.ok) {
        const j = await r.json();
        if (Array.isArray(j.iceServers)) _iceServers = j.iceServers;
      }
    } catch (_) { /* use default STUN */ }
  }

  async function _startWebRTC(isOffer) {
    try {
      _localStream = await navigator.mediaDevices.getUserMedia({
        audio: { echoCancellation: true, noiseSuppression: true, autoGainControl: true },
        video: false,
      });
    } catch (e) {
      _error('Microphone access denied');
      _cleanup('mic_denied');
      return;
    }

    _pc = new RTCPeerConnection({ iceServers: _iceServers });
    _localStream.getTracks().forEach(t => _pc.addTrack(t, _localStream));

    _pc.ontrack = (ev) => {
      _remoteStream = ev.streams[0] || new MediaStream([ev.track]);
      _playRemoteAudio(_remoteStream);
      if (_state === State.CONNECTING) {
        _setState(State.CONNECTED);
        _callStart = new Date();
        _startTimer();
        _startQualityMonitor();
      }
      _startAudioLevel();
    };

    _pc.onicecandidate = (ev) => {
      if (ev.candidate) {
        _socket.emit('webrtc_ice_candidate', {
          appointment_id: _appointmentId,
          call_id: _callId,
          candidate: ev.candidate,
          target_user_id: _remoteUserId,
        });
      }
    };

    _pc.oniceconnectionstatechange = () => {
      const s = _pc.iceConnectionState;
      if (s === 'connected' || s === 'completed') {
        _reconnectAttempts = 0;
        if (_state === State.RECONNECTING || _state === State.CONNECTING) {
          _setState(State.CONNECTED);
          if (!_callStart) {
            _callStart = new Date();
            _startTimer();
            _startQualityMonitor();
          }
        }
      } else if (s === 'disconnected') {
        _attemptReconnect();
      } else if (s === 'failed') {
        if (_reconnectAttempts < MAX_RECONNECT) {
          _attemptReconnect();
        } else {
          _error('Connection failed');
          VoiceCall.hangup('network_error');
        }
      }
    };

    // Join voice room
    _socket.emit('join_voice_room', { appointment_id: _appointmentId });

    if (isOffer) {
      try {
        const offer = await _pc.createOffer();
        await _pc.setLocalDescription(offer);
        _socket.emit('webrtc_offer', {
          appointment_id: _appointmentId,
          call_id: _callId,
          offer: _pc.localDescription,
          target_user_id: _remoteUserId,
        });
      } catch (e) {
        _error('Failed to create offer');
      }
    }
  }

  async function _handleOffer(d) {
    if (d.appointment_id != _appointmentId) return;
    if (!_pc) return;
    try {
      await _pc.setRemoteDescription(new RTCSessionDescription(d.offer));
      const answer = await _pc.createAnswer();
      await _pc.setLocalDescription(answer);
      _socket.emit('webrtc_answer', {
        appointment_id: _appointmentId,
        call_id: _callId,
        answer: _pc.localDescription,
        target_user_id: d.sender_id,
      });
    } catch (e) {
      _error('Failed to handle offer');
    }
  }

  async function _handleAnswer(d) {
    if (d.appointment_id != _appointmentId) return;
    if (!_pc) return;
    try {
      await _pc.setRemoteDescription(new RTCSessionDescription(d.answer));
    } catch (e) {
      _error('Failed to handle answer');
    }
  }

  async function _handleIce(d) {
    if (d.appointment_id != _appointmentId) return;
    if (!_pc) return;
    try {
      await _pc.addIceCandidate(new RTCIceCandidate(d.candidate));
    } catch (_) { /* non-fatal */ }
  }

  function _attemptReconnect() {
    if (_state === State.ENDED) return;
    _reconnectAttempts++;
    _setState(State.RECONNECTING);
    setTimeout(async () => {
      if (!_pc || _state === State.ENDED) return;
      try {
        const offer = await _pc.createOffer({ iceRestart: true });
        await _pc.setLocalDescription(offer);
        _socket.emit('webrtc_offer', {
          appointment_id: _appointmentId,
          call_id: _callId,
          offer: _pc.localDescription,
          target_user_id: _remoteUserId,
        });
      } catch (_) {}
    }, RECONNECT_DELAY * _reconnectAttempts);
  }

  /* ================================================================
   *  AUDIO
   * ================================================================ */
  function _playRemoteAudio(stream) {
    if (!_remoteAudio) {
      _remoteAudio = document.createElement('audio');
      _remoteAudio.autoplay = true;
      _remoteAudio.playsInline = true;
      document.body.appendChild(_remoteAudio);
    }
    _remoteAudio.srcObject = stream;
    _remoteAudio.volume = _speakerOn ? 1.0 : 0.3;
    _remoteAudio.play().catch(() => {});
  }

  function _startAudioLevel() {
    if (!_remoteStream || !_callbacks.onAudioLevel) return;
    try {
      _audioCtx = new (window.AudioContext || window.webkitAudioContext)();
      const source = _audioCtx.createMediaStreamSource(_remoteStream);
      _analyser = _audioCtx.createAnalyser();
      _analyser.fftSize = 256;
      source.connect(_analyser);
      const data = new Uint8Array(_analyser.frequencyBinCount);
      function tick() {
        if (!_analyser) return;
        _analyser.getByteFrequencyData(data);
        let sum = 0;
        for (let i = 0; i < data.length; i++) sum += data[i];
        const avg = sum / data.length / 255;
        _callbacks.onAudioLevel(avg);
        _levelFrameId = requestAnimationFrame(tick);
      }
      tick();
    } catch (_) {}
  }

  /* ================================================================
   *  TIMER & QUALITY
   * ================================================================ */
  function _startTimer() {
    _stopTimer();
    _timerInterval = setInterval(() => {
      if (!_callStart) return;
      const secs = Math.floor((Date.now() - _callStart.getTime()) / 1000);
      const h = Math.floor(secs / 3600);
      const m = Math.floor((secs % 3600) / 60);
      const s = secs % 60;
      const fmt = h > 0
        ? `${h}:${String(m).padStart(2, '0')}:${String(s).padStart(2, '0')}`
        : `${m}:${String(s).padStart(2, '0')}`;
      if (_callbacks.onDuration) _callbacks.onDuration(secs, fmt);
    }, 1000);
  }
  function _stopTimer() {
    if (_timerInterval) { clearInterval(_timerInterval); _timerInterval = null; }
  }

  function _startQualityMonitor() {
    _stopQualityMonitor();
    _qualityInterval = setInterval(async () => {
      if (!_pc) return;
      try {
        const stats = await _pc.getStats();
        let rtt = null, loss = null, jitter = null, bitrate = null;
        stats.forEach(r => {
          if (r.type === 'candidate-pair' && r.state === 'succeeded') {
            rtt = r.currentRoundTripTime ? Math.round(r.currentRoundTripTime * 1000) : null;
          }
          if (r.type === 'inbound-rtp' && r.kind === 'audio') {
            loss = r.packetsLost;
            jitter = r.jitter ? Math.round(r.jitter * 1000) : null;
          }
          if (r.type === 'outbound-rtp' && r.kind === 'audio') {
            bitrate = r.bytesSent;
          }
        });
        if (_callbacks.onQuality) {
          _callbacks.onQuality({ rtt, packetLoss: loss, jitter, bitrate });
        }
        // Send quality metrics to server periodically
        if (_callId && rtt !== null) {
          _socket.emit('quality:metrics', {
            call_id: _callId,
            rtt, packet_loss: loss, jitter, audio_bitrate: bitrate,
            audio_quality: rtt && rtt < 150 ? 'good' : (rtt && rtt < 300 ? 'fair' : 'poor'),
          });
        }
      } catch (_) {}
    }, 5000);
  }
  function _stopQualityMonitor() {
    if (_qualityInterval) { clearInterval(_qualityInterval); _qualityInterval = null; }
  }

  /* ================================================================
   *  HELPERS
   * ================================================================ */
  function _setState(s, detail) {
    _state = s;
    if (_callbacks.onStateChange) _callbacks.onStateChange(s, detail);
  }

  function _error(msg) {
    console.error('[VoiceCall]', msg);
    if (_callbacks.onError) _callbacks.onError(msg);
  }

  function _clearRingTimeout() {
    if (_ringTimeoutTimer) { clearTimeout(_ringTimeoutTimer); _ringTimeoutTimer = null; }
  }

  function _cleanup(reason) {
    _clearRingTimeout();
    _stopTimer();
    _stopQualityMonitor();
    if (_levelFrameId) { cancelAnimationFrame(_levelFrameId); _levelFrameId = null; }
    if (_analyser) { try { _analyser.disconnect(); } catch (_) {} _analyser = null; }
    if (_audioCtx) { try { _audioCtx.close(); } catch (_) {} _audioCtx = null; }
    if (_pc) { try { _pc.close(); } catch (_) {} _pc = null; }
    if (_localStream) {
      _localStream.getTracks().forEach(t => t.stop());
      _localStream = null;
    }
    if (_remoteAudio) {
      _remoteAudio.srcObject = null;
      try { _remoteAudio.remove(); } catch (_) {}
      _remoteAudio = null;
    }
    _remoteStream = null;
    _isMuted = false;
    _onHold = false;
    _speakerOn = true;
    _callStart = null;
    _reconnectAttempts = 0;
    _setState(State.ENDED, { reason: reason || 'ended' });
    _callId = null;
    _isInitiator = false;
  }
})();
