/**
 * Call Manager
 * Orchestrates WebRTC client + Signaling client
 * Manages call state machine, timers, UI updates, quality monitoring
 */

class CallManager {
  constructor(signalingClient, webrtcConfig = {}) {
    this.signaling = signalingClient;
    this.webrtc = null;
    this.webrtcConfig = webrtcConfig;

    // Call state machine
    this.callState = 'idle'; // idle, initiated, ringing, connecting, connected, ended, failed
    this.callId = null;
    this.callType = 'video'; // 'video' or 'audio'
    this.callStartTime = null;
    this.callEndTime = null;
    this.isInitiator = false;

    // Call participants
    this.localUserId = null;
    this.remoteUserId = null;
    this.appointmentId = null;

    // Timers and intervals
    this.callTimerInterval = null;
    this.callTimeoutTimer = null;
    this.callTimeoutDuration = 60000; // 60 seconds for ringing timeout
    this.callDuration = 0;

    // State tracking
    this.isMuted = false;
    this.isVideoOff = false;
    this.isScreenSharing = false;
    this.screenStream = null;

    // Callbacks
    this.onStateChange = null;
    this.onError = null;
    this.onQualityUpdate = null;
    this.onCallDurationUpdate = null;
    this.onRemoteStream = null;
    this.onLocalStream = null;

    // Setup signaling event handlers
    this._setupSignalingListeners();
  }

  /**
   * Setup event listeners on signaling client
   */
  _setupSignalingListeners() {
    this.signaling.addEventListener('onIncomingCall', (data) => {
      this._handleIncomingCall(data);
    });

    this.signaling.addEventListener('onCallAccepted', (data) => {
      this._handleCallAccepted(data);
    });

    this.signaling.addEventListener('onCallDeclined', (data) => {
      this._handleCallDeclined(data);
    });

    this.signaling.addEventListener('onCallBusy', (data) => {
      this._handleCallBusy(data);
    });

    this.signaling.addEventListener('onCallConnected', (data) => {
      this._handleCallConnected(data);
    });

    this.signaling.addEventListener('onCallEnded', (data) => {
      this._handleCallEnded(data);
    });

    this.signaling.addEventListener('onCallMissed', (data) => {
      this._handleCallMissed(data);
    });

    this.signaling.addEventListener('onWebRTCOffer', (data) => {
      this._handleWebRTCOffer(data);
    });

    this.signaling.addEventListener('onWebRTCAnswer', (data) => {
      this._handleWebRTCAnswer(data);
    });

    this.signaling.addEventListener('onWebRTCIce', (data) => {
      this._handleWebRTCIce(data);
    });
  }

  /**
   * Initiate a call (caller)
   */
  async initiateCall(remoteUserId, appointmentId, callType = 'video') {
    try {
      this.callType = callType;
      this.remoteUserId = remoteUserId;
      this.appointmentId = appointmentId;
      this.isInitiator = true;
      this.callId = `call_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;

      // Get local media stream
      this._setState('initiated');
      const constraints = {
        audio: true,
        video: callType === 'video'
      };

      this.webrtc = new WebRTCClient({
        ...this.webrtcConfig,
        audio: true,
        video: callType === 'video'
      });

      this.webrtc.callType = callType;

      // Setup WebRTC callbacks
      this.webrtc.onLocalStream = (stream) => {
        if (this.onLocalStream) this.onLocalStream(stream);
      };

      this.webrtc.onRemoteStream = (stream) => {
        if (this.onRemoteStream) this.onRemoteStream(stream);
      };

      this.webrtc.onStateChange = (state) => {
        console.log('WebRTC state:', state);
        if (state === 'connected') {
          this._setState('connected');
          this._startCallTimer();
        }
      };

      this.webrtc.onIceCandidate = (candidate) => {
        this.signaling.sendIceCandidate(this.callId, candidate);
      };

      this.webrtc.onError = (error) => {
        this._error('WebRTC error', error);
      };

      this.webrtc.onQualityMetrics = (metrics) => {
        if (this.onQualityUpdate) {
          this.onQualityUpdate(metrics);
        }
      };

      // Get local media
      await this.webrtc.getLocalStream(constraints);

      // Create and send offer
      this._setState('ringing');
      this._startRingingTimeout();
      const offer = await this.webrtc.createOffer();

      // Notify signaling server
      this.signaling.initiateCall(remoteUserId, appointmentId, callType);
      this.signaling.sendOffer(this.callId, offer);

    } catch (error) {
      this._error('Failed to initiate call', error);
      this._setState('failed');
    }
  }

  /**
   * Accept incoming call (callee)
   */
  async acceptCall(callData) {
    try {
      this.callId = callData.call_id;
      this.remoteUserId = callData.caller_id;
      this.appointmentId = callData.appointment_id;
      this.callType = callData.call_type || 'video';
      this.isInitiator = false;

      this._setState('connecting');

      // Get local media stream
      const constraints = {
        audio: true,
        video: this.callType === 'video'
      };

      this.webrtc = new WebRTCClient({
        ...this.webrtcConfig,
        audio: true,
        video: this.callType === 'video'
      });

      this.webrtc.callType = this.callType;

      // Setup WebRTC callbacks
      this.webrtc.onLocalStream = (stream) => {
        if (this.onLocalStream) this.onLocalStream(stream);
      };

      this.webrtc.onRemoteStream = (stream) => {
        if (this.onRemoteStream) this.onRemoteStream(stream);
      };

      this.webrtc.onStateChange = (state) => {
        if (state === 'connected') {
          this._setState('connected');
          this._startCallTimer();
        }
      };

      this.webrtc.onIceCandidate = (candidate) => {
        this.signaling.sendIceCandidate(this.callId, candidate);
      };

      // Get local media
      await this.webrtc.getLocalStream(constraints);

      // Create and send answer
      const answer = await this.webrtc.receiveOffer(callData.offer);
      this.signaling.sendAnswer(this.callId, answer);
      this.signaling.acceptCall(this.callId);

    } catch (error) {
      this._error('Failed to accept call', error);
      this._setState('failed');
      this.signaling.declineCall(this.callId, 'connection_failed');
    }
  }

  /**
   * Decline incoming call
   */
  declineCall(reason = 'user_declined') {
    if (this.callId) {
      this.signaling.declineCall(this.callId, reason);
    }
    this._cleanup();
  }

  /**
   * End active call
   */
  endCall(reason = 'user_hangup') {
    if (this.callId) {
      this.signaling.hangupCall(this.callId, reason);
    }
    this._cleanup();
  }

  /**
   * Toggle audio mute
   */
  toggleAudio() {
    this.isMuted = !this.isMuted;
    if (this.webrtc) {
      this.webrtc.setAudioEnabled(!this.isMuted);
    }
    return this.isMuted;
  }

  /**
   * Toggle video
   */
  toggleVideo() {
    this.isVideoOff = !this.isVideoOff;
    if (this.webrtc) {
      this.webrtc.setVideoEnabled(!this.isVideoOff);
    }
    return this.isVideoOff;
  }

  /**
   * Start screen sharing
   */
  async startScreenShare() {
    try {
      if (this.isScreenSharing) {
        console.warn('Screen sharing already active');
        return false;
      }

      // Get screen stream
      this.screenStream = await navigator.mediaDevices.getDisplayMedia({
        video: {
          cursor: 'always'
        },
        audio: false
      });

      const screenTrack = this.screenStream.getVideoTracks()[0];

      // Replace video track in peer connection
      const sender = this.webrtc.peerConnection
        .getSenders()
        .find(s => s.track && s.track.kind === 'video');

      if (sender) {
        await sender.replaceTrack(screenTrack);
      }

      // Listen for screen share stop
      screenTrack.onended = () => {
        this._stopScreenShare();
      };

      this.isScreenSharing = true;

      // Notify remote user
      this._sendMetadata();

      return true;
    } catch (error) {
      console.error('Failed to start screen sharing:', error);
      return false;
    }
  }

  /**
   * Stop screen sharing
   */
  async _stopScreenShare() {
    if (!this.isScreenSharing) return;

    try {
      // Stop screen stream tracks
      if (this.screenStream) {
        this.screenStream.getTracks().forEach(track => track.stop());
        this.screenStream = null;
      }

      // Switch back to camera
      const videoConstraints = {
        width: { ideal: 1280 },
        height: { ideal: 720 }
      };

      const cameraStream = await navigator.mediaDevices.getUserMedia({
        video: videoConstraints,
        audio: false
      });

      const cameraTrack = cameraStream.getVideoTracks()[0];

      // Replace video track
      const sender = this.webrtc.peerConnection
        .getSenders()
        .find(s => s.track && s.track.kind === 'video');

      if (sender) {
        await sender.replaceTrack(cameraTrack);
      }

      this.isScreenSharing = false;

      // Notify remote user
      this._sendMetadata();

    } catch (error) {
      console.error('Failed to stop screen sharing:', error);
    }
  }

  /**
   * Send metadata about call state
   */
  _sendMetadata() {
    if (this.webrtc && this.webrtc.dataChannel && this.webrtc.dataChannel.readyState === 'open') {
      this.webrtc.sendMessage({
        type: 'metadata',
        isScreenSharing: this.isScreenSharing,
        isMuted: this.isMuted,
        isVideoOff: this.isVideoOff,
        timestamp: Date.now()
      });
    }
  }

  /**
   * Send in-call message via data channel
   */
  sendMessage(body) {
    if (this.webrtc && this.webrtc.dataChannel) {
      return this.webrtc.sendMessage({
        type: 'message',
        body: body,
        timestamp: Date.now()
      });
    }
    return false;
  }

  /**
   * Get call statistics
   */
  async getCallStats() {
    if (!this.webrtc) return null;
    return await this.webrtc.getStats();
  }

  // ============================================
  // CALL EVENT HANDLERS (from signaling)
  // ============================================

  _handleIncomingCall(data) {
    console.log('Incoming call:', data);
    this.callId = data.call_id;
    this.remoteUserId = data.caller_id;
    this.appointmentId = data.appointment_id;
    this.callType = data.call_type || 'video';
    this._setState('ringing');
  }

  _handleCallAccepted(data) {
    console.log('Call accepted');
  }

  _handleCallDeclined(data) {
    console.log('Call declined:', data.reason);
    this._setState('ended');
    this._cleanup();
  }

  _handleCallBusy(data) {
    console.log('User busy');
    this._setState('ended');
    this._error('User is busy on another call', { reason: 'user_busy' });
    this._cleanup();
  }

  _handleCallConnected(data) {
    console.log('Call connected');
    this._setState('connected');
    this._startCallTimer();
  }

  _handleCallEnded(data) {
    console.log('Call ended:', data);
    this._setState('ended');
    this._cleanup();
  }

  _handleCallMissed(data) {
    console.log('Call missed');
    this._setState('ended');
    this._cleanup();
  }

  _handleWebRTCOffer(data) {
    console.log('Received WebRTC offer');
    if (this.webrtc) {
      this.webrtc.receiveOffer(data.offer);
    }
  }

  _handleWebRTCAnswer(data) {
    console.log('Received WebRTC answer');
    if (this.webrtc) {
      this.webrtc.receiveAnswer(data.answer);
    }
  }

  _handleWebRTCIce(data) {
    console.log('Received ICE candidate');
    if (this.webrtc) {
      this.webrtc.addIceCandidate(data.candidate);
    }
  }

  // ============================================
  // INTERNAL METHODS
  // ============================================

  /**
   * Start call timer
   */
  _startCallTimer() {
    this.callStartTime = Date.now();
    this.callTimerInterval = setInterval(() => {
      this.callDuration = Math.floor((Date.now() - this.callStartTime) / 1000);
      if (this.onCallDurationUpdate) {
        this.onCallDurationUpdate(this.callDuration);
      }
    }, 1000);
  }

  /**
   * Stop call timer
   */
  _stopCallTimer() {
    if (this.callTimerInterval) {
      clearInterval(this.callTimerInterval);
      this.callTimerInterval = null;
    }
  }

  /**
   * Start ringing timeout (auto-decline after timeout)
   */
  _startRingingTimeout() {
    this.callTimeoutTimer = setTimeout(() => {
      if (this.callState === 'ringing') {
        console.log('Call timeout - no answer');
        this._setState('ended');
        this.signaling.hangupCall(this.callId, 'no_answer');
        this._cleanup();
      }
    }, this.callTimeoutDuration);
  }

  /**
   * Clear ringing timeout
   */
  _clearRingingTimeout() {
    if (this.callTimeoutTimer) {
      clearTimeout(this.callTimeoutTimer);
      this.callTimeoutTimer = null;
    }
  }

  /**
   * Update call state
   */
  _setState(state) {
    if (this.callState !== state) {
      this.callState = state;
      console.log('Call state:', state);
      if (this.onStateChange) {
        this.onStateChange(state);
      }
    }
  }

  /**
   * Error handler
   */
  _error(message, error) {
    console.error(message, error);
    if (this.onError) {
      this.onError({ message, error });
    }
  }

  /**
   * Cleanup resources
   */
  _cleanup() {
    this._stopCallTimer();
    this._clearRingingTimeout();

    if (this.webrtc) {
      this.webrtc.stopLocalStream();
      this.webrtc.close();
      this.webrtc = null;
    }

    if (this.screenStream) {
      this.screenStream.getTracks().forEach(track => track.stop());
      this.screenStream = null;
    }

    this.isScreenSharing = false;
    this.isMuted = false;
    this.isVideoOff = false;
    this.callEndTime = Date.now();
  }

  // ============================================
  // STATE GETTERS
  // ============================================

  /**
   * Get current call state
   */
  getState() {
    return this.callState;
  }

  /**
   * Is call active
   */
  isCallActive() {
    return this.callState === 'connected';
  }

  /**
   * Get call duration formatted
   */
  getFormattedDuration() {
    const seconds = this.callDuration % 60;
    const minutes = Math.floor(this.callDuration / 60) % 60;
    const hours = Math.floor(this.callDuration / 3600);

    if (hours > 0) {
      return `${hours}:${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;
    }
    return `${minutes}:${seconds.toString().padStart(2, '0')}`;
  }

  /**
   * Get call metadata
   */
  getCallMetadata() {
    return {
      callId: this.callId,
      callType: this.callType,
      callState: this.callState,
      isInitiator: this.isInitiator,
      localUserId: this.localUserId,
      remoteUserId: this.remoteUserId,
      appointmentId: this.appointmentId,
      callDuration: this.callDuration,
      isMuted: this.isMuted,
      isVideoOff: this.isVideoOff,
      isScreenSharing: this.isScreenSharing
    };
  }
}

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
  module.exports = CallManager;
}
