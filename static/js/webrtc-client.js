/**
 * WebRTC Client Library
 * Handles RTCPeerConnection, SDP exchange, ICE candidates, media streams
 * Supports audio/video constraints, quality adaptation, and reconnection logic
 */

if (!window.WebRTCClient) {
  class WebRTCClient {
    constructor(config = {}) {
    this.config = {
      iceServers: [],
      audio: {
        echoCancellation: true,
        noiseSuppression: true,
        autoGainControl: true
      },
      video: {
        width: { ideal: 1280 },
        height: { ideal: 720 },
        frameRate: { ideal: 30 }
      },
      ...config
    };
    // Fetch ICE servers from backend to avoid hard-coding secrets
    this._loadIceServers();

    // State
    this.peerConnection = null;
    this.localStream = null;
    this.remoteStream = null;
    this.dataChannel = null;
    this.callState = 'idle'; // idle, initialized, connecting, connected, disconnected, failed
    this.callType = 'video'; // 'video' or 'audio'
    this.isInitiator = false;
    this.iceCandidates = [];
    this.pendingIceCandidates = [];
    this.reconnectAttempts = 0;
    this.maxReconnectAttempts = 5;
    this.reconnectDelay = 1000;

    // Callbacks
    this.onLocalStream = null;
    this.onRemoteStream = null;
    this.onStateChange = null;
    this.onIceCandidate = null;
    this.onError = null;
    this.onQualityMetrics = null;

    // Quality monitoring
    this.qualityCheckInterval = null;
    this.stats = {};
  }

  async _loadIceServers(){
    try {
      const r = await fetch('/api/ice', { credentials: 'same-origin' });
      if (r.ok) {
        const j = await r.json();
        if (j && Array.isArray(j.iceServers)) {
          this.config.iceServers = j.iceServers;
        }
      }
    } catch (e) {
      console.warn('Failed to fetch ICE servers, falling back to default STUN');
      if (!this.config.iceServers || this.config.iceServers.length === 0) {
        this.config.iceServers = [{ urls: 'stun:stun.l.google.com:19302' }];
      }
    }
  }

  /**
   * Initialize local media stream
   */
  async getLocalStream(constraints = {}) {
    try {
      const audioConstraints = constraints.audio !== false ? this.config.audio : false;
      const videoConstraints = constraints.video !== false ? this.config.video : false;

      const mediaConstraints = {
        audio: audioConstraints,
        video: this.callType === 'video' ? videoConstraints : false
      };

      this.localStream = await navigator.mediaDevices.getUserMedia(mediaConstraints);
      
      // Set stream ID for tracking
      this.localStream.id = `local_${Date.now()}`;
      
      if (this.onLocalStream) {
        this.onLocalStream(this.localStream);
      }

      return this.localStream;
    } catch (error) {
      this._error('Failed to get local stream', error);
      throw error;
    }
  }

  /**
   * Stop local media stream
   */
  stopLocalStream() {
    if (this.localStream) {
      this.localStream.getTracks().forEach(track => track.stop());
      this.localStream = null;
    }
  }

  /**
   * Initialize PeerConnection
   */
  initPeerConnection() {
    try {
      const config = {
        iceServers: this.config.iceServers
      };

      this.peerConnection = new RTCPeerConnection(config);
      // On network back online, try ICE restart if not connected
      try {
        window.addEventListener('online', () => {
          if (this.peerConnection && this.peerConnection.connectionState !== 'connected') {
            this._restartIce();
          }
        });
      } catch(e) {}

      // Add local stream tracks to peer connection
      if (this.localStream) {
        this.localStream.getTracks().forEach(track => {
          this.peerConnection.addTrack(track, this.localStream);
        });
      }

      // Handle ICE candidates
      this.peerConnection.onicecandidate = (event) => {
        if (event.candidate) {
          this.iceCandidates.push(event.candidate);
          if (this.onIceCandidate) {
            this.onIceCandidate(event.candidate);
          }
        }
      };

      // Handle connection state changes
      this.peerConnection.onconnectionstatechange = () => {
        this._handleConnectionStateChange();
      };

      // Handle ICE connection state
      this.peerConnection.oniceconnectionstatechange = () => {
        console.log('ICE connection state:', this.peerConnection.iceConnectionState);
      };

      // Handle remote stream
      this.peerConnection.ontrack = (event) => {
        console.log('Remote track received:', event.track.kind);
        if (!this.remoteStream) {
          this.remoteStream = new MediaStream();
        }
        this.remoteStream.addTrack(event.track);
        
        if (this.onRemoteStream) {
          this.onRemoteStream(this.remoteStream);
        }
      };

      // Create data channel for in-call chat
      if (this.isInitiator) {
        this.dataChannel = this.peerConnection.createDataChannel('chat', {
          ordered: true
        });
        this._setupDataChannel();
      } else {
        this.peerConnection.ondatachannel = (event) => {
          this.dataChannel = event.channel;
          this._setupDataChannel();
        };
      }

      this._setState('initialized');
    } catch (error) {
      this._error('Failed to initialize PeerConnection', error);
      throw error;
    }
  }

  /**
   * Setup data channel event listeners
   */
  _setupDataChannel() {
    if (!this.dataChannel) return;

    this.dataChannel.onopen = () => {
      console.log('Data channel opened');
    };

    this.dataChannel.onclose = () => {
      console.log('Data channel closed');
    };

    this.dataChannel.onerror = (error) => {
      console.error('Data channel error:', error);
    };
  }

  /**
   * Create and return offer
   */
  async createOffer() {
    try {
      this.isInitiator = true;
      this.initPeerConnection();
      
      const offer = await this.peerConnection.createOffer({
        offerToReceiveAudio: true,
        offerToReceiveVideo: this.callType === 'video'
      });

      await this.peerConnection.setLocalDescription(offer);
      this._setState('connecting');
      
      return offer;
    } catch (error) {
      this._error('Failed to create offer', error);
      throw error;
    }
  }

  /**
   * Receive offer and create answer
   */
  async receiveOffer(offer) {
    try {
      this.isInitiator = false;
      this.initPeerConnection();

      const sdpOffer = new RTCSessionDescription(offer);
      await this.peerConnection.setRemoteDescription(sdpOffer);

      const answer = await this.peerConnection.createAnswer();
      await this.peerConnection.setLocalDescription(answer);
      this._setState('connecting');

      return answer;
    } catch (error) {
      this._error('Failed to receive offer', error);
      throw error;
    }
  }

  /**
   * Receive answer
   */
  async receiveAnswer(answer) {
    try {
      const sdpAnswer = new RTCSessionDescription(answer);
      await this.peerConnection.setRemoteDescription(sdpAnswer);
      this._setState('connected');
    } catch (error) {
      this._error('Failed to receive answer', error);
      throw error;
    }
  }

  /**
   * Add ICE candidate
   */
  async addIceCandidate(candidate) {
    try {
      if (this.peerConnection && this.peerConnection.remoteDescription) {
        await this.peerConnection.addIceCandidate(new RTCIceCandidate(candidate));
      } else {
        // Queue candidate until remote description is set
        this.pendingIceCandidates.push(candidate);
      }
    } catch (error) {
      console.warn('Failed to add ICE candidate:', error);
    }
  }

  /**
   * Process queued ICE candidates
   */
  async _processPendingIceCandidates() {
    while (this.pendingIceCandidates.length > 0) {
      const candidate = this.pendingIceCandidates.shift();
      try {
        await this.peerConnection.addIceCandidate(new RTCIceCandidate(candidate));
      } catch (error) {
        console.warn('Failed to add pending ICE candidate:', error);
      }
    }
  }

  /**
   * Send message via data channel
   */
  sendMessage(message) {
    if (this.dataChannel && this.dataChannel.readyState === 'open') {
      this.dataChannel.send(JSON.stringify(message));
      return true;
    }
    return false;
  }

  /**
   * Mute/unmute audio
   */
  setAudioEnabled(enabled) {
    if (this.localStream) {
      this.localStream.getAudioTracks().forEach(track => {
        track.enabled = enabled;
      });
    }
  }

  /**
   * Enable/disable video
   */
  setVideoEnabled(enabled) {
    if (this.localStream) {
      this.localStream.getVideoTracks().forEach(track => {
        track.enabled = enabled;
      });
    }
  }

  /**
   * Get call statistics
   */
  async getStats() {
    if (!this.peerConnection) return null;

    try {
      const stats = {};
      const report = await this.peerConnection.getStats();

      report.forEach(stat => {
        if (stat.type === 'inbound-rtp') {
          if (stat.kind === 'video') {
            stats.video = {
              bytesReceived: stat.bytesReceived,
              framesDecoded: stat.framesDecoded,
              framesDropped: stat.framesDropped,
              frameWidth: stat.frameWidth,
              frameHeight: stat.frameHeight,
              jitter: stat.jitter
            };
          } else if (stat.kind === 'audio') {
            stats.audio = {
              bytesReceived: stat.bytesReceived,
              audioLevel: stat.audioLevel,
              jitter: stat.jitter
            };
          }
        } else if (stat.type === 'candidate-pair' && stat.state === 'succeeded') {
          stats.connection = {
            currentRoundTripTime: stat.currentRoundTripTime,
            availableOutgoingBitrate: stat.availableOutgoingBitrate,
            availableIncomingBitrate: stat.availableIncomingBitrate
          };
        }
      });

      this.stats = stats;
      if (this.onQualityMetrics) {
        this.onQualityMetrics(stats);
      }

      return stats;
    } catch (error) {
      console.error('Failed to get stats:', error);
      return null;
    }
  }

  /**
   * Start quality monitoring
   */
  startQualityMonitoring(interval = 1000) {
    if (this.qualityCheckInterval) return;

    this.qualityCheckInterval = setInterval(async () => {
      await this.getStats();
    }, interval);
  }

  /**
   * Stop quality monitoring
   */
  stopQualityMonitoring() {
    if (this.qualityCheckInterval) {
      clearInterval(this.qualityCheckInterval);
      this.qualityCheckInterval = null;
    }
  }

  /**
   * Handle connection state changes
   */
  _handleConnectionStateChange() {
    const state = this.peerConnection.connectionState;
    console.log('Connection state changed:', state);

    switch (state) {
      case 'connected':
        this._setState('connected');
        this.reconnectAttempts = 0;
        this._processPendingIceCandidates();
        this.startQualityMonitoring();
        break;
      case 'disconnected':
        this._setState('disconnected');
        this._attemptReconnect();
        break;
      case 'failed':
        this._setState('failed');
        this._error('WebRTC connection failed');
        break;
      case 'closed':
        this._setState('disconnected');
        break;
    }
  }

  /**
   * Attempt to reconnect
   */
  async _attemptReconnect() {
    if (this.reconnectAttempts >= this.maxReconnectAttempts) {
      this._error('Max reconnection attempts reached');
      this._setState('failed');
      return;
    }

    this.reconnectAttempts++;
    const delay = this.reconnectDelay * Math.pow(2, this.reconnectAttempts - 1);

    console.log(`Reconnecting in ${delay}ms (attempt ${this.reconnectAttempts}/${this.maxReconnectAttempts})`);

    setTimeout(() => {
      if (this.peerConnection && this.peerConnection.connectionState === 'disconnected') {
        // Trigger reconnection logic via signaling layer
        // This will be handled by the call manager
      }
    }, delay);
  }

  async _restartIce(){
    try {
      if (!this.peerConnection) return;
      const offer = await this.peerConnection.createOffer({ iceRestart: true });
      await this.peerConnection.setLocalDescription(offer);
      if (this.onRestartOffer) this.onRestartOffer(offer);
    } catch (e) {
      console.warn('ICE restart failed', e);
    }
  }

  /**
   * Close peer connection
   */
  close() {
    this.stopQualityMonitoring();
    
    if (this.peerConnection) {
      this.peerConnection.close();
      this.peerConnection = null;
    }

    if (this.dataChannel) {
      this.dataChannel.close();
      this.dataChannel = null;
    }

    this.remoteStream = null;
    this._setState('idle');
  }

  /**
   * Update call state
   */
  _setState(state) {
    if (this.callState !== state) {
      this.callState = state;
      if (this.onStateChange) {
        this.onStateChange(state);
      }
    }
  }

  /**
   * Handle error
   */
  _error(message, error) {
    console.error(message, error);
    if (this.onError) {
      this.onError({ message, error });
    }
  }

  /**
   * Get connection state
   */
  getState() {
    return this.callState;
  }

  /**
   * Check if connected
   */
  isConnected() {
    return this.callState === 'connected';
  }
}

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
  module.exports = WebRTCClient;
}

// Attach to window for global access
window.WebRTCClient = WebRTCClient;
}