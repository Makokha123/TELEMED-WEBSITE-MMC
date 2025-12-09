/**
 * Signaling Client for Socket.IO
 * Handles WebSocket communication for call signaling, presence updates, chat
 * Implements auto-reconnection, message queuing, and event routing
 */

if (!window.SignalingClient) {
  class SignalingClient {
    constructor(config = {}) {
    // Allow passing an existing Socket.IO socket instance as the config
    const isSocketInstance = config && typeof config.on === 'function' && typeof config.emit === 'function';

    if (isSocketInstance) {
      this.socket = config;
      this.config = {
        url: '',
        reconnect: true,
        reconnectionDelay: 1000,
        maxReconnectionAttempts: 10
      };
      this.isConnected = !!this.socket.connected;
    } else {
      this.config = {
        url: config.url || '',
        reconnect: true,
        reconnectionDelay: 1000,
        maxReconnectionAttempts: 10,
        ...config
      };
      this.socket = null;
      this.isConnected = false;
    }

    this.userId = null;
    this.currentCallId = null;
    this.messageQueue = [];
    this.eventHandlers = {};
    this.reconnectAttempts = 0;

    // Callbacks
    this.onConnect = null;
    this.onDisconnect = null;
    this.onError = null;

    // If socket instance provided, set up listeners routing
    if (isSocketInstance) {
      // Ensure our internal routing is configured
      this._setupCallEventListeners();
      this._setupPresenceEventListeners();
      this._setupChatEventListeners();
    }
  }

  /**
   * Initialize Socket.IO connection
   */
  connect(userId) {
    return new Promise((resolve, reject) => {
      try {
        this.userId = userId;

        // If socket already exists (passed in constructor), use it
        if (this.socket) {
          console.log('Using existing Socket.IO instance for signaling');
          this.isConnected = !!this.socket.connected;

          // Register user immediately
          if (this.isConnected) {
            this.emit('register_user', { user_id: userId });
            this._processMessageQueue();
            if (this.onConnect) this.onConnect();
            resolve();
            return;
          }

          // If socket exists but not connected, attach connect handler
          this.socket.on('connect', () => {
            console.log('Signaling connected (existing socket):', this.socket.id);
            this.isConnected = true;
            this.reconnectAttempts = 0;
            this.emit('register_user', { user_id: userId });
            this._processMessageQueue();
            if (this.onConnect) this.onConnect();
            resolve();
          });

          this.socket.on('disconnect', (reason) => {
            console.log('Signaling disconnected:', reason);
            this.isConnected = false;
            if (this.onDisconnect) this.onDisconnect(reason);
          });

          this.socket.on('connect_error', (error) => {
            console.error('Signaling connection error:', error);
            if (this.onError) this.onError(error);
          });

          // Ensure event listeners are setup
          this._setupCallEventListeners();
          this._setupPresenceEventListeners();
          this._setupChatEventListeners();

          return;
        }

        if (typeof io === 'undefined') {
          reject(new Error('Socket.IO not loaded'));
          return;
        }

        this.socket = io(this.config.url, {
          reconnection: this.config.reconnect,
          reconnectionDelay: this.config.reconnectionDelay,
          maxReconnectionAttempts: this.config.maxReconnectionAttempts,
          transports: ['websocket', 'polling']
        });

        // Connection events
        this.socket.on('connect', () => {
          console.log('Signaling connected:', this.socket.id);
          this.isConnected = true;
          this.reconnectAttempts = 0;

          // Register user
          this.emit('register_user', { user_id: userId });

          // Process queued messages
          this._processMessageQueue();

          if (this.onConnect) {
            this.onConnect();
          }

          resolve();
        });

        this.socket.on('disconnect', (reason) => {
          console.log('Signaling disconnected:', reason);
          this.isConnected = false;

          if (this.onDisconnect) {
            this.onDisconnect(reason);
          }
        });

        this.socket.on('connect_error', (error) => {
          console.error('Signaling connection error:', error);
          if (this.onError) {
            this.onError(error);
          }
        });

        // Setup event listeners for call signaling
        this._setupCallEventListeners();
        this._setupPresenceEventListeners();
        this._setupChatEventListeners();

      } catch (error) {
        reject(error);
      }
    });
  }

  /**
   * Setup call-related event listeners
   */
  _setupCallEventListeners() {
    // Incoming call notification
    this.on('call:ringing', (data) => {
      this._handleEvent('onIncomingCall', data);
    });

    // Call accepted by callee
    this.on('call:accepted', (data) => {
      this._handleEvent('onCallAccepted', data);
    });

    // Call declined
    this.on('call:declined', (data) => {
      this._handleEvent('onCallDeclined', data);
    });

    // Call busy
    this.on('call:busy', (data) => {
      this._handleEvent('onCallBusy', data);
    });

    // Call connected (media established)
    this.on('call:connected', (data) => {
      this._handleEvent('onCallConnected', data);
    });

    // Call ended
    this.on('call:ended', (data) => {
      this._handleEvent('onCallEnded', data);
    });

    // Call missed
    this.on('call:missed', (data) => {
      this._handleEvent('onCallMissed', data);
    });

    // WebRTC offer
    this.on('webrtc:offer', (data) => {
      this._handleEvent('onWebRTCOffer', data);
    });

    // WebRTC answer
    this.on('webrtc:answer', (data) => {
      this._handleEvent('onWebRTCAnswer', data);
    });

    // ICE candidate
    this.on('webrtc:ice', (data) => {
      this._handleEvent('onWebRTCIce', data);
    });

    // Call error
    this.on('call:error', (data) => {
      this._handleEvent('onCallError', data);
    });
  }

  /**
   * Setup presence-related event listeners
   */
  _setupPresenceEventListeners() {
    // User presence update
    this.on('presence:update', (data) => {
      this._handleEvent('onPresenceUpdate', data);
    });

    // User online
    this.on('user:online', (data) => {
      this._handleEvent('onUserOnline', data);
    });

    // User offline
    this.on('user:offline', (data) => {
      this._handleEvent('onUserOffline', data);
    });
  }

  /**
   * Setup chat-related event listeners
   */
  _setupChatEventListeners() {
    // Incoming message
    this.on('chat:message', (data) => {
      this._handleEvent('onChatMessage', data);
    });

    // Message delivered
    this.on('chat:delivered', (data) => {
      this._handleEvent('onMessageDelivered', data);
    });

    // Message read
    this.on('chat:read', (data) => {
      this._handleEvent('onMessageRead', data);
    });

    // Typing indicator
    this.on('chat:typing', (data) => {
      this._handleEvent('onTyping', data);
    });
  }

  /**
   * Emit event to server
   */
  emit(event, data) {
    if (this.isConnected && this.socket) {
      this.socket.emit(event, data);
    } else {
      // Queue message if not connected
      this.messageQueue.push({ event, data, timestamp: Date.now() });
    }
  }

  /**
   * Listen for event from server
   */
  on(event, callback) {
    if (!this.socket) {
      console.warn('Socket not initialized');
      return;
    }

    this.socket.on(event, callback);
  }

  /**
   * Register event handler
   */
  addEventListener(eventName, handler) {
    if (!this.eventHandlers[eventName]) {
      this.eventHandlers[eventName] = [];
    }
    this.eventHandlers[eventName].push(handler);
  }

  /**
   * Remove event handler
   */
  removeEventListener(eventName, handler) {
    if (this.eventHandlers[eventName]) {
      this.eventHandlers[eventName] = this.eventHandlers[eventName].filter(h => h !== handler);
    }
  }

  /**
   * Call event handlers
   */
  _handleEvent(eventName, data) {
    if (this.eventHandlers[eventName]) {
      this.eventHandlers[eventName].forEach(handler => {
        try {
          handler(data);
        } catch (error) {
          console.error(`Error in ${eventName} handler:`, error);
        }
      });
    }
  }

  /**
   * Process queued messages
   */
  _processMessageQueue() {
    while (this.messageQueue.length > 0) {
      const { event, data } = this.messageQueue.shift();
      this.socket.emit(event, data);
    }
  }

  // ============================================
  // CALL SIGNALING METHODS
  // ============================================

  /**
   * Initiate a call (caller)
   */
  initiateCall(calleeId, appointmentId, callType = 'video') {
    this.emit('initiate_call', {
      caller_id: this.userId,
      callee_id: calleeId,
      appointment_id: appointmentId,
      call_type: callType
    });
  }

  /**
   * Accept incoming call (callee)
   */
  acceptCall(callId, appointmentId = null) {
    const payload = {
      call_id: callId,
      user_id: this.userId
    };
    if (appointmentId) payload.appointment_id = appointmentId;
    this.emit('accept_call', payload);
  }

  /**
   * Decline incoming call (callee)
   */
  declineCall(callId, reason = 'user_declined', appointmentId = null) {
    const payload = {
      call_id: callId,
      reason: reason
    };
    if (appointmentId) payload.appointment_id = appointmentId;
    this.emit('decline_call', payload);
  }

  /**
   * Hangup active call
   */
  hangupCall(callId, reason = 'user_hangup', appointmentId = null) {
    const payload = {
      call_id: callId,
      reason: reason
    };
    if (appointmentId) payload.appointment_id = appointmentId;
    this.emit('hangup_call', payload);
  }

  /**
   * Send WebRTC offer
   */
  sendOffer(callId, offer, appointmentId = null) {
    const payload = { call_id: callId, offer: offer };
    if (appointmentId) payload.appointment_id = appointmentId;
    this.emit('webrtc:offer', payload);
  }

  /**
   * Send WebRTC answer
   */
  sendAnswer(callId, answer, appointmentId = null) {
    const payload = { call_id: callId, answer: answer };
    if (appointmentId) payload.appointment_id = appointmentId;
    this.emit('webrtc:answer', payload);
  }

  /**
   * Send ICE candidate
   */
  sendIceCandidate(callId, candidate, appointmentId = null) {
    const payload = { call_id: callId, candidate: candidate };
    if (appointmentId) payload.appointment_id = appointmentId;
    this.emit('webrtc:ice', payload);
  }

  /**
   * Send call quality metrics
   */
  sendQualityMetrics(callId, metrics) {
    this.emit('call:stats', {
      call_id: callId,
      metrics: metrics
    });
  }

  // ============================================
  // PRESENCE METHODS
  // ============================================

  /**
   * Update presence status
   */
  updatePresence(status, callId = null, appointmentId = null) {
    this.emit('presence:update', {
      user_id: this.userId,
      status: status,  // 'online', 'away', 'idle', 'busy', 'offline'
      current_call_id: callId,
      current_appointment_id: appointmentId,
      timestamp: new Date().toISOString()
    });
  }

  /**
   * Go online
   */
  setOnline() {
    this.updatePresence('online');
  }

  /**
   * Go away
   */
  setAway() {
    this.updatePresence('away');
  }

  /**
   * Go busy
   */
  setBusy(callId, appointmentId) {
    this.updatePresence('busy', callId, appointmentId);
  }

  /**
   * Go offline
   */
  setOffline() {
    this.updatePresence('offline');
  }

  // ============================================
  // CHAT METHODS
  // ============================================

  /**
   * Send message
   */
  sendMessage(conversationId, callId, body, attachmentIds = []) {
    this.emit('chat:message', {
      conversation_id: conversationId,
      call_id: callId,
      sender_id: this.userId,
      body: body,
      attachment_ids: attachmentIds,
      timestamp: new Date().toISOString()
    });
  }

  /**
   * Mark message as delivered
   */
  markDelivered(messageId) {
    this.emit('chat:delivered', {
      message_id: messageId
    });
  }

  /**
   * Mark message as read
   */
  markRead(messageId) {
    this.emit('chat:read', {
      message_id: messageId
    });
  }

  /**
   * Send typing indicator
   */
  sendTyping(conversationId) {
    this.emit('chat:typing', {
      conversation_id: conversationId,
      user_id: this.userId
    });
  }

  // ============================================
  // CONNECTION MANAGEMENT
  // ============================================

  /**
   * Disconnect from signaling server
   */
  disconnect() {
    if (this.socket) {
      this.socket.disconnect();
      this.isConnected = false;
    }
  }

  /**
   * Get connection status
   */
  getConnectionStatus() {
    return {
      connected: this.isConnected,
      socketId: this.socket ? this.socket.id : null,
      userId: this.userId,
      messageQueueLength: this.messageQueue.length
    };
  }

  /**
   * Force reconnect
   */
  reconnect() {
    if (this.socket) {
      this.socket.connect();
    }
  }

  /**
   * Check if connected
   */
  isSocketConnected() {
    return this.isConnected && this.socket && this.socket.connected;
  }
  }

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
  module.exports = SignalingClient;
}

// Attach to window for global access
window.SignalingClient = SignalingClient;
