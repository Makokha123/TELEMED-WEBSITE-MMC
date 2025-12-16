/**
 * Signaling Client for Socket.IO
 * Minimal, defensive implementation used by CallManager and other scripts.
 * Provides: constructor(socketOrConfig), connect(userId), emit, on,
 * addEventListener, removeEventListener, isSocketConnected, disconnect.
 */
(function(global){
  'use strict';

  class SignalingClient {
    constructor(config = {}) {
      const isSocketInstance = config && typeof config.on === 'function' && typeof config.emit === 'function';
      if (isSocketInstance) {
        this.socket = config;
        this.config = { url: '', reconnect: true, reconnectionDelay: 1000, maxReconnectionAttempts: 10 };
        this.isConnected = !!this.socket.connected;
      } else {
        this.config = Object.assign({ url: '', reconnect: true, reconnectionDelay: 1000, maxReconnectionAttempts: 10 }, config);
        this.socket = null;
        this.isConnected = false;
      }

      this.userId = null;
      this.messageQueue = [];
      this.eventHandlers = {}; // handlers registered via addEventListener
      this.deferredSocketListeners = []; // listeners registered via on() before socket exists
      this.onConnect = null;
      this.onDisconnect = null;
      this.onError = null;
    }

    connect(userId) {
      const self = this;
      return new Promise((resolve, reject) => {
        try {
          this.userId = userId;

          if (this.socket) {
            // attach deferred listeners
            this._attachDeferredListeners();
            if (this.socket.connected) {
              this.isConnected = true;
              this._registerUser();
              this._processMessageQueue();
              if (this.onConnect) this.onConnect();
              resolve();
              return;
            }

            this.socket.once('connect', () => {
              self.isConnected = true;
              self._registerUser();
              self._processMessageQueue();
              if (self.onConnect) self.onConnect();
              resolve();
            });

            this.socket.on('disconnect', (reason) => {
              self.isConnected = false;
              if (self.onDisconnect) self.onDisconnect(reason);
            });

            this.socket.on('connect_error', (err) => {
              if (self.onError) self.onError(err);
            });

            // bind core signaling events to our handler
            this._setupCoreListeners();
            return;
          }

          if (typeof io === 'undefined') {
            reject(new Error('Socket.IO (io) is not available in the page'));
            return;
          }

          this.socket = io(this.config.url || undefined, {
            reconnection: this.config.reconnect,
            reconnectionDelay: this.config.reconnectionDelay,
            maxReconnectionAttempts: this.config.maxReconnectionAttempts,
            transports: ['websocket', 'polling']
          });

          this.socket.once('connect', () => {
            self.isConnected = true;
            self._attachDeferredListeners();
            self._registerUser();
            self._processMessageQueue();
            if (self.onConnect) self.onConnect();
            resolve();
          });

          this.socket.on('disconnect', (reason) => {
            self.isConnected = false;
            if (self.onDisconnect) self.onDisconnect(reason);
          });

          this.socket.on('connect_error', (err) => {
            if (self.onError) self.onError(err);
          });

          this._setupCoreListeners();
        } catch (err) {
          reject(err);
        }
      });
    }

    _registerUser() {
      try {
        if (this.userId && this.socket && this.socket.emit) {
          this.emit('register_user', { user_id: this.userId });
        }
      } catch (e) { /* ignore */ }
    }

    _attachDeferredListeners() {
      if (!this.socket) return;
      this.deferredSocketListeners.forEach(({event, cb}) => {
        try { this.socket.on(event, cb); } catch(e){}
      });
      this.deferredSocketListeners = [];
    }

    _setupCoreListeners() {
      if (!this.socket) return;
      const map = ['call:ringing','call:accepted','call:declined','call:busy','call:connected','call:ended','call:missed','webrtc:offer','webrtc:answer','webrtc:ice','call:error','presence:update','user:online','user:offline','chat:message','chat:delivered','chat:read','chat:typing'];
      map.forEach(ev => {
        try {
          this.socket.on(ev, (data) => { this._handleEvent(ev, data); });
        } catch (e) {}
      });
    }

    emit(event, data) {
      if (this.isConnected && this.socket && typeof this.socket.emit === 'function') {
        try { this.socket.emit(event, data); } catch (e) { this.messageQueue.push({event,data}); }
      } else {
        this.messageQueue.push({event,data});
      }
    }

    on(event, callback) {
      if (this.socket && typeof this.socket.on === 'function') {
        try { this.socket.on(event, callback); } catch(e){ this.deferredSocketListeners.push({event,cb:callback}); }
      } else {
        this.deferredSocketListeners.push({event, cb: callback});
      }
    }

    addEventListener(name, handler) {
      if (!this.eventHandlers[name]) this.eventHandlers[name] = [];
      this.eventHandlers[name].push(handler);
    }

    removeEventListener(name, handler) {
      if (!this.eventHandlers[name]) return;
      this.eventHandlers[name] = this.eventHandlers[name].filter(h => h !== handler);
    }

    _handleEvent(name, data) {
      // Call explicit eventHandlers
      if (this.eventHandlers[name]) {
        this.eventHandlers[name].forEach(h => {
          try { h(data); } catch(e) { console.error('Signaling handler error', e); }
        });
      }
      // Also emit generic 'message' event if registered
      if (this.eventHandlers['message']) {
        this.eventHandlers['message'].forEach(h => { try { h({ event: name, data }); } catch(e){} });
      }
    }

    _processMessageQueue() {
      while (this.messageQueue.length > 0) {
        const {event, data} = this.messageQueue.shift();
        try { if (this.socket && this.socket.emit) this.socket.emit(event, data); } catch(e) {}
      }
    }

    disconnect() {
      try { if (this.socket && this.socket.disconnect) this.socket.disconnect(); } catch(e){}
      this.isConnected = false;
    }

    isSocketConnected() {
      return !!(this.isConnected && this.socket && this.socket.connected);
    }
  }

  // Export safely
  try {
    if (typeof module !== 'undefined' && module.exports) module.exports = SignalingClient;
  } catch(e){}
  try { if (global) global.SignalingClient = SignalingClient; } catch(e){}

})(typeof window !== 'undefined' ? window : this);


