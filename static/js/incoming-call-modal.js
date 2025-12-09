// incoming-call-modal.js
// Shows an incoming call modal and integrates actions with window.callManager and window.socket
(function(){
  function ensureModal(){
    let el = document.getElementById('incomingCallModal');
    if (el) return el;
    // Modal markup (Bootstrap 5)
    const div = document.createElement('div');
    div.innerHTML = `
<div class="modal fade" id="incomingCallModal" tabindex="-1" aria-hidden="true">
  <div class="modal-dialog modal-dialog-centered">
    <div class="modal-content">
      <div class="modal-body">
        <div class="d-flex align-items-center">
          <img id="incomingCallerAvatar" src="/static/img/default-avatar.png" style="height:56px;width:56px;border-radius:50%;object-fit:cover;margin-right:12px;" />
          <div>
            <div id="incomingCallerName" style="font-weight:700;font-size:16px;">Incoming Call</div>
            <div id="incomingCallerMeta" class="text-muted" style="font-size:13px;">Video Call</div>
          </div>
        </div>
      </div>
      <div class="modal-footer d-flex justify-content-between">
        <div>
          <button id="declineCallBtn" class="btn btn-outline-danger">Decline</button>
        </div>
        <div>
          <button id="acceptCallBtn" class="btn btn-success">Accept</button>
        </div>
      </div>
    </div>
  </div>
</div>
    `;
    document.body.appendChild(div);
    return document.getElementById('incomingCallModal');
  }

  function showIncomingCall(callInfo){
    try{
      const modalEl = ensureModal();
      // populate fields
      const name = callInfo.caller_name || callInfo.initiator_name || 'Caller';
      const meta = (callInfo.call_type || 'video').toUpperCase() + ' CALL';
      const avatar = callInfo.caller_profile_picture || '/static/img/default-avatar.png';
      document.getElementById('incomingCallerName').textContent = name;
      document.getElementById('incomingCallerMeta').textContent = meta;
      document.getElementById('incomingCallerAvatar').src = avatar;

      // wire buttons
      const accept = document.getElementById('acceptCallBtn');
      const decline = document.getElementById('declineCallBtn');
      const modal = new bootstrap.Modal(modalEl, { backdrop: 'static', keyboard: false });
      // Ringtone via Web Audio API (best-effort). Some browsers block autoplay until user gesture.
      let audioCtx = null, osc = null, gain = null, ringInterval = null;
      function startRingtone(){
        try{
          if (window._incomingRingPlaying) return;
          audioCtx = new (window.AudioContext || window.webkitAudioContext)();
          osc = audioCtx.createOscillator();
          gain = audioCtx.createGain();
          osc.type = 'sine';
          osc.frequency.setValueAtTime(620, audioCtx.currentTime);
          gain.gain.setValueAtTime(0, audioCtx.currentTime);
          osc.connect(gain); gain.connect(audioCtx.destination);
          osc.start();
          // beep pattern: 1s on, 1s off
          ringInterval = setInterval(()=>{
            try{ gain.gain.cancelScheduledValues(audioCtx.currentTime); gain.gain.setValueAtTime(0.0001, audioCtx.currentTime); gain.gain.linearRampToValueAtTime(0.8, audioCtx.currentTime + 0.02); setTimeout(()=>{ try{ gain.gain.linearRampToValueAtTime(0.0001, audioCtx.currentTime + 0.9); }catch(e){} }, 900); }catch(e){}
          }, 1000);
          // immediate first beep
          gain.gain.setValueAtTime(0.0001, audioCtx.currentTime); gain.gain.linearRampToValueAtTime(0.8, audioCtx.currentTime + 0.02);
          setTimeout(()=>{ try{ gain.gain.linearRampToValueAtTime(0.0001, audioCtx.currentTime + 0.02); }catch(e){} }, 900);
          window._incomingRingPlaying = true;
        }catch(e){ console.warn('startRingtone failed', e); }
      }
      function stopRingtone(){
        try{
          if (ringInterval) { clearInterval(ringInterval); ringInterval = null; }
          if (osc) try{ osc.stop(); }catch(e){}
          if (audioCtx) try{ audioCtx.close(); }catch(e){}
        }catch(e){}
        window._incomingRingPlaying = false;
      }

      // auto-start ringtone
      startRingtone();
      // ensure ringtone stops when modal hidden
      modalEl.addEventListener('hidden.bs.modal', ()=>{ stopRingtone(); });

      accept.onclick = function(ev){
        ev.preventDefault();
        stopRingtone();
        modal.hide();
        try{
          // Prefer CallManager to handle the flow (attach to existing PeerConnection)
          if (window.callManager && typeof window.callManager.acceptIncoming === 'function'){
            window.callManager.acceptIncoming(callInfo);
            return;
          }
          // If not available, navigate to the dedicated call page so the app initializes call UI
          if (callInfo && callInfo.appointment_id){
            // open same tab
            const url = '/video-call/' + encodeURIComponent(callInfo.appointment_id);
            window.location.href = url;
            return;
          }
          // last-resort: emit accept via socket
          if (window.socket){
            const uid = window.currentUserId || window.__currentUserId || '';
            window.socket.emit('accept_video_call', { call_id: callInfo.id, appointment_id: callInfo.appointment_id, user_id: uid });
          }
        }catch(e){ console.warn('accept handler failed', e); }
      };
      decline.onclick = function(ev){
        ev.preventDefault();
        stopRingtone();
        modal.hide();
        try{
          if (window.callManager && typeof window.callManager.rejectIncoming === 'function'){
            window.callManager.rejectIncoming(callInfo);
            return;
          }
          if (window.socket){
            const uid = window.currentUserId || window.__currentUserId || '';
            window.socket.emit('reject_video_call', { call_id: callInfo.id, appointment_id: callInfo.appointment_id, reason: 'rejected', user_id: uid });
          }
        }catch(e){ console.warn('reject handler failed', e); }
      };

      // Auto-dismiss modal after 60 seconds and emit unanswered/reject
      const AUTO_TIMEOUT_MS = (callInfo.timeout_ms && parseInt(callInfo.timeout_ms)) || 60000;
      const autoTimer = setTimeout(()=>{
        try{
          stopRingtone();
          modal.hide();
          if (window.socket){
            const uid = window.currentUserId || window.__currentUserId || '';
            window.socket.emit('reject_video_call', { call_id: callInfo.id, appointment_id: callInfo.appointment_id, reason: 'unanswered', user_id: uid });
          }
        }catch(e){ console.warn('auto-dismiss handler failed', e); }
      }, AUTO_TIMEOUT_MS);
      // Clear timeout if user responds
      modalEl.addEventListener('hidden.bs.modal', ()=>{ try{ clearTimeout(autoTimer); }catch(e){} });

      // Stop ringtone and hide if server notifies call ended/accepted/rejected for this call id
      try{
        if (window.socket){
          const onEnd = function(payload){
            try{
              if (!payload) return;
              const ids = [payload.call_id, payload.appointment_id, payload.id];
              if (ids.indexOf(callInfo.id) !== -1 || ids.indexOf(callInfo.appointment_id) !== -1) {
                stopRingtone();
                try{ modal.hide(); }catch(e){}
              }
            }catch(e){}
          };
          window.socket.on('video_call_accepted', onEnd);
          window.socket.on('video_call_rejected', onEnd);
          window.socket.on('video_call_unanswered', onEnd);
          window.socket.on('video_call_ended', onEnd);
          // remove listeners when modal hidden
          modalEl.addEventListener('hidden.bs.modal', function(){ try{ window.socket.off('video_call_accepted', onEnd); window.socket.off('video_call_rejected', onEnd); window.socket.off('video_call_unanswered', onEnd); window.socket.off('video_call_ended', onEnd); }catch(e){} });
        }
      }catch(e){ console.warn('socket end-listener attach failed', e); }

      modal.show();

    }catch(e){ console.warn('showIncomingCall failed', e); }
  }

  // Expose helper
  window.IncomingCallModal = { show: showIncomingCall };

  // Listen for incoming call socket event and show modal
  if (window.socket) {
    window.socket.on('incoming_video_call', function(data){
      try{ window.IncomingCallModal.show(data); }catch(e){ console.warn('incoming_video_call handler failed', e); }
    });
  }
})();
