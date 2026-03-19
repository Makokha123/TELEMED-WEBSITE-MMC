/**
 * consultation-room.js
 * Full state-machine + multi-peer-mesh WebRTC for the Consultation Room.
 *
 * States: locked → lobby → active → ended
 */

(function () {
    'use strict';

    /* ── Read configuration from <meta name="app-data"> ─────────────── */
    const meta = document.querySelector('meta[name="app-data"]');
    function d(key) {
        return meta ? meta.getAttribute('data-' + key) || '' : '';
    }

    const APPOINTMENT_ID   = parseInt(d('appointment-id'), 10);
    const MY_USER_ID       = parseInt(d('current-user-id'), 10);
    const MY_ROLE          = d('current-user-role');          // doctor|patient|admin
    const MY_NAME          = d('current-user-name');
    const MY_PIC           = d('current-user-pic');
    const DOCTOR_USER_ID   = parseInt(d('doctor-user-id'), 10);
    const OBSERVE_MODE     = d('observe-mode') === '1';
    const PAYMENT_STATUS   = d('payment-status');
    const CSRF_TOKEN       = document.querySelector('meta[name="csrf-token"]')?.content || '';

    let roomStatus        = d('room-status');                 // waiting|active|ended
    let roomIsOpen        = d('room-is-open') === '1';
    let secondsUntilUnlock = parseInt(d('seconds-until-unlock'), 10) || 0;
    let isGroupSession    = d('is-group') === '1';

    /* ── DOM refs ────────────────────────────────────────────────────── */
    const screens = {
        locked: document.getElementById('screenLocked'),
        lobby:  document.getElementById('screenLobby'),
        room:   document.getElementById('screenRoom'),
        ended:  document.getElementById('screenEnded'),
    };

    /* ── App state ───────────────────────────────────────────────────── */
    let socket            = null;
    let localStream       = null;
    let screenStream      = null;
    let peers             = {};       // { userId: RTCPeerConnection }
    let peerStates        = {};       // { userId: { audio, video, name, pic } }
    let isMicOn           = true;
    let isCamOn           = true;
    let isScreenSharing   = false;
    let isHandRaised      = false;
    let sessionStartTime  = null;
    let sessionTimerInterval = null;
    let lockedPollInterval   = null;
    let lockedCountdownInterval = null;
    let notesSaveTimeout  = null;
    let unreadChat        = 0;
    let activePanel       = 'chat';
    let mediaRecorder     = null;
    let recordedChunks    = [];
    let isSelfRecording   = false;
    const wbState         = { drawing: false, color: '#1a1a1a', size: 3, erasing: false };

    const ICE_SERVERS = [
        { urls: 'stun:stun.l.google.com:19302' },
        { urls: 'stun:stun1.l.google.com:19302' },
    ];

    /* ════════════════════════════════════════════════════════════════
       SCREEN MANAGEMENT
    ════════════════════════════════════════════════════════════════ */
    function showScreen(name) {
        Object.entries(screens).forEach(([k, el]) => {
            if (el) el.classList.toggle('active', k === name);
        });
    }

    /* ════════════════════════════════════════════════════════════════
       INIT — entry point
    ════════════════════════════════════════════════════════════════ */
    function init() {
        if (roomStatus === 'ended') {
            showScreen('ended');
            document.getElementById('endedByMessage').textContent = 'This consultation has already ended.';
            return;
        }

        if (!roomIsOpen || PAYMENT_STATUS !== 'paid') {
            initLockedScreen();
            return;
        }

        initLobby();
    }

    /* ════════════════════════════════════════════════════════════════
       LOCKED SCREEN
    ════════════════════════════════════════════════════════════════ */
    function initLockedScreen() {
        showScreen('locked');
        const payBadge = document.getElementById('paymentBadge');
        const countdownWrapper = document.getElementById('countdownWrapper');
        const payNotice = document.getElementById('paymentRequiredNotice');
        const subtitle = document.getElementById('lockedSubtitle');

        if (PAYMENT_STATUS !== 'paid') {
            if (payBadge) { payBadge.textContent = '⚠ Payment Required'; payBadge.className = 'cr-payment-badge unpaid'; }
            if (payNotice) { payNotice.style.display = ''; payNotice.className = 'alert alert-danger'; }
            if (subtitle) subtitle.textContent = 'Payment is required to access this room.';
        } else {
            if (payBadge) { payBadge.textContent = '✓ Paid'; payBadge.className = 'cr-payment-badge paid'; }
            if (subtitle) subtitle.textContent = 'This room is not yet open. Check back when your appointment time approaches.';

            if (secondsUntilUnlock > 0) {
                if (countdownWrapper) countdownWrapper.style.display = '';
                startLockedCountdown(secondsUntilUnlock);
            }
            startLockedPoll();
        }

        document.getElementById('btnRefreshStatus')?.addEventListener('click', pollRoomStatus);
    }

    function startLockedCountdown(seconds) {
        let remaining = seconds;
        const display = document.getElementById('countdownDisplay');
        if (!display) return;

        function tick() {
            if (remaining <= 0) {
                display.textContent = 'Opening…';
                clearInterval(lockedCountdownInterval);
                pollRoomStatus();
                return;
            }
            const h = Math.floor(remaining / 3600);
            const m = Math.floor((remaining % 3600) / 60);
            const s = remaining % 60;
            display.textContent = h > 0
                ? `${String(h).padStart(2,'0')}:${String(m).padStart(2,'0')}:${String(s).padStart(2,'0')}`
                : `${String(m).padStart(2,'0')}:${String(s).padStart(2,'0')}`;
            remaining--;
        }
        tick();
        lockedCountdownInterval = setInterval(tick, 1000);
    }

    function startLockedPoll() {
        lockedPollInterval = setInterval(pollRoomStatus, 30000);
    }

    function pollRoomStatus() {
        fetch(`/api/consultation-room/${APPOINTMENT_ID}/status`, {
            headers: { 'X-CSRFToken': CSRF_TOKEN, 'Accept': 'application/json' },
            credentials: 'same-origin',
        })
        .then(r => r.json())
        .then(data => {
            if (data.is_open && data.payment_status === 'paid') {
                clearInterval(lockedPollInterval);
                clearInterval(lockedCountdownInterval);
                roomIsOpen = true;
                PAYMENT_STATUS === 'paid';
                roomStatus = data.status;
                initLobby();
            }
        })
        .catch(() => {/* silent – will retry */});
    }

    /* ════════════════════════════════════════════════════════════════
       PRE-ROOM LOBBY
    ════════════════════════════════════════════════════════════════ */
    function initLobby() {
        showScreen('lobby');

        const subtitle = document.getElementById('lobbySubtitle');

        // Observer mode (admin silent join): skip media, go straight to join
        if (OBSERVE_MODE) {
            if (subtitle) subtitle.textContent = 'You are joining as a silent observer. Participants will not see or hear you.';
            isMicOn = false;
            isCamOn = false;
            localStream = null;
            const previewVid = document.getElementById('previewVideo');
            if (previewVid) previewVid.style.display = 'none';
            // Hide lobby controls for observer
            document.getElementById('btnLobbyMicToggle')?.style && (document.getElementById('btnLobbyMicToggle').style.display = 'none');
            document.getElementById('btnLobbyCamToggle')?.style && (document.getElementById('btnLobbyCamToggle').style.display = 'none');
            // Auto-join after brief delay
            setTimeout(joinRoom, 500);
            return;
        }

        if (subtitle) {
            subtitle.textContent = MY_ROLE === 'doctor'
                ? 'Request camera & microphone access, then join.'
                : 'Your doctor is ready. Request access & join below.';
        }

        // Camera preview
        navigator.mediaDevices.getUserMedia({ video: true, audio: true })
            .then(stream => {
                localStream = stream;
                const previewVid = document.getElementById('previewVideo');
                if (previewVid) { previewVid.srcObject = stream; }
                document.getElementById('pipName').textContent = MY_NAME.split(' ')[0] || 'You';
            })
            .catch(() => {
                // No camera — allow text-only
                localStream = null;
                isCamOn = false;
                isMicOn = false;
                const previewVid = document.getElementById('previewVideo');
                if (previewVid) previewVid.style.display = 'none';
            });

        document.getElementById('btnLobbyMicToggle')?.addEventListener('click', toggleLobbyMic);
        document.getElementById('btnLobbyCamToggle')?.addEventListener('click', toggleLobbyCam);
        document.getElementById('btnJoinRoom')?.addEventListener('click', joinRoom);
    }

    function toggleLobbyMic() {
        if (!localStream) return;
        isMicOn = !isMicOn;
        localStream.getAudioTracks().forEach(t => { t.enabled = isMicOn; });
        const btn = document.getElementById('btnLobbyMicToggle');
        if (btn) btn.innerHTML = isMicOn
            ? '<i class="fas fa-microphone"></i> Mic On'
            : '<i class="fas fa-microphone-slash"></i> Mic Off';
    }

    function toggleLobbyCam() {
        if (!localStream) return;
        isCamOn = !isCamOn;
        localStream.getVideoTracks().forEach(t => { t.enabled = isCamOn; });
        const btn = document.getElementById('btnLobbyCamToggle');
        if (btn) btn.innerHTML = isCamOn
            ? '<i class="fas fa-video"></i> Camera On'
            : '<i class="fas fa-video-slash"></i> Camera Off';
    }

    /* ════════════════════════════════════════════════════════════════
       JOIN ROOM → connect Socket.IO
    ════════════════════════════════════════════════════════════════ */
    function joinRoom() {
        const btn = document.getElementById('btnJoinRoom');
        if (btn) { btn.disabled = true; btn.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Joining…'; }

        // Connect socket if not already connected
        if (!socket) {
            socket = io({ transports: ['websocket', 'polling'] });
            bindSocketEvents();
        }

        socket.emit('join_consultation_room', { appointment_id: APPOINTMENT_ID, observer: OBSERVE_MODE });
    }

    /* ════════════════════════════════════════════════════════════════
       SOCKET.IO EVENTS
    ════════════════════════════════════════════════════════════════ */
    function bindSocketEvents() {
        socket.on('connect', () => {
            console.log('[CR] Socket connected');
        });

        socket.on('disconnect', () => {
            console.warn('[CR] Socket disconnected');
            // Attempt graceful re-join after brief pause
            setTimeout(() => {
                if (socket && roomStatus !== 'ended') {
                    socket.emit('join_consultation_room', { appointment_id: APPOINTMENT_ID, observer: OBSERVE_MODE });
                }
            }, 3000);
        });

        socket.on('consultation_room_joined', onRoomJoined);
        socket.on('participant_joined', onParticipantJoined);
        socket.on('participant_left', onParticipantLeft);
        socket.on('consultation_room_ended', onRoomEnded);
        socket.on('recording_consent_update', onRecordingConsentUpdate);

        // WebRTC signalling
        socket.on('consultation_webrtc_offer', onWebRtcOffer);
        socket.on('consultation_webrtc_answer', onWebRtcAnswer);
        socket.on('consultation_webrtc_ice', onWebRtcIce);

        // In-room features
        socket.on('consultation_chat_message', onChatMessage);
        socket.on('consultation_whiteboard', onWhiteboardEvent);
        socket.on('consultation_media_state', onMediaState);
        socket.on('consultation_raise_hand', onRaiseHand);
    }

    /* ── Room Joined ─────────────────────────────────────────────── */
    function onRoomJoined(data) {
        roomStatus = data.room.status;

        showScreen('room');

        // Attach local stream (observers have none)
        const localVid = document.getElementById('localVideo');
        if (localVid && localStream) localVid.srcObject = localStream;

        // Hide local PiP for observers
        if (OBSERVE_MODE) {
            const pip = document.getElementById('localPip');
            if (pip) pip.style.display = 'none';
            // Hide control buttons that don't apply to observers
            ['btnMic', 'btnCam', 'btnScreenShare', 'btnRaiseHand', 'btnRecord', 'btnMarkComplete'].forEach(id => {
                const el = document.getElementById(id);
                if (el) el.style.display = 'none';
            });
        }

        // Seed existing participants
        (data.participants || []).forEach(p => {
            if (p.user_id !== MY_USER_ID && !p.observer) {
                peerStates[p.user_id] = p;
                addParticipantTile(p);
                // Observers don't initiate offers — they wait for offers from peers
                if (!OBSERVE_MODE) {
                    initiateWebRtcOffer(p.user_id);
                }
            }
        });

        updateParticipantsList();
        startSessionTimer();
        initControls();
        initSidebar();
        initWhiteboard();
        makePipDraggable();

        // Restore notes if doctor
        const notesArea = document.getElementById('sessionNotesArea');
        if (notesArea && data.room.session_notes) notesArea.value = data.room.session_notes;

        // Auto-start recording for all participants (captured locally)
        startAutoRecording();
    }

    /* ── Participant Joined ──────────────────────────────────────── */
    function onParticipantJoined(data) {
        const p = data.participant;
        if (p.user_id === MY_USER_ID || p.observer) return;

        peerStates[p.user_id] = p;
        addParticipantTile(p);
        updateParticipantsList();
        // Observers wait for incoming offers instead of initiating
        if (!OBSERVE_MODE) {
            initiateWebRtcOffer(p.user_id);
        }

        appendSystemMessage(`${p.display_name} joined the consultation.`);
    }

    /* ── Participant Left ────────────────────────────────────────── */
    function onParticipantLeft(data) {
        const userId = data.user_id;
        removePeerTile(userId);
        if (peers[userId]) { peers[userId].close(); delete peers[userId]; }
        delete peerStates[userId];
        updateParticipantsList();
        appendSystemMessage(`${data.display_name || 'Participant'} left the consultation.`);
    }

    /* ── Room Ended ──────────────────────────────────────────────── */
    function onRoomEnded(data) {
        roomStatus = 'ended';
        stopAutoRecording().then(() => {
            uploadRecording();
        });
        cleanupMedia();

        const dur = document.getElementById('endedDuration');
        if (dur && sessionStartTime) dur.textContent = formatDuration(Math.floor((Date.now() - sessionStartTime) / 1000));
        const byMsg = document.getElementById('endedByMessage');
        if (byMsg) byMsg.textContent = data.ended_by ? `Ended by ${data.ended_by}` : 'The session has ended.';

        showScreen('ended');
    }

    /* ── Recording Consent Update ────────────────────────────────── */
    function onRecordingConsentUpdate(data) {
        const both = data.doctor_consented && data.patient_consented;
        const recInd = document.getElementById('recordingIndicator');
        if (recInd) recInd.classList.toggle('active', both);
    }

    /* ════════════════════════════════════════════════════════════════
       WebRTC — multi-peer mesh
    ════════════════════════════════════════════════════════════════ */
    function createPeerConnection(targetUserId) {
        if (peers[targetUserId]) peers[targetUserId].close();

        const pc = new RTCPeerConnection({ iceServers: ICE_SERVERS });
        peers[targetUserId] = pc;

        // Add local tracks only if not in observer mode
        if (localStream && !OBSERVE_MODE) {
            localStream.getTracks().forEach(t => pc.addTrack(t, localStream));
        } else if (OBSERVE_MODE) {
            // Observer: add receive-only transceivers so remote media arrives
            pc.addTransceiver('audio', { direction: 'recvonly' });
            pc.addTransceiver('video', { direction: 'recvonly' });
        }

        // Remote stream → video tile
        const remoteStream = new MediaStream();
        pc.ontrack = e => {
            remoteStream.addTrack(e.track);
            const vid = document.querySelector(`#peer-tile-${targetUserId} video`);
            if (vid) vid.srcObject = remoteStream;
        };

        // ICE candidates
        pc.onicecandidate = e => {
            if (e.candidate) {
                socket.emit('consultation_webrtc_ice', {
                    appointment_id: APPOINTMENT_ID,
                    target_user_id: targetUserId,
                    candidate: e.candidate,
                });
            }
        };

        // Connection state
        pc.onconnectionstatechange = () => {
            if (['disconnected', 'failed', 'closed'].includes(pc.connectionState)) {
                removePeerTile(targetUserId);
            }
            updateQuality();
        };

        return pc;
    }

    function initiateWebRtcOffer(targetUserId) {
        const pc = createPeerConnection(targetUserId);
        ensurePeerTile(targetUserId);

        pc.createOffer()
            .then(offer => pc.setLocalDescription(offer))
            .then(() => {
                socket.emit('consultation_webrtc_offer', {
                    appointment_id: APPOINTMENT_ID,
                    target_user_id: targetUserId,
                    sdp: pc.localDescription,
                });
            })
            .catch(console.error);
    }

    function onWebRtcOffer(data) {
        const fromId = data.from_user_id;
        const pc = createPeerConnection(fromId);
        ensurePeerTile(fromId);

        pc.setRemoteDescription(new RTCSessionDescription(data.sdp))
            .then(() => pc.createAnswer())
            .then(answer => pc.setLocalDescription(answer))
            .then(() => {
                socket.emit('consultation_webrtc_answer', {
                    appointment_id: APPOINTMENT_ID,
                    target_user_id: fromId,
                    sdp: pc.localDescription,
                });
            })
            .catch(console.error);
    }

    function onWebRtcAnswer(data) {
        const pc = peers[data.from_user_id];
        if (pc) pc.setRemoteDescription(new RTCSessionDescription(data.sdp)).catch(console.error);
    }

    function onWebRtcIce(data) {
        const pc = peers[data.from_user_id];
        if (pc && data.candidate) {
            pc.addIceCandidate(new RTCIceCandidate(data.candidate)).catch(console.error);
        }
    }

    /* ── Video tiles ─────────────────────────────────────────────── */
    function ensurePeerTile(userId) {
        if (document.getElementById(`peer-tile-${userId}`)) return;

        const p = peerStates[userId] || {};
        const tile = document.createElement('div');
        tile.className = 'peer-tile';
        tile.id = `peer-tile-${userId}`;

        const vid = document.createElement('video');
        vid.autoplay = true;
        vid.playsInline = true;
        vid.setAttribute('aria-label', `${p.display_name || 'Participant'} camera`);
        tile.appendChild(vid);

        // Fallback avatar
        const fallback = document.createElement('div');
        fallback.className = 'peer-avatar-fallback';
        if (p.profile_picture_url) {
            const img = document.createElement('img');
            img.src = p.profile_picture_url;
            img.className = 'peer-avatar-img';
            img.alt = p.display_name || 'Participant';
            fallback.appendChild(img);
        } else {
            const circle = document.createElement('div');
            circle.className = 'peer-initials-circle';
            circle.textContent = getInitials(p.display_name || '?');
            fallback.appendChild(circle);
        }
        tile.appendChild(fallback);

        // Overlay
        const overlay = document.createElement('div');
        overlay.className = 'peer-overlay';
        overlay.innerHTML = `
            <i class="fas fa-microphone peer-icon on" id="peer-mic-${userId}"></i>
            <span class="peer-name-badge">${escHtml(p.display_name || 'Participant')}</span>
        `;
        tile.appendChild(overlay);

        // Pin button
        const pinBtn = document.createElement('button');
        pinBtn.className = 'pin-btn';
        pinBtn.innerHTML = '<i class="fas fa-thumbtack"></i>';
        pinBtn.title = 'Pin video';
        pinBtn.setAttribute('aria-label', 'Pin video');
        pinBtn.addEventListener('click', () => tile.classList.toggle('pinned'));
        tile.appendChild(pinBtn);

        const grid = document.getElementById('videoGrid');
        if (grid) grid.appendChild(tile);
        updateGridLayout();
    }

    function removePeerTile(userId) {
        const tile = document.getElementById(`peer-tile-${userId}`);
        if (tile) tile.remove();
        updateGridLayout();
    }

    function updateGridLayout() {
        const grid = document.getElementById('videoGrid');
        if (!grid) return;
        const count = grid.querySelectorAll('.peer-tile').length;
        grid.className = `peers-${Math.min(count, 4)}`;
    }

    /* ════════════════════════════════════════════════════════════════
       CONTROLS
    ════════════════════════════════════════════════════════════════ */
    function initControls() {
        document.getElementById('btnMic')?.addEventListener('click', toggleMic);
        document.getElementById('btnCam')?.addEventListener('click', toggleCam);
        document.getElementById('btnScreenShare')?.addEventListener('click', toggleScreenShare);
        document.getElementById('btnRaiseHand')?.addEventListener('click', toggleRaiseHand);
        document.getElementById('btnRecord')?.addEventListener('click', () => {
            const modal = new bootstrap.Modal(document.getElementById('modalRecordConsent'));
            modal.show();
        });
        document.getElementById('btnMarkComplete')?.addEventListener('click', () => {
            const modal = new bootstrap.Modal(document.getElementById('modalMarkComplete'));
            modal.show();
        });
        document.getElementById('btnEndSession')?.addEventListener('click', endSession);
        document.getElementById('btnConfirmComplete')?.addEventListener('click', markComplete);
        document.getElementById('btnGiveConsent')?.addEventListener('click', giveRecordingConsent);
    }

    function toggleMic() {
        isMicOn = !isMicOn;
        if (localStream) localStream.getAudioTracks().forEach(t => { t.enabled = isMicOn; });
        updateCtrlBtn('btnMic', isMicOn, 'fa-microphone', 'fa-microphone-slash');
        broadcastMediaState();
    }

    function toggleCam() {
        isCamOn = !isCamOn;
        if (localStream) localStream.getVideoTracks().forEach(t => { t.enabled = isCamOn; });
        updateCtrlBtn('btnCam', isCamOn, 'fa-video', 'fa-video-slash');
        broadcastMediaState();
    }

    function toggleScreenShare() {
        if (!isScreenSharing) {
            navigator.mediaDevices.getDisplayMedia({ video: true, audio: false })
                .then(stream => {
                    screenStream = stream;
                    isScreenSharing = true;
                    const screenTrack = stream.getVideoTracks()[0];

                    // Replace video track in all peer connections
                    Object.values(peers).forEach(pc => {
                        const sender = pc.getSenders().find(s => s.track && s.track.kind === 'video');
                        if (sender) sender.replaceTrack(screenTrack);
                    });

                    // Show local screen in PiP
                    const localVid = document.getElementById('localVideo');
                    if (localVid) localVid.srcObject = screenStream;

                    screenTrack.onended = () => { if (isScreenSharing) toggleScreenShare(); };
                    updateCtrlBtn('btnScreenShare', false, 'fa-desktop', 'fa-desktop');
                    document.getElementById('btnScreenShare')?.classList.replace('active-on', 'accent');
                    broadcastMediaState();
                })
                .catch(() => { /* user cancelled */ });
        } else {
            if (screenStream) { screenStream.getTracks().forEach(t => t.stop()); screenStream = null; }
            isScreenSharing = false;

            // Restore camera track
            const camTrack = localStream?.getVideoTracks()[0];
            if (camTrack) {
                Object.values(peers).forEach(pc => {
                    const sender = pc.getSenders().find(s => s.track && s.track.kind === 'video');
                    if (sender) sender.replaceTrack(camTrack);
                });
            }

            const localVid = document.getElementById('localVideo');
            if (localVid && localStream) localVid.srcObject = localStream;
            updateCtrlBtn('btnScreenShare', true, 'fa-desktop', 'fa-desktop');
            document.getElementById('btnScreenShare')?.classList.replace('accent', 'active-on');
            broadcastMediaState();
        }
    }

    function toggleRaiseHand() {
        if (OBSERVE_MODE) return;
        isHandRaised = !isHandRaised;
        socket.emit('consultation_raise_hand', {
            appointment_id: APPOINTMENT_ID,
            raised: isHandRaised,
        });
        updateCtrlBtn('btnRaiseHand', !isHandRaised, 'fa-hand-paper', 'fa-hand-paper');
        if (isHandRaised) document.getElementById('btnRaiseHand')?.classList.replace('active-on', 'accent');
        else document.getElementById('btnRaiseHand')?.classList.replace('accent', 'active-on');
    }

    function updateCtrlBtn(btnId, isOn, iconOn, iconOff) {
        const btn = document.getElementById(btnId);
        if (!btn) return;
        btn.classList.toggle('active-on', isOn);
        btn.classList.toggle('active-off', !isOn);
        btn.setAttribute('aria-pressed', isOn ? 'true' : 'false');
        const icon = btn.querySelector('i');
        if (icon) { icon.className = `fas ${isOn ? iconOn : iconOff}`; }
    }

    function broadcastMediaState() {
        if (!socket) return;
        socket.emit('consultation_media_state', {
            appointment_id: APPOINTMENT_ID,
            audio: isMicOn,
            video: isCamOn,
            screen: isScreenSharing,
        });
    }

    function onMediaState(data) {
        if (data.user_id === MY_USER_ID) return;
        const tile = document.getElementById(`peer-tile-${data.user_id}`);
        if (!tile) return;

        tile.classList.toggle('video-off', !data.video);
        const micIcon = document.getElementById(`peer-mic-${data.user_id}`);
        if (micIcon) micIcon.classList.toggle('on', data.audio);
    }

    function onRaiseHand(data) {
        if (data.user_id === MY_USER_ID) return;
        const toast = document.getElementById('raiseHandToast');
        if (!toast) return;
        toast.textContent = data.raised
            ? `✋ ${escHtml(data.display_name)} raised their hand`
            : `${escHtml(data.display_name)} lowered their hand`;
        toast.classList.add('show');
        setTimeout(() => toast.classList.remove('show'), 5000);
    }

    /* ── End / Complete ──────────────────────────────────────────── */
    function endSession() {
        if (!confirm('Are you sure you want to leave this consultation?')) return;
        stopAutoRecording().then(() => {
            uploadRecording();
        });
        if (socket) socket.emit('leave_consultation_room', { appointment_id: APPOINTMENT_ID });
        cleanupMedia();

        const dur = document.getElementById('endedDuration');
        if (dur && sessionStartTime) dur.textContent = formatDuration(Math.floor((Date.now() - sessionStartTime) / 1000));
        showScreen('ended');
    }

    function markComplete() {
        fetch(`/api/consultation-room/${APPOINTMENT_ID}/end`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-CSRFToken': CSRF_TOKEN },
            credentials: 'same-origin',
            body: JSON.stringify({ mark_completed: true }),
        })
        .then(r => r.json())
        .then(() => {
            bootstrap.Modal.getInstance(document.getElementById('modalMarkComplete'))?.hide();
        })
        .catch(console.error);
    }

    function giveRecordingConsent() {
        fetch(`/api/consultation-room/${APPOINTMENT_ID}/recording-consent`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-CSRFToken': CSRF_TOKEN },
            credentials: 'same-origin',
            body: JSON.stringify({ consent: true }),
        })
        .then(r => r.json())
        .then(() => {
            bootstrap.Modal.getInstance(document.getElementById('modalRecordConsent'))?.hide();
        })
        .catch(console.error);
    }

    /* ════════════════════════════════════════════════════════════════
       SIDEBAR & CHAT
    ════════════════════════════════════════════════════════════════ */
    function initSidebar() {
        document.querySelectorAll('.sidebar-tab').forEach(tab => {
            tab.addEventListener('click', () => {
                const panel = tab.dataset.panel;
                switchPanel(panel);
            });
        });

        document.getElementById('btnSendChat')?.addEventListener('click', sendChat);
        const chatInput = document.getElementById('chatInput');
        if (chatInput) {
            chatInput.addEventListener('keydown', e => {
                if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendChat(); }
            });
        }

        document.getElementById('chatFileInput')?.addEventListener('change', handleChatFileShare);
        document.getElementById('shareFileInput')?.addEventListener('change', handleFileShare);

        // Notes auto-save (debounced)
        document.getElementById('sessionNotesArea')?.addEventListener('input', () => {
            clearTimeout(notesSaveTimeout);
            setNoteStatus('Saving…');
            notesSaveTimeout = setTimeout(saveNotes, 1500);
        });

        // Prescription form
        document.getElementById('rxQuickForm')?.addEventListener('submit', submitPrescription);

        // Group invite
        document.getElementById('btnGroupInvite')?.addEventListener('click', openGroupInviteModal);
        document.getElementById('btnSendGroupInvites')?.addEventListener('click', sendGroupInvites);
    }

    function switchPanel(name) {
        activePanel = name;
        document.querySelectorAll('.sidebar-panel').forEach(p => p.classList.toggle('active', p.id === `panel${cap(name)}`));
        document.querySelectorAll('.sidebar-tab').forEach(t => {
            const isActive = t.dataset.panel === name;
            t.classList.toggle('active', isActive);
            t.setAttribute('aria-selected', isActive ? 'true' : 'false');
        });
        if (name === 'chat') { unreadChat = 0; updateChatBadge(); }
        if (name === 'whiteboard') resizeWhiteboard();
    }

    function sendChat() {
        const input = document.getElementById('chatInput');
        const msg = (input?.value || '').trim();
        if (!msg || !socket) return;
        socket.emit('consultation_chat_message', {
            appointment_id: APPOINTMENT_ID,
            message: msg,
        });
        input.value = '';
    }

    function onChatMessage(data) {
        const messages = document.getElementById('chatMessages');
        if (!messages) return;

        const isMine = data.user_id === MY_USER_ID;
        const div = document.createElement('div');
        div.className = `chat-msg ${isMine ? 'mine' : ''}`;

        const avatar = document.createElement(data.profile_picture_url ? 'img' : 'div');
        if (data.profile_picture_url) {
            avatar.src = data.profile_picture_url;
            avatar.alt = data.display_name || 'User';
        } else {
            avatar.textContent = getInitials(data.display_name || '?');
            avatar.style.cssText = 'width:28px;height:28px;border-radius:50%;background:var(--cr-accent);display:flex;align-items:center;justify-content:center;font-size:.65rem;font-weight:700;color:#fff;flex-shrink:0;';
        }
        avatar.className = 'chat-msg-avatar';

        const bubble = document.createElement('div');
        bubble.className = 'chat-msg-bubble';
        bubble.textContent = data.message;

        // File attachment
        if (data.file_url) {
            const link = document.createElement('a');
            link.href = data.file_url;
            link.download = data.file_name || 'file';
            link.textContent = `📎 ${data.file_name || 'Download file'}`;
            link.className = 'd-block mt-1';
            link.style.color = isMine ? '#fff' : 'var(--cr-accent)';
            link.rel = 'noopener noreferrer';
            bubble.appendChild(link);
        }

        const meta = document.createElement('div');
        meta.className = 'chat-msg-meta';
        meta.textContent = `${isMine ? 'You' : (data.display_name || '')} · ${fmtTime(new Date())}`;

        const col = document.createElement('div');
        col.appendChild(bubble);
        col.appendChild(meta);

        div.appendChild(avatar);
        div.appendChild(col);
        messages.appendChild(div);
        messages.scrollTop = messages.scrollHeight;

        if (activePanel !== 'chat') {
            unreadChat++;
            updateChatBadge();
        }
    }

    function appendSystemMessage(text) {
        const messages = document.getElementById('chatMessages');
        if (!messages) return;
        const p = document.createElement('p');
        p.style.cssText = 'text-align:center;font-size:.72rem;color:var(--cr-muted);margin:.3rem 0;';
        p.textContent = text;
        messages.appendChild(p);
        messages.scrollTop = messages.scrollHeight;
    }

    function updateChatBadge() {
        const badge = document.getElementById('chatBadge');
        if (!badge) return;
        badge.textContent = unreadChat;
        badge.classList.toggle('visible', unreadChat > 0);
    }

    /* ── Notes ───────────────────────────────────────────────────── */
    function saveNotes() {
        const notesArea = document.getElementById('sessionNotesArea');
        if (!notesArea) return;
        fetch(`/api/consultation-room/${APPOINTMENT_ID}/notes`, {
            method: 'PATCH',
            headers: { 'Content-Type': 'application/json', 'X-CSRFToken': CSRF_TOKEN },
            credentials: 'same-origin',
            body: JSON.stringify({ notes: notesArea.value }),
        })
        .then(r => r.json())
        .then(() => setNoteStatus('Saved ✓'))
        .catch(() => setNoteStatus('Save failed – retrying…'));
    }

    function setNoteStatus(msg) {
        const el = document.getElementById('noteSaveStatus');
        if (el) el.textContent = msg;
    }

    /* ── Prescriptions ───────────────────────────────────────────── */
    function submitPrescription(e) {
        e.preventDefault();
        const fd = new FormData(e.target);
        const body = Object.fromEntries(fd.entries());
        body.appointment_id = APPOINTMENT_ID;

        fetch('/api/prescriptions', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-CSRFToken': CSRF_TOKEN },
            credentials: 'same-origin',
            body: JSON.stringify(body),
        })
        .then(r => r.json())
        .then(data => {
            if (data.success) {
                e.target.reset();
                appendRxCard(data.prescription || body);
            }
        })
        .catch(console.error);
    }

    function appendRxCard(rx) {
        const list = document.getElementById('rxList');
        if (!list) return;
        const card = document.createElement('div');
        card.className = 'card mb-2';
        card.style.cssText = 'background:var(--cr-border);border-color:var(--cr-border);color:var(--cr-text);';
        card.innerHTML = `<div class="card-body p-2">
            <strong style="font-size:.82rem;">${escHtml(rx.drug_name || rx.medication)}</strong>
            <span class="badge bg-success ms-1" style="font-size:.65rem;">${escHtml(rx.dosage || '')}</span>
            <p class="mb-0" style="font-size:.75rem;color:var(--cr-muted);">${escHtml(rx.frequency || '')} · ${escHtml(rx.duration || '')}</p>
        </div>`;
        list.prepend(card);
    }

    /* ── File sharing ────────────────────────────────────────────── */
    function handleChatFileShare(e) {
        const file = e.target.files[0];
        if (file) uploadAndShareFile(file, true);
        e.target.value = '';
    }

    function handleFileShare(e) {
        const file = e.target.files[0];
        if (file) uploadAndShareFile(file, false);
        e.target.value = '';
    }

    function uploadAndShareFile(file, inChat) {
        const fd = new FormData();
        fd.append('file', file);
        fd.append('appointment_id', APPOINTMENT_ID);
        fd.append('csrf_token', CSRF_TOKEN);

        fetch('/api/consultation-room/upload', { method: 'POST', body: fd, credentials: 'same-origin' })
            .then(r => r.json())
            .then(data => {
                if (data.success && socket) {
                    socket.emit('consultation_chat_message', {
                        appointment_id: APPOINTMENT_ID,
                        message: inChat ? '' : `Shared a file: ${file.name}`,
                        file_url: data.url,
                        file_name: file.name,
                    });
                    if (!inChat) addFileToList(data.url, file.name);
                }
            })
            .catch(console.error);
    }

    function addFileToList(url, name) {
        const list = document.getElementById('filesList');
        if (!list) return;
        const empty = list.querySelector('p');
        if (empty) empty.remove();

        const item = document.createElement('div');
        item.className = 'file-item';
        item.innerHTML = `<i class="fas fa-file-alt"></i>
            <a href="${escHtml(url)}" download="${escHtml(name)}" class="flex-grow-1 text-truncate" rel="noopener noreferrer" style="color:var(--cr-text);font-size:.8rem;">${escHtml(name)}</a>`;
        list.appendChild(item);

        const badge = document.getElementById('filesBadge');
        if (badge) {
            badge.textContent = parseInt(badge.textContent || '0', 10) + 1;
            badge.classList.add('visible');
        }
    }

    /* ════════════════════════════════════════════════════════════════
       PARTICIPANTS LIST
    ════════════════════════════════════════════════════════════════ */
    function addParticipantTile(p) {
        // No-op: ensurePeerTile handles video tile; updateParticipantsList handles sidebar list
    }

    function updateParticipantsList() {
        const list = document.getElementById('participantsList');
        if (!list) return;
        list.innerHTML = '';

        // Self
        appendParticipantItem(list, {
            user_id: MY_USER_ID,
            display_name: 'You (' + MY_NAME + ')',
            role: MY_ROLE,
            profile_picture_url: MY_PIC,
        }, true);

        // Peers
        Object.values(peerStates).forEach(p => appendParticipantItem(list, p, false));

        const badge = document.getElementById('peopleBadge');
        if (badge) {
            const count = Object.keys(peerStates).length + 1;
            badge.textContent = count;
        }
    }

    function appendParticipantItem(container, p, isMe) {
        const item = document.createElement('div');
        item.className = 'participant-item';

        if (p.profile_picture_url) {
            item.innerHTML = `<img src="${escHtml(p.profile_picture_url)}" alt="${escHtml(p.display_name || '')}">`;
        } else {
            item.innerHTML = `<div class="participant-initials">${escHtml(getInitials(p.display_name || '?'))}</div>`;
        }

        item.innerHTML += `
            <div class="participant-info">
                <div class="participant-name">${escHtml(p.display_name || 'User')}</div>
                <div class="participant-role">${cap(p.role || '')}</div>
            </div>
            <span class="participant-status online">${isMe ? '● You' : '● Live'}</span>
        `;
        container.appendChild(item);
    }

    /* ════════════════════════════════════════════════════════════════
       GROUP INVITE
    ════════════════════════════════════════════════════════════════ */
    function openGroupInviteModal() {
        const modal = new bootstrap.Modal(document.getElementById('modalGroupInvite'));
        modal.show();

        const listEl = document.getElementById('groupInviteList');
        if (!listEl) return;
        listEl.innerHTML = '<p class="text-muted small text-center">Loading…</p>';

        fetch(`/api/doctor/appointments/today-confirmed`, {
            headers: { 'Accept': 'application/json', 'X-CSRFToken': CSRF_TOKEN },
            credentials: 'same-origin',
        })
        .then(r => r.json())
        .then(data => {
            if (!data.appointments || !data.appointments.length) {
                listEl.innerHTML = '<p class="text-muted small text-center">No other eligible appointments found for today.</p>';
                return;
            }
            listEl.innerHTML = '';
            data.appointments.forEach(appt => {
                if (appt.id === APPOINTMENT_ID) return;
                const item = document.createElement('label');
                item.className = 'appt-select-item';
                item.innerHTML = `
                    <input type="checkbox" name="invite_appt" value="${appt.id}">
                    <div>
                        <div style="font-size:.82rem;font-weight:600;">${escHtml(appt.patient_name)}</div>
                        <div style="font-size:.72rem;color:var(--cr-muted);">${escHtml(appt.scheduled_time || '')}</div>
                    </div>`;
                listEl.appendChild(item);
            });
        })
        .catch(() => {
            listEl.innerHTML = '<p class="text-danger small text-center">Failed to load appointments.</p>';
        });
    }

    function sendGroupInvites() {
        const selected = Array.from(document.querySelectorAll('input[name="invite_appt"]:checked')).map(cb => parseInt(cb.value, 10));
        if (!selected.length) { alert('Please select at least one patient.'); return; }

        const btn = document.getElementById('btnSendGroupInvites');
        if (btn) { btn.disabled = true; btn.textContent = 'Sending…'; }

        fetch(`/api/doctor/consultation-room/${APPOINTMENT_ID}/group-invite`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-CSRFToken': CSRF_TOKEN },
            credentials: 'same-origin',
            body: JSON.stringify({ appointment_ids: selected }),
        })
        .then(r => r.json())
        .then(() => {
            bootstrap.Modal.getInstance(document.getElementById('modalGroupInvite'))?.hide();
            appendSystemMessage('Group invitations sent.');
        })
        .catch(() => {
            if (btn) { btn.disabled = false; btn.textContent = 'Send Invites'; }
        });
    }

    /* ════════════════════════════════════════════════════════════════
       WHITEBOARD
    ════════════════════════════════════════════════════════════════ */
    function initWhiteboard() {
        const canvas = document.getElementById('whiteboardCanvas');
        if (!canvas) return;
        const ctx = canvas.getContext('2d');
        resizeWhiteboard();

        // Color buttons
        document.querySelectorAll('.wb-color').forEach(btn => {
            btn.addEventListener('click', () => {
                document.querySelectorAll('.wb-color').forEach(b => b.classList.remove('active'));
                btn.classList.add('active');
                wbState.color = btn.dataset.color;
                wbState.erasing = false;
            });
        });

        // Size buttons
        document.querySelectorAll('.wb-size-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                document.querySelectorAll('.wb-size-btn').forEach(b => b.classList.remove('active'));
                btn.classList.add('active');
                wbState.size = parseInt(btn.dataset.size, 10);
            });
        });

        document.getElementById('wbEraseBtn')?.addEventListener('click', () => { wbState.erasing = true; });
        document.getElementById('wbClearBtn')?.addEventListener('click', () => {
            ctx.clearRect(0, 0, canvas.width, canvas.height);
            if (socket) socket.emit('consultation_whiteboard', { appointment_id: APPOINTMENT_ID, action: 'clear' });
        });

        let lastX = 0, lastY = 0;

        function getPos(e) {
            const rect = canvas.getBoundingClientRect();
            const src = e.touches ? e.touches[0] : e;
            return {
                x: (src.clientX - rect.left) * (canvas.width / rect.width),
                y: (src.clientY - rect.top) * (canvas.height / rect.height),
            };
        }

        function startDraw(e) {
            wbState.drawing = true;
            const pos = getPos(e);
            lastX = pos.x; lastY = pos.y;
        }

        function draw(e) {
            if (!wbState.drawing) return;
            e.preventDefault();
            const pos = getPos(e);
            const data = {
                appointment_id: APPOINTMENT_ID,
                action: 'draw',
                x0: lastX, y0: lastY,
                x1: pos.x, y1: pos.y,
                color: wbState.erasing ? '#ffffff' : wbState.color,
                size: wbState.erasing ? 20 : wbState.size,
                w: canvas.width, h: canvas.height,
            };
            drawLine(ctx, data);
            if (socket) socket.emit('consultation_whiteboard', data);
            lastX = pos.x; lastY = pos.y;
        }

        function stopDraw() { wbState.drawing = false; }

        canvas.addEventListener('mousedown', startDraw);
        canvas.addEventListener('mousemove', draw);
        canvas.addEventListener('mouseup', stopDraw);
        canvas.addEventListener('mouseleave', stopDraw);
        canvas.addEventListener('touchstart', startDraw, { passive: false });
        canvas.addEventListener('touchmove', draw, { passive: false });
        canvas.addEventListener('touchend', stopDraw);

        window.addEventListener('resize', resizeWhiteboard);
    }

    function onWhiteboardEvent(data) {
        const canvas = document.getElementById('whiteboardCanvas');
        if (!canvas) return;
        const ctx = canvas.getContext('2d');
        if (data.action === 'clear') {
            ctx.clearRect(0, 0, canvas.width, canvas.height);
        } else if (data.action === 'draw') {
            // Scale coordinates from sender's canvas size to ours
            const scaleX = canvas.width / (data.w || canvas.width);
            const scaleY = canvas.height / (data.h || canvas.height);
            drawLine(ctx, {
                x0: data.x0 * scaleX, y0: data.y0 * scaleY,
                x1: data.x1 * scaleX, y1: data.y1 * scaleY,
                color: data.color, size: data.size,
            });
        }
    }

    function drawLine(ctx, d) {
        ctx.beginPath();
        ctx.strokeStyle = d.color;
        ctx.lineWidth = d.size;
        ctx.lineCap = 'round';
        ctx.moveTo(d.x0, d.y0);
        ctx.lineTo(d.x1, d.y1);
        ctx.stroke();
    }

    function resizeWhiteboard() {
        const canvas = document.getElementById('whiteboardCanvas');
        if (!canvas) return;
        const panel = document.getElementById('panelWhiteboard');
        if (!panel) return;
        const controls = panel.querySelector('.wb-controls');
        const ctrlH = controls ? controls.offsetHeight : 48;
        canvas.width = panel.offsetWidth;
        canvas.height = Math.max(panel.offsetHeight - ctrlH, 200);
    }

    /* ════════════════════════════════════════════════════════════════
       SESSION TIMER
    ════════════════════════════════════════════════════════════════ */
    function startSessionTimer() {
        sessionStartTime = Date.now();
        sessionTimerInterval = setInterval(() => {
            const elapsed = Math.floor((Date.now() - sessionStartTime) / 1000);
            const fmt = formatDuration(elapsed);
            const timerEl = document.getElementById('sessionTimer');
            const ctrlTimer = document.getElementById('ctrlTimerDisplay');
            if (timerEl) timerEl.textContent = fmt;
            if (ctrlTimer) ctrlTimer.textContent = fmt;
        }, 1000);
    }

    /* ════════════════════════════════════════════════════════════════
       QUALITY METER
    ════════════════════════════════════════════════════════════════ */
    function updateQuality() {
        const pcs = Object.values(peers);
        if (!pcs.length) return;

        Promise.all(pcs.map(pc => pc.getStats())).then(allStats => {
            let totalRtt = 0, count = 0;
            allStats.forEach(stats => {
                stats.forEach(report => {
                    if (report.type === 'candidate-pair' && report.state === 'succeeded' && report.currentRoundTripTime != null) {
                        totalRtt += report.currentRoundTripTime;
                        count++;
                    }
                });
            });
            const avgRtt = count ? totalRtt / count : 9999;
            let level = 'poor';
            if (avgRtt < 0.05) level = 'excellent';
            else if (avgRtt < 0.15) level = 'good';
            else if (avgRtt < 0.4) level = 'fair';

            const bars = document.getElementById('qualityBars');
            const label = document.getElementById('qualityLabel');
            if (bars) bars.className = `quality-bars ${level}`;
            if (label) { label.textContent = cap(level); label.className = `ctrl-quality-label ${level}`; }
        }).catch(() => {});
    }
    setInterval(updateQuality, 5000);

    /* ════════════════════════════════════════════════════════════════
       LOCAL PiP DRAGGING
    ════════════════════════════════════════════════════════════════ */
    function makePipDraggable() {
        const pip = document.getElementById('localPip');
        if (!pip) return;
        let startX, startY, startLeft, startTop;

        pip.addEventListener('mousedown', e => {
            startX = e.clientX; startY = e.clientY;
            const rect = pip.getBoundingClientRect();
            startLeft = rect.left; startTop = rect.top;
            document.addEventListener('mousemove', onDrag);
            document.addEventListener('mouseup', stopDrag, { once: true });
        });

        function onDrag(e) {
            const dx = e.clientX - startX;
            const dy = e.clientY - startY;
            const newLeft = Math.max(0, Math.min(window.innerWidth - pip.offsetWidth, startLeft + dx));
            const newTop = Math.max(0, Math.min(window.innerHeight - pip.offsetHeight, startTop + dy));
            pip.style.left = newLeft + 'px';
            pip.style.top = newTop + 'px';
            pip.style.right = 'auto';
            pip.style.bottom = 'auto';
        }

        function stopDrag() {
            document.removeEventListener('mousemove', onDrag);
        }
    }

    /* ════════════════════════════════════════════════════════════════
       AUTO-RECORDING — captures all peer streams + local into one file
    ════════════════════════════════════════════════════════════════ */
    function startAutoRecording() {
        try {
            // Combine all available streams: local + remote peers
            const combinedStream = new MediaStream();

            // Add local tracks if available
            if (localStream) {
                localStream.getTracks().forEach(t => combinedStream.addTrack(t.clone()));
            }

            // Add remote tracks from peer connections
            Object.values(peers).forEach(pc => {
                pc.getReceivers().forEach(receiver => {
                    if (receiver.track) combinedStream.addTrack(receiver.track.clone());
                });
            });

            if (combinedStream.getTracks().length === 0) {
                console.log('[CR] No tracks to record yet, will retry when peers connect');
                // Retry after peers connect
                setTimeout(startAutoRecording, 3000);
                return;
            }

            const mimeType = MediaRecorder.isTypeSupported('video/webm;codecs=vp9,opus')
                ? 'video/webm;codecs=vp9,opus'
                : MediaRecorder.isTypeSupported('video/webm;codecs=vp8,opus')
                    ? 'video/webm;codecs=vp8,opus'
                    : 'video/webm';

            mediaRecorder = new MediaRecorder(combinedStream, { mimeType });
            recordedChunks = [];

            mediaRecorder.ondataavailable = e => {
                if (e.data && e.data.size > 0) recordedChunks.push(e.data);
            };

            mediaRecorder.onstop = () => {
                console.log('[CR] Recording stopped, chunks:', recordedChunks.length);
            };

            mediaRecorder.start(5000); // collect chunks every 5s
            isSelfRecording = true;
            console.log('[CR] Auto-recording started');

            const recInd = document.getElementById('recordingIndicator');
            if (recInd) recInd.classList.add('active');
        } catch (e) {
            console.error('[CR] Auto-recording failed to start:', e);
        }
    }

    function stopAutoRecording() {
        return new Promise(resolve => {
            if (!mediaRecorder || mediaRecorder.state === 'inactive') {
                resolve();
                return;
            }
            mediaRecorder.onstop = () => {
                isSelfRecording = false;
                const recInd = document.getElementById('recordingIndicator');
                if (recInd) recInd.classList.remove('active');
                console.log('[CR] Auto-recording stopped');
                resolve();
            };
            mediaRecorder.stop();
        });
    }

    function uploadRecording() {
        if (!recordedChunks.length) return;

        const blob = new Blob(recordedChunks, { type: 'video/webm' });
        const formData = new FormData();
        formData.append('recording', blob, `consultation_${APPOINTMENT_ID}.webm`);
        formData.append('type', 'video');

        fetch(`/api/consultation-room/${APPOINTMENT_ID}/upload-recording`, {
            method: 'POST',
            headers: { 'X-CSRFToken': CSRF_TOKEN },
            credentials: 'same-origin',
            body: formData,
        })
        .then(r => r.json())
        .then(data => {
            if (data.success) console.log('[CR] Recording uploaded, id:', data.recording_id);
            else console.error('[CR] Recording upload failed:', data.error);
        })
        .catch(e => console.error('[CR] Recording upload error:', e));

        recordedChunks = [];
    }

    /* ════════════════════════════════════════════════════════════════
       CLEANUP
    ════════════════════════════════════════════════════════════════ */
    function cleanupMedia() {
        clearInterval(sessionTimerInterval);
        localStream?.getTracks().forEach(t => t.stop());
        screenStream?.getTracks().forEach(t => t.stop());
        Object.values(peers).forEach(pc => pc.close());
        peers = {};
        if (socket) { socket.emit('leave_consultation_room', { appointment_id: APPOINTMENT_ID }); }
    }

    window.addEventListener('beforeunload', () => {
        if (socket && roomStatus !== 'ended') {
            socket.emit('leave_consultation_room', { appointment_id: APPOINTMENT_ID });
        }
    });

    /* ════════════════════════════════════════════════════════════════
       UTILITY
    ════════════════════════════════════════════════════════════════ */
    function formatDuration(seconds) {
        const h = Math.floor(seconds / 3600);
        const m = Math.floor((seconds % 3600) / 60);
        const s = seconds % 60;
        if (h > 0) return `${String(h).padStart(2,'0')}:${String(m).padStart(2,'0')}:${String(s).padStart(2,'0')}`;
        return `${String(m).padStart(2,'0')}:${String(s).padStart(2,'0')}`;
    }

    function getInitials(name) {
        return name.split(' ').filter(Boolean).slice(0, 2).map(w => w[0].toUpperCase()).join('');
    }

    function cap(str) { return str ? str.charAt(0).toUpperCase() + str.slice(1) : ''; }

    function fmtTime(d) {
        return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    }

    function escHtml(str) {
        if (!str) return '';
        return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
    }

    /* ── BOOT ──────────────────────────────────────────────────── */
    document.addEventListener('DOMContentLoaded', init);

})();
