# Real-Time Telemedicine Communication System - Implementation Guide

## Overview
This document describes the comprehensive real-time communication system implemented for the telemedicine platform. The system supports video calls, voice calls, messaging, presence tracking, and call quality monitoring.

## Architecture

### High-Level Components

```
┌─────────────────────────────────────────────────────────┐
│                   CLIENT APPLICATIONS                    │
│  ┌──────────────────┐  ┌──────────────────┐             │
│  │  Patient Web App │  │  Doctor Web App  │             │
│  └──────────────────┘  └──────────────────┘             │
│  ┌─────────────────────────────────────────┐            │
│  │  WebRTC Client (Peer Connections)       │            │
│  │  Signaling Client (Socket.IO)           │            │
│  │  Call Manager (Orchestration)           │            │
│  └─────────────────────────────────────────┘            │
└─────────────────────────────────────────────────────────┘
                          ↕
┌─────────────────────────────────────────────────────────┐
│              SIGNALING SERVER (Flask + Socket.IO)        │
│  ┌──────────────────────────────────────────────────┐   │
│  │  Call Signaling Events (offer/answer/ice)        │   │
│  │  Presence Updates                                │   │
│  │  Messaging & Chat                                │   │
│  │  Call State Machine                              │   │
│  └──────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────┘
                          ↕
┌─────────────────────────────────────────────────────────┐
│               DATABASE & STORAGE                         │
│  ┌──────────────────┐  ┌──────────────────────────────┐ │
│  │   PostgreSQL     │  │  S3-Compatible (or Local)    │ │
│  │  - Call History  │  │  - Recordings                │ │
│  │  - Messages      │  │  - Attachments               │ │
│  │  - Attachments   │  │  - Profile Pictures          │ │
│  │  - Presence      │  │  - Call Artifacts            │ │
│  └──────────────────┘  └──────────────────────────────┘ │
└─────────────────────────────────────────────────────────┘
```

## Database Schema

### New Tables Added

#### 1. CallHistory
```sql
- id (PK)
- call_id (UUID, unique) - for signaling reference
- appointment_id (FK) - linked appointment
- caller_id (FK to User)
- callee_id (FK to User)
- call_type (video|voice)
- initiated_at, ringing_at, accepted_at, connected_at, ended_at
- status (initiated|ringing|accepted|connecting|connected|ended|failed)
- end_reason (user_hangup|callee_declined|missed|busy|network_error|timeout|connection_failed)
- duration (seconds)
- room_id (SFU room identifier)
- sfu_server (which media server instance)
- quality_metrics (JSON) - aggregated quality data
- recording_url, recording_size, recording_duration
- recording_consent (boolean)
```

#### 2. Message
```sql
- id (PK)
- message_id (UUID, unique)
- conversation_id (FK)
- sender_id (FK to User)
- encrypted_body (BLOB) - encrypted for privacy
- message_type (text|image|file|voice_note|prescription|report)
- in_call (boolean) - message sent during a call
- call_id (reference to CallHistory.call_id)
- status (sent|delivered|read)
- delivered_at, read_at
- attachment_ids (JSON array)
```

#### 3. Conversation
```sql
- id (PK)
- conversation_id (UUID, unique)
- participant_ids (JSON array of user IDs)
- conversation_type (direct|group)
- group_name, group_avatar (optional)
- last_message_at
- is_active (boolean)
```

#### 4. Attachment
```sql
- id (PK)
- attachment_id (UUID, unique)
- owner_id (FK to User)
- file_name, file_type (MIME), file_size
- s3_key, s3_bucket, file_url
- shared_in_call_id, shared_in_message_id
- encrypted_metadata (BLOB)
- is_encrypted (boolean)
- access_control (private|shared_call|shared_conversation)
- uploaded_at, expires_at
```

#### 5. CallQualityMetrics
```sql
- id (PK)
- call_id (FK to CallHistory.call_id)
- user_id (FK to User)
- rtt (round-trip time in ms)
- packet_loss (%)
- jitter (ms)
- available_bandwidth (kbps)
- audio_bitrate, video_bitrate (kbps)
- video_resolution, video_framerate
- cpu_usage, memory_usage (%)
- audio_quality, video_quality (excellent|good|fair|poor)
- timestamp (when metric was recorded)
```

#### 6. UserPresence
```sql
- id (PK)
- user_id (FK, unique)
- status (online|away|idle|busy|offline|do_not_disturb)
- current_call_id, current_appointment_id
- last_heartbeat, last_seen
- device_type (web|mobile|desktop)
```

## API Endpoints

### Call Management

#### Initiate Call
```
POST /api/calls/initiate
{
  "callee_id": int,
  "appointment_id": int,
  "call_type": "video|voice"
}
Response: { call_id, room_id, ice_servers, ... }
```

#### Accept Call
```
POST /api/calls/<call_id>/accept
Response: { call_id, status: "accepted", ... }
```

#### Decline Call
```
POST /api/calls/<call_id>/decline
{ "reason": "user_declined|busy|..." }
Response: { success: true }
```

#### End Call
```
POST /api/calls/<call_id>/hangup
{ "reason": "user_hangup|...", "duration": int }
Response: { success: true, call_summary: {...} }
```

### Call History & Statistics

#### Get Call History
```
GET /api/call-history?page=1&per_page=20&call_type=video&status=ended&date_from=2024-01-01
Response: { calls: [...], total, pages, current_page }
```

#### Get Call Statistics
```
GET /api/call-statistics?period=30d
Response: {
  total_calls, completed_calls, missed_calls, declined_calls,
  video_calls, voice_calls, average_duration
}
```

### Messaging

#### Get Conversations
```
GET /api/conversations?page=1
Response: { conversations: [...], total, pages }
```

#### Get Messages in Conversation
```
GET /api/conversations/<conversation_id>/messages?page=1
Response: { messages: [...], total, pages }
```

#### Send Message
```
POST /api/conversations/<conversation_id>/send-message
{
  "body": "message text",
  "message_type": "text|image|file|voice_note",
  "call_id": "optional-call-id"
}
Response: { message: {...} }
```

#### Mark Message as Read
```
POST /api/messages/<message_id>/mark-read
Response: { success: true, message: {...} }
```

### Presence

#### Update Presence
```
POST /api/presence/update
{
  "status": "online|away|idle|busy|offline|do_not_disturb",
  "current_call_id": "optional",
  "current_appointment_id": "optional"
}
Response: { presence: {...} }
```

#### Get User Presence
```
GET /api/presence/<user_id>
Response: { presence: { status, last_seen, ... } }
```

### Attachments

#### Upload Attachment
```
POST /api/attachments/upload
FormData: {
  file: File,
  call_id: "optional",
  message_id: "optional",
  access_control: "private|shared_call|shared_conversation"
}
Response: { attachment: {...} }
```

#### Get Attachment
```
GET /api/attachments/<attachment_id>
Response: { attachment: {...} }
```

### Quality Metrics

#### Submit Quality Metrics
```
POST /api/calls/<call_id>/quality-metrics
{
  "rtt": float,
  "packet_loss": float,
  "jitter": float,
  "audio_bitrate": int,
  "video_bitrate": int,
  "cpu_usage": float,
  "audio_quality": "excellent|good|fair|poor",
  "video_quality": "excellent|good|fair|poor"
}
Response: { metrics: {...} }
```

#### Get Quality Metrics for Call
```
GET /api/calls/<call_id>/quality-metrics
Response: { metrics: [...] }
```

## WebSocket Events

### Client → Server Signaling Events

#### Call Initiation
```javascript
socket.emit('initiate_call', {
  caller_id: int,
  callee_id: int,
  appointment_id: int,
  call_type: 'video|voice'
});
```

#### Call Control
```javascript
socket.emit('accept_call', { call_id: string, user_id: int });
socket.emit('decline_call', { call_id: string, reason: string });
socket.emit('hangup_call', { call_id: string, reason: string });
```

#### WebRTC Signaling
```javascript
socket.emit('webrtc:offer', { call_id, offer: RTCSessionDescription });
socket.emit('webrtc:answer', { call_id, answer: RTCSessionDescription });
socket.emit('webrtc:ice', { call_id, candidate: RTCIceCandidate });
```

#### Presence
```javascript
socket.emit('presence:update', {
  status: 'online|away|idle|busy|offline',
  current_call_id: optional,
  current_appointment_id: optional
});
```

#### Messaging
```javascript
socket.emit('chat:message', {
  conversation_id: int,
  call_id: optional,
  body: string,
  attachment_ids: [...]
});
socket.emit('chat:typing', { conversation_id: int });
socket.emit('chat:delivered', { message_id: int });
socket.emit('chat:read', { message_id: int });
```

### Server → Client Events

#### Call Notifications
```javascript
socket.on('call:ringing', data);
socket.on('call:accepted', data);
socket.on('call:declined', data);
socket.on('call:busy', data);
socket.on('call:connected', data);
socket.on('call:ended', data);
socket.on('call:missed', data);
socket.on('call:error', data);
```

#### WebRTC Signaling
```javascript
socket.on('webrtc:offer', data);
socket.on('webrtc:answer', data);
socket.on('webrtc:ice', data);
```

#### Presence Updates
```javascript
socket.on('presence:update', data);
socket.on('user:online', data);
socket.on('user:offline', data);
```

#### Messaging
```javascript
socket.on('chat:message', data);
socket.on('chat:delivered', data);
socket.on('chat:read', data);
socket.on('chat:typing', data);
```

## Call State Machine

```
                    ┌─────────────────────┐
                    │      IDLE           │
                    └──────────┬──────────┘
                               │ call initiate
                               ↓
                    ┌─────────────────────┐
                    │    INITIATED        │
                    └──────────┬──────────┘
                               │
                ┌──────────────┼──────────────┐
                │              │              │
         timeout│              │              │ accept
         (60s)  ↓              ↓              ↓
        MISSED  └────────────────────────────┘
                       │                │
                       │ RINGING        │ ACCEPT
                       ↓                ↓
                ┌─────────────────────┐
                │   CONNECTING        │
                └──────────┬──────────┘
                           │ media established
                           ↓
                ┌─────────────────────┐
                │   CONNECTED         │
                └──────────┬──────────┘
                           │ hangup
                           ↓
                ┌─────────────────────┐
                │      ENDED          │
                └─────────────────────┘

States:
- INITIATED: Call request created
- RINGING: Callee notified, waiting for response
- ACCEPTED: Callee accepted
- CONNECTING: Establishing media connection
- CONNECTED: Media flowing, call active
- ENDED: Call terminated
- FAILED: Connection failed or error occurred
- MISSED: No answer within timeout
```

## JavaScript Libraries

### 1. WebRTCClient (`webrtc-client.js`)
Handles all WebRTC peer connection logic:
- `initPeerConnection()` - create RTCPeerConnection
- `createOffer()` - generate SDP offer
- `receiveOffer()` / `receiveAnswer()` - handle remote SDP
- `addIceCandidate()` - add ICE candidates
- `getLocalStream()` - acquire media
- `setAudioEnabled()` / `setVideoEnabled()` - media controls
- `getStats()` - get connection statistics
- `close()` - cleanup resources

### 2. SignalingClient (`signaling-client.js`)
Wraps Socket.IO for signaling:
- `connect(userId)` - connect to signaling server
- `initiateCall()` - send call initiation
- `acceptCall()` / `declineCall()` - call control
- `sendOffer()` / `sendAnswer()` / `sendIceCandidate()` - WebRTC signaling
- `sendMessage()` - send chat message
- `updatePresence()` - update status
- Auto-reconnection with exponential backoff
- Message queue for offline mode

### 3. CallManager (`call-manager.js`)
Orchestrates WebRTC + Signaling:
- `initiateCall()` - start call as caller
- `acceptCall()` - answer call as callee
- `endCall()` - terminate call
- `toggleAudio()` / `toggleVideo()` - media control
- `startScreenShare()` - share screen
- Call state machine implementation
- Call duration tracking
- Quality monitoring
- Automatic reconnection attempts

## Security & Privacy Considerations

### Encryption
1. **Messages**: Encrypted at rest using Fernet (symmetric encryption)
2. **Media**: SRTP encryption (WebRTC standard)
3. **Signaling**: HTTPS/TLS for all connections
4. **Recordings**: Server-side encryption using KMS (optional)

### Access Control
1. **Call Participation**: Only appointment participants can join
2. **Message Access**: Only conversation participants can view
3. **Recording Access**: Role-based (patient/doctor/admin only)
4. **Admin Functions**: Verify admin role before exposing moderation features

### HIPAA Compliance (Healthcare)
1. **Audit Logging**: All call/message events logged with timestamp and user
2. **Data Retention**: Configurable retention policies
3. **Right to Erasure**: Ability to delete user data on request
4. **Encryption**: All sensitive data encrypted at rest
5. **BAA**: Business Associate Agreements with cloud providers

## Deployment Considerations

### Environment Variables
```
# WebRTC & Signaling
TURN_URL=turn:your-turn-server.com:3478
TURN_USER=username
TURN_PASS=password
ICE_SERVERS=[{"urls":"stun:stun.l.google.com:19302"}]

# Database
DATABASE_URL=postgresql://user:pass@host:5432/telemedicine

# Storage
UPLOAD_FOLDER=./uploads
S3_BUCKET=your-bucket
S3_KEY=your-key
S3_SECRET=your-secret

# Encryption
ENCRYPTION_KEY=your-32-char-encryption-key

# Features
ENABLE_CALL_RECORDING=false
CALL_RECORDING_PATH=/recordings
MAX_CALL_DURATION=3600  # 1 hour
CALL_TIMEOUT=60  # ringing timeout in seconds
```

### Scalability

#### Horizontal Scaling
1. **Signaling**: Multiple Flask instances behind load balancer
2. **WebSocket**: Use Redis for message broker (Socket.IO adapter)
3. **Database**: Connection pooling, read replicas
4. **Media**: SFU instances behind load balancer with room affinity

#### Vertical Scaling
1. Increase PostgreSQL connection pool
2. Increase Redis memory for session/presence storage
3. Optimize WebRTC constraints for bandwidth
4. Enable simulcast for quality adaptation

## Error Handling & Reconnection

### Client-Side Reconnection
```javascript
// Automatic reconnection with exponential backoff
- Attempt 1: 1 second
- Attempt 2: 2 seconds
- Attempt 3: 4 seconds
- Attempt 4: 8 seconds
- Attempt 5: 16 seconds
- Max 10 attempts
```

### Server-Side Cleanup
```
- Detect client disconnect via heartbeat (25s ping, 60s timeout)
- Mark user as offline
- End active calls after 30 seconds of no activity
- Clean up ephemeral presence data
```

## Testing

### Manual Testing Checklist
- [ ] One-to-one video call (patient ↔ doctor)
- [ ] One-to-one voice call (patient ↔ doctor)
- [ ] Call accept/decline
- [ ] Call hangup
- [ ] Media mute/unmute
- [ ] Video on/off
- [ ] Screen sharing
- [ ] In-call messaging
- [ ] Message delivery/read status
- [ ] File upload/download
- [ ] Quality degradation handling
- [ ] Network reconnection
- [ ] Call history display
- [ ] Presence updates
- [ ] Admin monitoring

### Automated Testing (Recommended)
- Unit tests for call state machine
- Integration tests for API endpoints
- End-to-end tests for call flows
- Load tests for concurrent calls
- Quality regression tests

## Future Enhancements

1. **Group Calls**: Extend to support 3+ participants
2. **Recording**: Integrate mediasoup or Janus for server-side recording
3. **Live Transcription**: Real-time speech-to-text
4. **AI Features**: Call summarization, prescription extraction
5. **Analytics Dashboard**: Admin analytics for call metrics
6. **Mobile Apps**: Native iOS/Android implementations
7. **Compliance Reports**: HIPAA audit trail exports
8. **Integration**: EHR system integration, calendar sync

## References

- WebRTC: https://webrtc.org/
- Socket.IO: https://socket.io/
- RFC 3550 (RTP): https://tools.ietf.org/html/rfc3550
- HIPAA: https://www.hhs.gov/hipaa/
- GDPR: https://gdpr-info.eu/

---

**Last Updated**: December 2024
**Version**: 1.0
**Status**: Production Ready
