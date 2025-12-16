# API Quick Reference Guide

## Base URL
```
http://localhost:5000/api
```

## Authentication
All endpoints require:
- User to be logged in (`@login_required`)
- CSRF token in headers or form data
- Proper role/permissions

## Call Management Endpoints

### Initiate Call
```
POST /api/calls/initiate
Content-Type: application/json

{
  "callee_id": 123,
  "appointment_id": 456,
  "call_type": "video" // or "voice"
}

Response: {
  "success": true,
  "data": {
    "call_id": "uuid-string",
    "room_id": "room-identifier",
    "ice_servers": [...]
  }
}
```

### Accept Call
```
POST /api/calls/<call_id>/accept
Content-Type: application/json

{}

Response: {
  "success": true,
  "data": {
    "call_id": "uuid-string",
    "status": "accepted",
    "room_id": "room-identifier"
  }
}
```

### Decline/Reject Call
```
POST /api/calls/<call_id>/decline
Content-Type: application/json

{
  "reason": "user_declined" // or "busy"
}

Response: {
  "success": true
}
```

### End Call
```
POST /api/calls/<call_id>/hangup
Content-Type: application/json

{
  "reason": "user_hangup",
  "duration": 300  // seconds
}

Response: {
  "success": true
}
```

## Call History Endpoints

### List Call History
```
GET /api/call-history?page=1&per_page=20&call_type=video&status=completed&date_from=2024-01-01&date_to=2024-12-31

Response: {
  "success": true,
  "data": {
    "calls": [{
      "call_id": "uuid",
      "caller_name": "Dr. Smith",
      "callee_name": "John Doe",
      "call_type": "video",
      "duration": 1200,
      "initiated_at": "2024-12-08T10:30:00Z",
      "status": "completed",
      "quality_assessment": "good"
    }],
    "total": 150,
    "pages": 8,
    "current_page": 1
  }
}
```

### Get Call Detail
```
GET /api/call-history/<call_id>

Response: {
  "success": true,
  "data": {
    "call_id": "uuid",
    "caller_id": 1,
    "caller_name": "Dr. Smith",
    "callee_id": 2,
    "callee_name": "John Doe",
    "call_type": "video",
    "duration": 1200,
    "initiated_at": "2024-12-08T10:30:00Z",
    "accepted_at": "2024-12-08T10:31:00Z",
    "connected_at": "2024-12-08T10:31:30Z",
    "ended_at": "2024-12-08T10:51:30Z",
    "status": "completed",
    "quality_metrics": {
      "1": {"rtt": 45, "packet_loss": 0.2, "audio_quality": "good"},
      "2": {"rtt": 42, "packet_loss": 0.1, "audio_quality": "excellent"}
    }
  }
}
```

### Get Call Statistics
```
GET /api/call-statistics?period=30d

Response: {
  "success": true,
  "data": {
    "total_calls": 245,
    "completed_calls": 220,
    "missed_calls": 15,
    "declined_calls": 10,
    "video_calls": 150,
    "voice_calls": 95,
    "average_duration": 720
  }
}
```

## Messaging Endpoints

### Get Conversations
```
GET /api/conversations?page=1

Response: {
  "success": true,
  "data": {
    "conversations": [{
      "conversation_id": "uuid",
      "participant_ids": [1, 2],
      "conversation_type": "direct",
      "last_message_at": "2024-12-08T15:30:00Z",
      "unread_count": 3
    }],
    "total": 45,
    "pages": 3,
    "current_page": 1
  }
}
```

### Get Messages in Conversation
```
GET /api/conversations/<conversation_id>/messages?page=1&per_page=50

Response: {
  "success": true,
  "data": {
    "messages": [{
      "message_id": "uuid",
      "sender_id": 1,
      "sender_name": "Dr. Smith",
      "body": "How are you feeling today?",
      "message_type": "text",
      "status": "read",
      "created_at": "2024-12-08T14:20:00Z",
      "delivered_at": "2024-12-08T14:20:01Z",
      "read_at": "2024-12-08T14:20:30Z"
    }],
    "total": 150,
    "pages": 3,
    "current_page": 1
  }
}
```

### Send Message
```
POST /api/conversations/<conversation_id>/send-message
Content-Type: application/json

{
  "body": "I'm feeling much better",
  "message_type": "text",  // text, image, file, voice_note
  "call_id": "optional-uuid"  // for in-call messages
}

Response: {
  "success": true,
  "data": {
    "message_id": "uuid",
    "sender_id": 2,
    "body": "I'm feeling much better",
    "message_type": "text",
    "status": "sent",
    "created_at": "2024-12-08T14:25:00Z"
  }
}
```

### Mark Message as Read
```
POST /api/messages/<message_id>/mark-read

Response: {
  "success": true,
  "data": {
    "message_id": "uuid",
    "status": "read",
    "read_at": "2024-12-08T14:25:30Z"
  }
}
```

## Presence Endpoints

### Update Presence
```
POST /api/presence/update
Content-Type: application/json

{
  "status": "online",  // online, away, idle, busy, offline, do_not_disturb
  "current_call_id": "optional-uuid",
  "current_appointment_id": 456
}

Response: {
  "success": true,
  "data": {
    "user_id": 1,
    "status": "online",
    "last_heartbeat": "2024-12-08T15:45:00Z"
  }
}
```

### Get User Presence
```
GET /api/presence/<user_id>

Response: {
  "success": true,
  "data": {
    "user_id": 1,
    "status": "online",
    "last_seen": "2024-12-08T15:45:00Z",
    "current_call_id": null,
    "current_appointment_id": 456,
    "device_type": "web"
  }
}
```

### Get Online Users
```
GET /api/presence/online-users?role=doctor

Response: {
  "success": true,
  "data": [
    {
      "user_id": 1,
      "name": "Dr. Smith",
      "role": "doctor",
      "status": "online",
      "last_seen": "2024-12-08T15:45:00Z",
      "device_type": "web"
    }
  ]
}
```

## Attachment Endpoints

### Upload Attachment
```
POST /api/attachments/upload
Content-Type: multipart/form-data

Form Data:
  file: <binary-file>
  call_id: "optional-uuid"
  message_id: "optional-uuid"
  access_control: "private"  // private, shared_call, shared_conversation

Response: {
  "success": true,
  "data": {
    "attachment_id": "uuid",
    "file_name": "document.pdf",
    "file_type": "application/pdf",
    "file_size": 102400,
    "file_url": "https://storage.example.com/path/to/file",
    "uploaded_at": "2024-12-08T15:50:00Z"
  }
}
```

### Get Attachment Metadata
```
GET /api/attachments/<attachment_id>

Response: {
  "success": true,
  "data": {
    "attachment_id": "uuid",
    "file_name": "document.pdf",
    "file_type": "application/pdf",
    "file_size": 102400,
    "file_url": "https://storage.example.com/path/to/file",
    "owner_id": 1,
    "access_control": "private",
    "uploaded_at": "2024-12-08T15:50:00Z"
  }
}
```

## Quality Metrics Endpoints

### Submit Quality Metrics
```
POST /api/calls/<call_id>/quality-metrics
Content-Type: application/json

{
  "rtt": 45,  // milliseconds
  "packet_loss": 0.2,  // percentage
  "jitter": 8,  // milliseconds
  "audio_bitrate": 128,  // kbps
  "video_bitrate": 2500,  // kbps
  "video_resolution": "1280x720",
  "video_framerate": 30,
  "cpu_usage": 25.5,  // percentage
  "memory_usage": 512,  // MB
  "audio_quality": "good",  // excellent, good, fair, poor
  "video_quality": "excellent"
}

Response: {
  "success": true,
  "data": {
    "metric_id": "uuid",
    "call_id": "uuid",
    "user_id": 1,
    "rtt": 45,
    "packet_loss": 0.2,
    "audio_quality": "good",
    "video_quality": "excellent",
    "timestamp": "2024-12-08T15:55:00Z"
  }
}
```

### Get Quality Metrics for Call
```
GET /api/calls/<call_id>/quality-metrics

Response: {
  "success": true,
  "data": [
    {
      "metric_id": "uuid",
      "user_id": 1,
      "user_name": "Dr. Smith",
      "rtt": 45,
      "packet_loss": 0.2,
      "jitter": 8,
      "audio_bitrate": 128,
      "video_bitrate": 2500,
      "audio_quality": "good",
      "video_quality": "excellent",
      "timestamp": "2024-12-08T15:55:00Z"
    },
    {
      "metric_id": "uuid2",
      "user_id": 2,
      "user_name": "John Doe",
      "rtt": 42,
      "packet_loss": 0.1,
      "jitter": 6,
      "audio_bitrate": 128,
      "video_bitrate": 2800,
      "audio_quality": "excellent",
      "video_quality": "excellent",
      "timestamp": "2024-12-08T15:55:00Z"
    }
  ]
}
```

## WebSocket Events (Socket.IO)

### Client to Server

```javascript
// Call signaling
socket.emit('call:initiate', { 
  callee_id, appointment_id, call_type 
});
socket.emit('call:accept', { call_id });
socket.emit('call:decline', { call_id, reason });
socket.emit('call:end', { call_id, reason, duration });

// WebRTC signaling
socket.emit('webrtc:offer', { call_id, offer });
socket.emit('webrtc:answer', { call_id, answer });
socket.emit('webrtc:ice', { call_id, candidate });

// Presence
socket.emit('presence:update', { 
  status, current_call_id, current_appointment_id 
});

// Chat
socket.emit('chat:message', { 
  conversation_id, body, message_type, call_id 
});
socket.emit('chat:delivered', { message_id });
socket.emit('chat:read', { message_id });
```

### Server to Client

```javascript
// Call notifications
socket.on('call_initiated', data);
socket.on('call_accepted', data);
socket.on('call_declined', data);
socket.on('call_ended', data);
socket.on('call_connected', data);

// WebRTC signaling
socket.on('webrtc:offer', data);
socket.on('webrtc:answer', data);
socket.on('webrtc:ice', data);

// Presence
socket.on('presence:updated', data);
socket.on('user:online', data);
socket.on('user:offline', data);

// Chat
socket.on('chat:message', data);
socket.on('chat:delivered', data);
socket.on('chat:read', data);

// Quality
socket.on('quality:recorded', data);
```

## Error Responses

All endpoints return error responses in this format:

```json
{
  "success": false,
  "error": "Descriptive error message",
  "code": 400
}
```

Common HTTP Status Codes:
- `200` - Success
- `400` - Bad request (validation error)
- `403` - Forbidden (permission denied)
- `404` - Not found
- `500` - Server error

## Rate Limiting

- Messages: 10 per minute per user
- Call initiation: 1 per 5 seconds per user
- Quality metrics: 1 per second per call
- Attachment upload: 10 per hour per user

## Implementation Notes

1. All timestamps are in ISO 8601 format (UTC)
2. IDs are UUID strings unless specified as integers
3. Pagination defaults: page=1, per_page=20
4. Access control enforced on all operations
5. All responses wrapped in `{ success, data/error, code }`
6. Encryption applied to message bodies and attachments
7. Quality metrics collected automatically by client
8. Presence updates tracked with heartbeat timeout

---

**Last Updated:** December 8, 2025  
**Version:** 1.0  
**Status:** Production Ready
