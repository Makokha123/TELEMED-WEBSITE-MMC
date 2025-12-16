import os
import json
import hmac
import hashlib
import ipaddress
from datetime import datetime, timezone, timedelta
import time

from flask import Blueprint, current_app as app, request, jsonify, g
from sqlalchemy import text

# Optional Marshmallow schema validation
try:
    from marshmallow import Schema, fields, ValidationError
except Exception:
    Schema = None
    fields = None
    ValidationError = Exception

from models import (
    db,
    Payment,
    PaymentLedger,
    WebhookEvent,
    IdempotencyKey,
    Appointment,
    Patient,
)

v1_bp = Blueprint("v1", __name__)

# In-memory basic metrics
metrics = {
    "requests_total": 0,
    "requests_by_path": {},
    "webhooks_total": 0,
    "webhooks_processed": 0,
    "webhooks_duplicates": 0,
    "webhooks_failed": 0,
}

# Marshmallow schema for payment initiation (if available)
if Schema is not None:
    class PaymentInitiateSchema(Schema):
        appointment_id = fields.Integer(required=True)
        amount = fields.Float(required=True)
        currency = fields.String(required=False, load_default="KES")
        provider = fields.String(required=True)
        provider_token = fields.String(required=False, allow_none=True)
        reference = fields.String(required=False, allow_none=True)
        psp_reference = fields.String(required=False, allow_none=True)
else:
    PaymentInitiateSchema = None

# ---------------------
# Helpers and middleware
# ---------------------

def _now():
    return datetime.now(timezone.utc)


def _json_error(code: str, http_status: int = 400, message: str = None, details: dict = None):
    return jsonify({
        "error": {
            "code": code,
            "message": message or code,
            "details": details or {},
            "request_id": getattr(g, "request_id", None)
        }
    }), http_status


@v1_bp.before_app_request
def attach_request_context():
    # Only attach for API v1 routes to avoid impacting existing views
    if not request.path.startswith("/api/v1/"):
        return
    # lightweight request id
    rid = hashlib.sha256(f"{_now().timestamp()}|{request.remote_addr}|{os.urandom(8).hex()}".encode()).hexdigest()[:16]
    g.request_id = rid
    g._start_ts = _now()
    # metrics counters
    try:
        metrics["requests_total"] += 1
        metrics["requests_by_path"][request.path] = metrics["requests_by_path"].get(request.path, 0) + 1
    except Exception:
        pass


@v1_bp.after_app_request
def access_log(response):
    try:
        if request.path.startswith("/api/v1/"):
            duration_ms = None
            try:
                duration_ms = int(((_now() - g._start_ts).total_seconds()) * 1000) if getattr(g, "_start_ts", None) else None
            except Exception:
                duration_ms = None
            log = {
                "ts": _now().isoformat(),
                "logger": "access",
                "level": "INFO",
                "method": request.method,
                "path": request.path,
                "status": response.status_code,
                "duration_ms": duration_ms,
                "ip": request.headers.get("X-Forwarded-For", request.remote_addr),
                "request_id": getattr(g, "request_id", None),
                "user_id": getattr(getattr(request, 'user', None), 'id', None)
            }
            app.logger.info(json.dumps(log))
    except Exception:
        pass
    return response


# ---------------------
# Idempotency utilities
# ---------------------

def _request_hash():
    try:
        body = request.get_data(cache=True) or b""
        return hashlib.sha256(body).hexdigest()
    except Exception:
        return None


def enforce_idempotency():
    key = request.headers.get("Idempotency-Key")
    if not key:
        return None, None
    rec = IdempotencyKey.query.filter_by(key=key).first()
    req_hash = _request_hash()
    if rec:
        # Return stored response for same key
        return rec, (jsonify(rec.response_body), rec.status_code or 200)
    return None, req_hash


def persist_idempotent_response(key: str, req_hash: str, status_code: int, body: dict):
    try:
        ttl_days = int(os.getenv("IDEMPOTENCY_TTL_DAYS", "7"))
        rec = IdempotencyKey(
            key=key,
            request_hash=req_hash,
            method=request.method,
            path=request.path,
            status_code=status_code,
            response_body=body,
            expires_at=_now() + timedelta(days=ttl_days)
        )
        db.session.add(rec)
        db.session.commit()
    except Exception:
        try:
            db.session.rollback()
        except Exception:
            pass


# ---------------------
# Payments initiation (idempotent)
# ---------------------

@v1_bp.post("/api/v1/payments/initiate")
def payments_initiate():
    # Enforce no raw card data; require PSP token/reference
    try:
        payload = request.get_json(force=True)
    except Exception:
        return _json_error("invalid_json", 400, "Request body must be valid JSON")

    if not isinstance(payload, dict):
        return _json_error("invalid_payload", 400)

    # Reject direct card data
    prohibited = {"card", "card_number", "number", "cvv", "cvc", "expiry", "exp_month", "exp_year"}
    if any(k in payload for k in prohibited):
        return _json_error("card_data_not_allowed", 422, message="Direct card data is not accepted. Use PSP tokens/refs.")

    # Marshmallow validation if available
    if PaymentInitiateSchema is not None:
        try:
            data = PaymentInitiateSchema().load(payload)
        except ValidationError as ve:
            return _json_error("validation_error", 422, details=ve.messages)
        appointment_id = data.get("appointment_id")
        amount = data.get("amount")
        currency = data.get("currency", "KES")
        provider = data.get("provider")
        provider_token = data.get("provider_token") or data.get("reference") or data.get("psp_reference")
    else:
        # Fallback basic validation
        appointment_id = payload.get("appointment_id")
        amount = payload.get("amount")
        currency = payload.get("currency", "KES")
        provider = payload.get("provider")
        provider_token = payload.get("provider_token") or payload.get("reference") or payload.get("psp_reference")
        if not appointment_id or not isinstance(appointment_id, int):
            return _json_error("missing_appointment_id", 422, details={"field": "appointment_id"})
        if not amount or not isinstance(amount, (int, float)) or amount <= 0:
            return _json_error("invalid_amount", 422, details={"field": "amount"})
        if not provider:
            return _json_error("missing_provider", 422, details={"field": "provider"})
        if not provider_token:
            return _json_error("missing_provider_token", 422, details={"field": "provider_token"})

    # Idempotency
    idemp_rec, idemp_resp = enforce_idempotency()
    if idemp_resp:
        return idemp_resp

    # Confirm appointment exists and relates to a patient
    appt = db.session.get(Appointment, int(appointment_id))
    if not appt:
        return _json_error("appointment_not_found", 404)

    # Find patient from appointment
    patient = db.session.get(Patient, appt.patient_id) if appt.patient_id else None

    # Create or update Payment row
    payment = Payment.query.filter_by(appointment_id=appt.id).order_by(Payment.created_at.desc()).first()
    if not payment:
        payment = Payment(
            appointment_id=appt.id,
            patient_id=patient.id if patient else None,
            amount=float(amount),
            currency=currency,
            provider=provider,
            status='pending'
        )
        db.session.add(payment)
    else:
        # Ensure amount/currency/provider are up to date
        payment.amount = float(amount)
        payment.currency = currency
        payment.provider = provider
        payment.status = payment.status or 'pending'

    # Store provider reference token (not PAN)
    try:
        payment.provider_reference = str(provider_token)
        db.session.commit()
    except Exception:
        db.session.rollback()
        return _json_error("db_error", 500, "Failed to persist payment")

    # Response body (no secrets)
    body = {
        "payment_id": payment.id,
        "appointment_id": appt.id,
        "amount": payment.amount,
        "currency": payment.currency,
        "status": payment.status,
        "provider": payment.provider,
    }

    key = request.headers.get("Idempotency-Key")
    if key:
        persist_idempotent_response(key, _request_hash(), 201, body)

    return jsonify(body), 201


# ---------------------
# Webhooks (signature verification + idempotency + ledger)
# ---------------------


def _is_ip_allowed(remote_ip: str) -> bool:
    cidrs = app.config.get("WEBHOOK_IP_ALLOWLIST", []) or []
    if not cidrs:
        return True  # not enforced
    try:
        ip = ipaddress.ip_address(remote_ip)
        for cidr in cidrs:
            try:
                if ip in ipaddress.ip_network(cidr):
                    return True
            except Exception:
                continue
    except Exception:
        return False
    return False


@v1_bp.post("/api/v1/webhooks/payments/<provider>")
def payments_webhook(provider):
    # Optional IP allowlist
    try:
        metrics["webhooks_total"] += 1
    except Exception:
        pass
    remote_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    if not _is_ip_allowed(remote_ip):
        app.logger.warning(json.dumps({
            "logger": "security",
            "event": "webhook_ip_blocked",
            "provider": provider,
            "ip": remote_ip,
            "request_id": getattr(g, "request_id", None)
        }))
        return _json_error("forbidden", 403, "IP not allowed")

    secret_map = app.config.get('PAYMENT_PROVIDER_SECRETS', {}) or {}
    secret = secret_map.get(provider)
    if not secret:
        return _json_error("provider_not_configured", 400)

    raw = request.get_data()
    signature = request.headers.get('X-Signature') or request.headers.get('Stripe-Signature')

    # Verify HMAC (generic shared-secret approach). For Stripe, prefer official lib elsewhere.
    try:
        digest = hmac.new(secret.encode(), raw or b"", hashlib.sha256).hexdigest()
        if signature and (signature != digest):
            return _json_error("invalid_signature", 401)
    except Exception:
        return _json_error("signature_verification_failed", 401)

    # Parse JSON
    try:
        payload = json.loads(raw.decode('utf-8') or '{}')
    except Exception:
        payload = {}

    # Determine unique ids
    event_id = request.headers.get('X-Event-Id') or payload.get('event_id') or payload.get('id')
    if not event_id:
        # fallback to hash of content
        event_id = hashlib.sha256((signature or '') .encode() + (raw or b'')).hexdigest()

    # Idempotency of webhook events
    existing = WebhookEvent.query.filter_by(event_id=event_id).first()
    if existing:
        try:
            existing.status = 'duplicate'
            existing.processed_at = _now()
            db.session.add(existing)
            db.session.commit()
        except Exception:
            db.session.rollback()
        try:
            metrics["webhooks_duplicates"] += 1
        except Exception:
            pass
        return jsonify({"ok": True, "duplicate": True})

    # Create event record first (so duplicates are short-circuited next time)
    event = WebhookEvent(
        provider=provider,
        event_id=event_id,
        signature=signature,
        status='received',
        raw_event=payload,
    )
    db.session.add(event)
    try:
        db.session.commit()
    except Exception:
        db.session.rollback()
        # Even if we can't persist event, continue processing but idempotency may not be guaranteed

    # Map payload to canonical data
    payment_id = payload.get('payment_id') or payload.get('metadata', {}).get('payment_id')
    external_payment_id = payload.get('transaction_id') or payload.get('payment_intent_id') or payload.get('id')
    provider_reference = payload.get('provider_reference') or external_payment_id
    raw_status = (payload.get('status') or '').lower()

    status_map = {
        'paid': 'succeeded',
        'success': 'succeeded',
        'succeeded': 'succeeded',
        'completed': 'succeeded',
        'pending': 'pending',
        'processing': 'pending',
        'failed': 'failed',
        'declined': 'failed',
        'cancelled': 'cancelled',
        'refunded': 'refunded',
    }
    canonical = status_map.get(raw_status, 'pending')

    # Upsert into ledger
    ledger = None
    if external_payment_id:
        ledger = PaymentLedger.query.filter_by(external_payment_id=str(external_payment_id)).first()
    if not ledger:
        ledger = PaymentLedger(
            external_payment_id=str(external_payment_id or f"evt:{event_id}"),
            appointment_id=payload.get('appointment_id'),
            patient_id=payload.get('patient_id'),
            amount=payload.get('amount'),
            currency=payload.get('currency'),
            provider=provider,
            status=canonical,
            raw_event=payload,
        )
        db.session.add(ledger)
    else:
        ledger.status = canonical
        ledger.raw_event = payload
        if payload.get('amount'):
            ledger.amount = payload.get('amount')
        if payload.get('currency'):
            ledger.currency = payload.get('currency')
        if payload.get('appointment_id'):
            ledger.appointment_id = payload.get('appointment_id')
        if payload.get('patient_id'):
            ledger.patient_id = payload.get('patient_id')

    # Update Payment if identifiable
    payment = None
    if payment_id:
        try:
            payment = db.session.get(Payment, int(payment_id))
        except Exception:
            payment = None
    if not payment and ledger and ledger.appointment_id:
        payment = Payment.query.filter_by(appointment_id=ledger.appointment_id).order_by(Payment.created_at.desc()).first()

    if payment:
        if canonical == 'succeeded':
            payment.status = 'paid'
        elif canonical in ('failed', 'cancelled'):
            payment.status = 'failed'
        elif canonical == 'refunded':
            payment.status = 'cancelled'
        else:
            payment.status = 'pending'
        if provider_reference:
            payment.provider_reference = str(provider_reference)
        ledger.payment_id = payment.id

    try:
        event.status = 'processed'
        event.processed_at = _now()
        db.session.add(event)
        db.session.add(ledger)
        if payment:
            db.session.add(payment)
        db.session.commit()
        try:
            metrics["webhooks_processed"] += 1
        except Exception:
            pass
    except Exception as e:
        db.session.rollback()
        try:
            event.status = 'failed'
            event.error_message = str(e)
            db.session.add(event)
            db.session.commit()
        except Exception:
            db.session.rollback()
        try:
            metrics["webhooks_failed"] += 1
        except Exception:
            pass
        return _json_error("db_error", 500, "Failed to persist webhook")

    return jsonify({"ok": True})


# ---------------------
# Health and readiness
# ---------------------

@v1_bp.get("/api/v1/healthz")
def healthz():
    return jsonify({"status": "ok", "ts": _now().isoformat()})


@v1_bp.get("/api/v1/readyz")
def readyz():
    # Check DB connectivity and presence of a core table
    try:
        db.session.execute(text("SELECT 1"))
        db_ok = True
    except Exception:
        db_ok = False
    return jsonify({
        "status": "ok" if db_ok else "degraded",
        "db": db_ok,
        "ts": _now().isoformat()
    }), (200 if db_ok else 503)


@v1_bp.get("/api/v1/metrics")
def get_metrics():
    # Return in-memory counters (for dev/observability bootstrapping)
    try:
        snapshot = dict(metrics)
        snapshot["requests_by_path"] = dict(metrics.get("requests_by_path", {}))
    except Exception:
        snapshot = {}
    return jsonify({"metrics": snapshot, "ts": _now().isoformat()})
