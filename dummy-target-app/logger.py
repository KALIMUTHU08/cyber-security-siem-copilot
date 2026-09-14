"""
Structured logger for dummy target application.
Generates SIEM-compliant security log events and stores them locally and in-memory.
"""

import json
import uuid
from datetime import datetime, timezone
from threading import Lock
from typing import List, Dict, Any, Optional
from config import LOG_DIR, LOG_FILE

_buffer_lock = Lock()
_event_buffer: List[Dict[str, Any]] = []


def init_logger():
    """Ensure log directory exists."""
    LOG_DIR.mkdir(parents=True, exist_ok=True)


def create_security_log(
    event_type: str,
    status: str,
    source_ip: str = "127.0.0.1",
    destination_ip: str = "127.0.0.1",
    username: str = "",
    message: str = "",
    device: str = "dummy-target-portal",
    source_port: Optional[int] = None,
    destination_port: Optional[int] = 5000,
    parsed_fields: Optional[Dict[str, Any]] = None,
    timestamp: Optional[datetime] = None,
) -> Dict[str, Any]:
    """Build a SIEM-compliant security log record."""
    ts = timestamp or datetime.now(timezone.utc)
    ts_iso = ts.isoformat().replace("+00:00", "Z")
    log_id = f"target-{uuid.uuid4().hex[:8]}"

    fields = dict(parsed_fields or {})
    fields.setdefault("protocol", "HTTP")
    fields.setdefault("source_ip", source_ip)
    fields.setdefault("destination_ip", destination_ip)
    fields.setdefault("username", username)
    fields.setdefault("device", device)
    fields.setdefault("event_type", event_type)
    fields.setdefault("status", status)
    fields.setdefault("message", message)

    raw_log = f"[{ts_iso}] {device} {event_type} {status} from {source_ip} to {destination_ip}:{destination_port} user='{username}': {message}"

    log_entry = {
        "id": log_id,
        "timestamp": ts_iso,
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "source_port": source_port,
        "destination_port": destination_port,
        "username": username,
        "event_type": event_type,
        "status": status,
        "device": device,
        "message": message,
        "raw_log": raw_log,
        "parsed_fields": fields,
    }

    # Record to in-memory buffer
    with _buffer_lock:
        _event_buffer.append(log_entry)

    # Record to local JSONL file
    try:
        init_logger()
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(log_entry) + "\n")
    except Exception as e:
        print(f"[Logger Error] Failed to write to {LOG_FILE}: {e}")

    return log_entry


def get_buffered_events() -> List[Dict[str, Any]]:
    """Return all buffered events (most recent first)."""
    with _buffer_lock:
        return list(reversed(_event_buffer))


def get_raw_buffer() -> List[Dict[str, Any]]:
    """Return all buffered events in chronological order."""
    with _buffer_lock:
        return list(_event_buffer)


def clear_buffered_events():
    """Clear in-memory event buffer and local log file."""
    with _buffer_lock:
        _event_buffer.clear()
    try:
        if LOG_FILE.exists():
            LOG_FILE.unlink()
    except Exception as e:
        print(f"[Logger Error] Failed to clear log file: {e}")
