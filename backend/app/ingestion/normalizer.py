from datetime import datetime, timezone
from typing import Dict, Any, Optional
import uuid


VALID_EVENT_TYPES = {
    "LOGIN",
    "LOGIN_FAILED",
    "LOGOUT",
    "FILE_ACCESS",
    "FILE_DELETE",
    "FILE_CREATE",
    "PROCESS_STARTED",
    "NETWORK_CONNECTION",
    "CONNECTION_BLOCKED",
    "PRIVILEGE_CHANGE",
    "USER_CREATED",
    "PASSWORD_CHANGED",
    "PORT_SCAN",
    "DATA_EXFILTRATION",
}

VALID_STATUSES = {"SUCCESS", "FAILURE", "BLOCKED", "TIMEOUT", "UNKNOWN"}


def parse_iso_datetime(val: Any) -> datetime:
    if isinstance(val, datetime):
        return val.replace(tzinfo=None) if val.tzinfo else val
    if not val:
        return datetime.utcnow()
    val_str = str(val).strip()
    try:
        # Handle 'Z' suffix
        if val_str.endswith("Z"):
            val_str = val_str[:-1] + "+00:00"
        dt = datetime.fromisoformat(val_str)
        return dt.replace(tzinfo=None)
    except Exception:
        # Fallback formats
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M:%S.%f", "%Y/%m/%d %H:%M:%S"):
            try:
                return datetime.strptime(val_str, fmt)
            except ValueError:
                continue
        return datetime.utcnow()


def normalize_log_record(raw_record: Dict[str, Any], index: int = 0) -> Dict[str, Any]:
    # Extract ID or generate deterministic/unique one
    log_id = str(raw_record.get("id") or raw_record.get("log_id") or f"log-{uuid.uuid4().hex[:8]}")
    
    # Timestamp
    raw_ts = raw_record.get("timestamp") or raw_record.get("time") or raw_record.get("datetime")
    timestamp = parse_iso_datetime(raw_ts)
    
    # IPs
    source_ip = str(raw_record.get("sourceIp") or raw_record.get("source_ip") or raw_record.get("src_ip") or "127.0.0.1").strip()
    destination_ip = str(raw_record.get("destinationIp") or raw_record.get("destination_ip") or raw_record.get("dst_ip") or "").strip()
    
    # Ports
    def parse_port(p: Any) -> Optional[int]:
        if p is None or p == "":
            return None
        try:
            val = int(p)
            return val if 0 <= val <= 65535 else None
        except (ValueError, TypeError):
            return None

    source_port = parse_port(raw_record.get("sourcePort") or raw_record.get("source_port") or raw_record.get("src_port"))
    destination_port = parse_port(raw_record.get("destinationPort") or raw_record.get("destination_port") or raw_record.get("dst_port"))
    
    # Username & Device
    username = str(raw_record.get("username") or raw_record.get("user") or "").strip()
    device = str(raw_record.get("device") or raw_record.get("hostname") or raw_record.get("host") or "Unknown-Host").strip()
    
    # Event Type
    raw_event_type = str(raw_record.get("eventType") or raw_record.get("event_type") or raw_record.get("type") or "LOGIN").strip().upper()
    if raw_event_type not in VALID_EVENT_TYPES:
        # Mapping helpers
        if "FAIL" in raw_event_type:
            event_type = "LOGIN_FAILED"
        elif "PRIV" in raw_event_type or "SUDO" in raw_event_type:
            event_type = "PRIVILEGE_CHANGE"
        elif "PORT" in raw_event_type or "SCAN" in raw_event_type:
            event_type = "PORT_SCAN"
        elif "NET" in raw_event_type or "CONN" in raw_event_type:
            event_type = "NETWORK_CONNECTION"
        elif "FILE" in raw_event_type:
            event_type = "FILE_ACCESS"
        else:
            event_type = "LOGIN"
    else:
        event_type = raw_event_type
        
    # Status
    raw_status = str(raw_record.get("status") or "SUCCESS").strip().upper()
    status = raw_status if raw_status in VALID_STATUSES else ("FAILURE" if "FAIL" in raw_status else "SUCCESS")
    
    # Message and Raw log
    message = str(raw_record.get("message") or raw_record.get("msg") or f"{event_type} {status} by {username or 'unknown'} on {device}").strip()
    raw_log = str(raw_record.get("rawLog") or raw_record.get("raw_log") or raw_record.get("raw") or f"[{timestamp.isoformat()}] {device} {event_type} {status}: {message}").strip()
    
    # Parsed fields
    parsed_fields = raw_record.get("parsedFields") or raw_record.get("parsed_fields") or {}
    if not isinstance(parsed_fields, dict):
        parsed_fields = {}
    
    # Enrich parsed fields if empty
    if not parsed_fields:
        parsed_fields = {
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "username": username,
            "device": device,
            "event_type": event_type,
            "status": status,
            "message": message,
        }
        if source_port:
            parsed_fields["source_port"] = str(source_port)
        if destination_port:
            parsed_fields["destination_port"] = str(destination_port)

    return {
        "id": log_id,
        "timestamp": timestamp,
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "source_port": source_port,
        "destination_port": destination_port,
        "username": username,
        "event_type": event_type,
        "status": status,
        "device": device,
        "raw_log": raw_log,
        "parsed_fields": parsed_fields,
        "related_alert_ids": [],
        "related_incident_ids": [],
    }
