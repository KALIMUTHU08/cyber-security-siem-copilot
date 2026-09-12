"""
Dataset Adapter — Kaggle Cybersecurity Threat Detection Logs
============================================================
Maps the Kaggle dataset CSV schema to internal SecurityLog records.

CSV columns:
    timestamp, source_ip, dest_ip, protocol, action,
    threat_label, log_type, bytes_transferred, user_agent, request_path

Rules:
    - threat_label is ground truth and MUST NOT be used as a detection trigger.
      It is stored in parsed_fields["_ground_truth"] only.
    - All field mapping is purely structural (no label-based shortcuts).
    - Yields records in configurable chunk sizes to avoid OOM on 6M rows.
"""

import csv
import uuid
from datetime import datetime
from pathlib import Path
from typing import Iterator, List, Dict, Any, Optional, Tuple


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
CHUNK_SIZE = 5_000
MAX_ROWS = None


# ---------------------------------------------------------------------------
# Field mapping helpers
# ---------------------------------------------------------------------------
PROTOCOL_TO_PORT = {
    "HTTP": 80,
    "HTTPS": 443,
    "FTP": 21,
    "SSH": 22,
    "ICMP": None,
    "TCP": None,
    "UDP": None,
}

ACTION_TO_STATUS = {
    "allowed": "SUCCESS",
    "blocked": "BLOCKED",
}

LOGTYPE_PROTO_EVENT = {
    ("firewall", "blocked"): "CONNECTION_BLOCKED",
    ("firewall", "allowed"): "NETWORK_CONNECTION",
    ("ids", "blocked"): "CONNECTION_BLOCKED",
    ("ids", "allowed"): "NETWORK_CONNECTION",
    ("application", "allowed"): "NETWORK_CONNECTION",
    ("application", "blocked"): "CONNECTION_BLOCKED",
}

LOGIN_PATHS = {"/login", "/auth", "/api/login", "/wp-login.php", "/signin"}
ADMIN_PATHS = {"/admin/config", "/dashboard", "/secure"}
DATA_PATHS  = {"/api/v1/data", "/index.php"}


def _path_to_event_type(path, protocol, log_type, action):
    p = (path or "").lower().strip()
    proto = (protocol or "").upper()
    base = LOGTYPE_PROTO_EVENT.get((log_type.lower(), action.lower()), "NETWORK_CONNECTION")

    if p in LOGIN_PATHS:
        return "LOGIN_FAILED" if action.lower() == "blocked" else "LOGIN"
    if p in ADMIN_PATHS and proto in ("HTTP", "HTTPS"):
        return "FILE_ACCESS"
    if proto == "FTP":
        return "DATA_EXFILTRATION" if action.lower() == "blocked" else "FILE_ACCESS"
    if proto == "SSH":
        return "LOGIN_FAILED" if action.lower() == "blocked" else "LOGIN"
    return base


def _parse_timestamp(ts_str):
    if not ts_str:
        return datetime.utcnow()
    try:
        val = ts_str.strip()
        if val.endswith("Z"):
            val = val[:-1] + "+00:00"
        dt = datetime.fromisoformat(val)
        return dt.replace(tzinfo=None)
    except Exception:
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d", "%Y/%m/%d %H:%M:%S"):
            try:
                return datetime.strptime(ts_str.strip(), fmt)
            except ValueError:
                continue
    return datetime.utcnow()


def _build_log_record(row, row_num):
    timestamp    = _parse_timestamp(row.get("timestamp", ""))
    source_ip    = (row.get("source_ip") or "0.0.0.0").strip()
    dest_ip      = (row.get("dest_ip") or "").strip()
    protocol     = (row.get("protocol") or "TCP").strip().upper()
    action       = (row.get("action") or "allowed").strip().lower()
    log_type     = (row.get("log_type") or "firewall").strip().lower()
    request_path = (row.get("request_path") or "/").strip()
    user_agent   = (row.get("user_agent") or "").strip()
    bytes_str    = row.get("bytes_transferred", "0") or "0"
    threat_label = (row.get("threat_label") or "benign").strip().lower()

    try:
        bytes_transferred = int(bytes_str)
    except ValueError:
        bytes_transferred = 0

    event_type = _path_to_event_type(request_path, protocol, log_type, action)
    status     = ACTION_TO_STATUS.get(action, "SUCCESS")
    dest_port  = PROTOCOL_TO_PORT.get(protocol)

    device_map = {"firewall": "FW-NODE", "ids": "IDS-SENSOR", "application": "APP-SERVER"}
    device = device_map.get(log_type, "UNKNOWN-HOST")

    message = f"{protocol} {action.upper()} {source_ip} to {dest_ip}{request_path} [{log_type.upper()}] {bytes_transferred}B"
    raw_log = f"[{timestamp.isoformat()}] {device} {event_type} {status} src={source_ip} dst={dest_ip} proto={protocol} path={request_path}"

    parsed_fields = {
        "source_ip": source_ip,
        "destination_ip": dest_ip,
        "protocol": protocol,
        "action": action,
        "log_type": log_type,
        "request_path": request_path,
        "user_agent": user_agent,
        "bytes_transferred": bytes_transferred,
        "event_type": event_type,
        "status": status,
        "_ground_truth": threat_label,
    }

    return {
        "id": f"ds-{uuid.uuid4().hex[:10]}",
        "timestamp": timestamp,
        "source_ip": source_ip,
        "destination_ip": dest_ip,
        "source_port": None,
        "destination_port": dest_port,
        "username": "",
        "event_type": event_type,
        "status": status,
        "device": device,
        "raw_log": raw_log,
        "parsed_fields": parsed_fields,
        "related_alert_ids": [],
        "related_incident_ids": [],
        "message": message,
    }


def stream_dataset_chunks(csv_path, chunk_size=CHUNK_SIZE, max_rows=MAX_ROWS, skip_rows=0):
    path = Path(csv_path)
    if not path.exists():
        raise FileNotFoundError(f"Dataset not found: {path}")

    chunk = []
    total_read = 0

    with open(path, encoding="utf-8", errors="replace", newline="") as fh:
        reader = csv.DictReader(fh)
        for row_num, row in enumerate(reader, start=1):
            if row_num <= skip_rows:
                continue
            if max_rows is not None and total_read >= max_rows:
                break
            try:
                record = _build_log_record(row, row_num)
                chunk.append(record)
                total_read += 1
            except Exception:
                continue

            if len(chunk) >= chunk_size:
                yield chunk, total_read
                chunk = []

    if chunk:
        yield chunk, total_read


def get_dataset_info(csv_path):
    path = Path(csv_path)
    if not path.exists():
        return {"exists": False, "path": str(path)}

    size_mb = path.stat().st_size / (1024 * 1024)
    preview_rows = []
    with open(path, encoding="utf-8", errors="replace", newline="") as fh:
        reader = csv.DictReader(fh)
        columns = list(reader.fieldnames or [])
        for i, row in enumerate(reader):
            if i >= 5:
                break
            preview_rows.append(dict(row))

    return {
        "exists": True,
        "path": str(path),
        "size_mb": round(size_mb, 1),
        "columns": columns,
        "preview": preview_rows,
    }
