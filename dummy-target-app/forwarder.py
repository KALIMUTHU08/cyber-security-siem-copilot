"""
Log forwarding client for transmitting security logs to the SIEM Copilot backend.
Uses HTTP multipart upload to the SIEM's /api/logs/upload endpoint.
"""

import json
from typing import List, Dict, Any
import httpx

from config import SIEM_INGEST_URL, SIEM_API_TOKEN


def forward_logs_to_siem(
    events: List[Dict[str, Any]],
    target_url: str = SIEM_INGEST_URL,
    token: str = SIEM_API_TOKEN,
) -> Dict[str, Any]:
    """
    Forward log events to the SIEM ingestion endpoint.
    Sends logs as a JSON batch via multipart file upload to /api/logs/upload.
    """
    if not events:
        return {
            "success": False,
            "message": "No logs in buffer to forward.",
            "stats": None,
            "error_detail": None,
        }

    payload_json = json.dumps(events)
    files = {
        "file": ("dummy_events.json", payload_json.encode("utf-8"), "application/json")
    }

    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    try:
        with httpx.Client(timeout=10.0) as client:
            response = client.post(target_url, files=files, headers=headers)

        if response.status_code == 200:
            stats = response.json()
            alerts = stats.get("alertsGenerated", 0)
            incidents = stats.get("incidentsUpdated", 0)
            processed = stats.get("processed", len(events))
            msg = f"Successfully forwarded {processed} events to SIEM. Pipeline produced {alerts} alert(s) and {incidents} incident(s)."
            return {
                "success": True,
                "message": msg,
                "stats": stats,
                "error_detail": None,
            }
        else:
            return {
                "success": False,
                "message": f"SIEM returned HTTP {response.status_code}: {response.text[:200]}",
                "stats": None,
                "error_detail": response.text,
            }
    except httpx.ConnectError:
        return {
            "success": False,
            "message": f"Connection refused by SIEM backend at {target_url}. Ensure the SIEM backend is running locally (e.g., uvicorn app.main:app on port 8000).",
            "stats": None,
            "error_detail": "ConnectError: Could not reach endpoint.",
        }
    except httpx.TimeoutException:
        return {
            "success": False,
            "message": f"Timeout connecting to SIEM at {target_url}.",
            "stats": None,
            "error_detail": "TimeoutException",
        }
    except Exception as e:
        return {
            "success": False,
            "message": f"Forwarding error: {str(e)}",
            "stats": None,
            "error_detail": str(e),
        }
