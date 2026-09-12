import csv
import io
import json
from typing import List, Dict, Any, Tuple
from app.ingestion.normalizer import normalize_log_record

MAX_UPLOAD_BYTES = 10 * 1024 * 1024  # 10MB limit


def parse_csv_content(content_str: str) -> Tuple[List[Dict[str, Any]], List[str]]:
    normalized_records: List[Dict[str, Any]] = []
    errors: List[str] = []

    try:
        reader = csv.DictReader(io.StringIO(content_str))
        if not reader.fieldnames:
            return [], ["Empty CSV file or missing headers"]

        for row_num, row in enumerate(reader, start=2):
            try:
                # Check for completely empty rows
                if not any(row.values()):
                    continue
                record = normalize_log_record(row, index=row_num)
                normalized_records.append(record)
            except Exception as e:
                errors.append(f"Row {row_num}: Failed to parse row ({str(e)})")
    except Exception as e:
        errors.append(f"Fatal CSV parsing error: {str(e)}")

    return normalized_records, errors


def parse_json_content(content_str: str) -> Tuple[List[Dict[str, Any]], List[str]]:
    normalized_records: List[Dict[str, Any]] = []
    errors: List[str] = []

    try:
        data = json.loads(content_str)
        if isinstance(data, dict):
            # Check if it has an "items" or "logs" key
            items = data.get("logs") or data.get("items") or [data]
        elif isinstance(data, list):
            items = data
        else:
            return [], ["JSON must be an array of log objects or a single log object"]

        for idx, item in enumerate(items, start=1):
            if not isinstance(item, dict):
                errors.append(f"Item {idx}: Expected JSON object, got {type(item).__name__}")
                continue
            try:
                record = normalize_log_record(item, index=idx)
                normalized_records.append(record)
            except Exception as e:
                errors.append(f"Item {idx}: Failed to normalize log ({str(e)})")
    except json.JSONDecodeError as e:
        errors.append(f"Invalid JSON format: {str(e)}")
    except Exception as e:
        errors.append(f"Fatal JSON parsing error: {str(e)}")

    return normalized_records, errors


def parse_upload_file(filename: str, content_bytes: bytes) -> Tuple[List[Dict[str, Any]], List[str]]:
    if len(content_bytes) > MAX_UPLOAD_BYTES:
        return [], [f"File exceeds maximum upload limit of {MAX_UPLOAD_BYTES // (1024*1024)}MB"]

    content_str = content_bytes.decode("utf-8", errors="replace")
    lower_name = filename.lower()

    if lower_name.endswith(".json"):
        return parse_json_content(content_str)
    else:
        # Default to CSV parser
        return parse_csv_content(content_str)
