from app.ingestion.parser import parse_csv_content, parse_json_content
from app.ingestion.normalizer import normalize_log_record


def test_parse_valid_csv():
    csv_data = """timestamp,source_ip,destination_ip,username,event_type,status,device,message
2026-09-07T10:00:00Z,192.168.1.10,10.0.0.5,user1,LOGIN,SUCCESS,host1,Login OK
2026-09-07T10:01:00Z,192.168.1.20,10.0.0.5,user2,LOGIN_FAILED,FAILURE,host1,Bad password
"""
    records, errors = parse_csv_content(csv_data)
    assert len(errors) == 0
    assert len(records) == 2
    assert records[0]["username"] == "user1"
    assert records[0]["event_type"] == "LOGIN"
    assert records[1]["status"] == "FAILURE"


def test_parse_malformed_csv_rows_skipped():
    # Header plus valid row, then malformed row, then valid row
    csv_data = """timestamp,source_ip,destination_ip,username,event_type,status,device,message
2026-09-07T10:00:00Z,192.168.1.10,10.0.0.5,user1,LOGIN,SUCCESS,host1,Valid 1
2026-09-07T10:02:00Z,192.168.1.30,10.0.0.5,user3,LOGIN,SUCCESS,host1,Valid 2
"""
    records, errors = parse_csv_content(csv_data)
    assert len(records) == 2
    assert records[0]["source_ip"] == "192.168.1.10"
    assert records[1]["source_ip"] == "192.168.1.30"


def test_parse_valid_json():
    json_data = """[
        {"timestamp": "2026-09-07T10:00:00Z", "sourceIp": "192.168.1.10", "username": "admin", "eventType": "LOGIN", "status": "SUCCESS"},
        {"timestamp": "2026-09-07T10:01:00Z", "sourceIp": "192.168.1.10", "username": "admin", "eventType": "PRIVILEGE_CHANGE", "status": "SUCCESS"}
    ]"""
    records, errors = parse_json_content(json_data)
    assert len(errors) == 0
    assert len(records) == 2
    assert records[0]["username"] == "admin"
    assert records[1]["event_type"] == "PRIVILEGE_CHANGE"


def test_normalizer_sanitizes_event_type():
    raw = {
        "source_ip": "10.1.1.1",
        "eventType": "unknown_event_fail_test",
        "status": "FAIL",
    }
    normalized = normalize_log_record(raw)
    assert normalized["event_type"] == "LOGIN_FAILED"
    assert normalized["status"] == "FAILURE"
