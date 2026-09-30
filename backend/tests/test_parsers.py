import pytest
from app.parsers.cef_parser import CEFParser
from app.parsers.csv_parser import CSVParser
from app.parsers.json_parser import JSONParser
from app.parsers.leef_parser import LEEFParser
from app.parsers.registry import ParserRegistry
from app.parsers.syslog_parser import SyslogParser
from app.parsers.xml_parser import XMLParser


def test_syslog_parser():
    parser = SyslogParser()
    raw = "<85>1 2026-09-30T10:42:31Z host sshd 88421 - - Failed password for user admin from 192.168.1.24"
    assert parser.can_parse(raw) > 0.8
    parsed = parser.parse(raw)
    assert parsed["syslog_pri"] == 85
    assert parsed["app_name"] == "sshd"


def test_json_parser():
    parser = JSONParser()
    raw = '{"event_id": "123", "src_ip": "10.0.0.1", "username": "admin", "severity": "High"}'
    assert parser.can_parse(raw) > 0.9
    parsed = parser.parse(raw)
    assert parsed["src_ip"] == "10.0.0.1"
    assert parsed["username"] == "admin"


def test_cef_parser():
    parser = CEFParser()
    raw = "CEF:0|Palo Alto Networks|PAN-OS|10.1|TRAFFIC|end|1|src=192.168.0.17 dst=10.0.0.42 suser=svc_backup act=allow"
    assert parser.can_parse(raw) > 0.9
    parsed = parser.parse(raw)
    assert parsed["vendor"] == "Palo Alto Networks"
    assert parsed["src_ip"] == "192.168.0.17"
    assert parsed["username"] == "svc_backup"


def test_leef_parser():
    parser = LEEFParser()
    raw = "LEEF:2.0|IBM|QRadar|7.4|PrivEsc|src=172.16.2.91\tdst=10.0.0.12\tusrName=root\tsev=Critical"
    assert parser.can_parse(raw) > 0.9
    parsed = parser.parse(raw)
    assert parsed["vendor"] == "IBM"
    assert parsed["src_ip"] == "172.16.2.91"
    assert parsed["username"] == "root"


def test_csv_parser():
    parser = CSVParser()
    raw = "2026-09-30 10:24:17, 192.168.1.24, 10.0.0.32, admin, Logout, Success, Low, Application, Session closed"
    assert parser.can_parse(raw) >= 0.8
    parsed = parser.parse(raw)
    assert parsed["src_ip"] == "192.168.1.24"
    assert parsed["username"] == "admin"


def test_xml_parser():
    parser = XMLParser()
    raw = "<Event><EventID>4624</EventID><TargetUserName>analyst</TargetUserName></Event>"
    assert parser.can_parse(raw) > 0.9
    parsed = parser.parse(raw)
    assert parsed["EventID"] == "4624"
    assert parsed["TargetUserName"] == "analyst"


def test_parser_registry_detection():
    registry = ParserRegistry()
    raw_cef = "CEF:0|Vendor|Product|1.0|100|LogName|5|src=1.1.1.1"
    parser, conf, fmt = registry.detect_format(raw_cef)
    assert parser.name == "cef"
    assert fmt == "CEF"
    assert conf > 0.9
