from typing import List


class DemoDataService:
    """
    SIH PS 26156 Demo Data Generator.
    Provides a deterministic, realistic mixed-format log dataset for judging demonstrations.
    Includes Syslog, JSON, CEF, LEEF, and CSV logs across authentication, firewall, network, and file access events.
    """
    DEMO_LOGS: List[str] = [
        # 1. Syslog - Linux SSH Authentication Failure
        "<85>1 2026-09-30T10:42:31Z ip-10-0-0-12 sshd 88421 - - Failed password for invalid user admin from 192.168.1.24 port 44821 ssh2",
        
        # 2. Syslog - Linux File Access Success
        "<86>1 2026-09-30T10:41:18Z workstation-04 auditd 88420 - - type=SYSCALL arch=c000003e syscall=2 success=yes exit=3 a0=7ff user=analyst item=/var/log/auth.log scontext=system_u:system_r",
        
        # 3. JSON - Authentication Failure / Privilege Escalation
        '{"event_id": "EVT-88419", "timestamp": "2026-09-30 10:39:02", "src_ip": "172.16.2.91", "dst_ip": "10.0.0.12", "username": "root", "event_type": "Authentication", "message": "Root authentication rejected after 8 attempts", "status": "Failed", "severity": "Critical", "source": "Authentication", "vendor": "IdentityServer", "attempt_count": 8}',
        
        # 4. CEF - Firewall Connection
        "CEF:0|Palo Alto Networks|PAN-OS|10.1.0|TRAFFIC|end|1|src=192.168.0.17 dst=10.0.0.42 spt=54120 dpt=443 proto=TCP suser=svc_backup act=allow outcome=Success msg=Outbound connection to backup server established cat=Firewall",
        
        # 5. CEF - Firewall Port Scan Blocked
        "CEF:0|Fortinet|FortiGate|7.0.2|PERIMETER|PortScan|4|src=203.0.113.45 dst=10.0.0.12 spt=33100 dpt=80 proto=TCP suser=unknown act=block outcome=Blocked msg=Sequential connection attempts across restricted ports cat=Security",
        
        # 6. JSON - Windows Event Interactive Login Success
        '{"event_id": "EVT-88416", "timestamp": "2026-09-30 10:32:08", "src_ip": "10.20.4.15", "dst_ip": "10.0.0.28", "username": "analyst", "event_type": "Login", "message": "Interactive session authenticated via SSO", "status": "Success", "severity": "Low", "source": "Windows Event", "vendor": "Microsoft", "logon_type": 2}',
        
        # 7. LEEF - Privilege Escalation Attempt
        "LEEF:2.0|IBM|QRadar|7.4.0|PrivEsc|src=172.16.2.91\tdst=10.0.0.12\tusrName=root\tsev=Critical\taction=Blocked\tcat=Linux System\tmsg=Unauthorized privilege escalation attempt detected",
        
        # 8. CSV - Application Logout
        "2026-09-30 10:24:17, 192.168.1.24, 10.0.0.32, admin, Logout, Success, Informational, Application, Administrative session terminated normally",
        
        # 9. JSON - Web Application Rate Limiting Block
        '{"event_id": "EVT-88413", "timestamp": "2026-09-30 10:20:33", "src_ip": "198.51.100.18", "dst_ip": "10.0.0.44", "username": "guest", "event_type": "HTTP Request", "message": "Repeated requests to protected API endpoint", "status": "Blocked", "severity": "Medium", "source": "Web Server", "vendor": "Nginx WAF", "http_status": 429}',
        
        # 10. CSV - Scheduled Backup Access
        "2026-09-30 10:16:09, 192.168.0.17, 10.0.0.42, svc_backup, File Access, Success, Low, Application, Scheduled backup archive read completed",
        
        # 11. Duplicate Log Entry (For testing deduplication stage)
        "CEF:0|Palo Alto Networks|PAN-OS|10.1.0|TRAFFIC|end|1|src=192.168.0.17 dst=10.0.0.42 spt=54120 dpt=443 proto=TCP suser=svc_backup act=allow outcome=Success msg=Outbound connection to backup server established cat=Firewall",
        
        # 12. Malformed / Cleaning test log (Invalid IP & Missing Port repair test)
        "<84>1 2026-09-30T10:10:00Z webhost nginx 88411 - - src_ip=999.999.999.999 dst_ip=10.0.0.12 username=test_user status=failed msg=Request with malformed IP header"
    ]

    @classmethod
    def get_demo_logs(cls) -> List[str]:
        return cls.DEMO_LOGS
