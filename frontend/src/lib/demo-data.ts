export type Severity = "Critical" | "High" | "Medium" | "Low" | "Informational";
export type LogEvent = {
  id: string; timestamp: string; ip: string; destination: string; username: string;
  event: string; message: string; status: "Failed" | "Success" | "Blocked"; severity: Severity; source: string;
};

export const logs: LogEvent[] = [
  { id: "EVT-88421", timestamp: "2026-09-30 10:42:31", ip: "192.168.1.24", destination: "10.0.0.12", username: "admin", event: "Failed Login", message: "Multiple failed SSH login attempts from internal host", status: "Failed", severity: "High", source: "Linux System" },
  { id: "EVT-88420", timestamp: "2026-09-30 10:41:18", ip: "10.20.4.15", destination: "10.0.0.28", username: "analyst", event: "File Access", message: "Accessed /var/log/auth.log with read permissions", status: "Success", severity: "Low", source: "Linux System" },
  { id: "EVT-88419", timestamp: "2026-09-30 10:39:02", ip: "172.16.2.91", destination: "10.0.0.12", username: "root", event: "Authentication", message: "Root authentication rejected after 8 attempts", status: "Failed", severity: "Critical", source: "Authentication" },
  { id: "EVT-88418", timestamp: "2026-09-30 10:37:46", ip: "192.168.0.17", destination: "10.0.0.42", username: "svc_backup", event: "Network Connection", message: "Outbound connection to backup server established", status: "Success", severity: "Informational", source: "Firewall" },
  { id: "EVT-88417", timestamp: "2026-09-30 10:35:12", ip: "203.0.113.45", destination: "10.0.0.12", username: "unknown", event: "Port Scan", message: "Sequential connection attempts across restricted ports", status: "Blocked", severity: "High", source: "Firewall" },
  { id: "EVT-88416", timestamp: "2026-09-30 10:32:08", ip: "10.20.4.15", destination: "10.0.0.28", username: "analyst", event: "Login", message: "Interactive session authenticated via SSO", status: "Success", severity: "Low", source: "Windows Event" },
  { id: "EVT-88415", timestamp: "2026-09-30 10:28:54", ip: "172.16.2.91", destination: "10.0.0.12", username: "root", event: "Permission Change", message: "Unauthorized privilege escalation attempt detected", status: "Blocked", severity: "Critical", source: "Linux System" },
  { id: "EVT-88414", timestamp: "2026-09-30 10:24:17", ip: "192.168.1.24", destination: "10.0.0.32", username: "admin", event: "Logout", message: "Administrative session terminated normally", status: "Success", severity: "Informational", source: "Application" },
  { id: "EVT-88413", timestamp: "2026-09-30 10:20:33", ip: "198.51.100.18", destination: "10.0.0.44", username: "guest", event: "HTTP Request", message: "Repeated requests to protected API endpoint", status: "Blocked", severity: "Medium", source: "Web Server" },
  { id: "EVT-88412", timestamp: "2026-09-30 10:16:09", ip: "192.168.0.17", destination: "10.0.0.42", username: "svc_backup", event: "File Access", message: "Scheduled backup archive read completed", status: "Success", severity: "Low", source: "Application" },
];

export const hourlyEvents = [
  { hour: "00:00", events: 310, threats: 48 }, { hour: "02:00", events: 255, threats: 36 },
  { hour: "04:00", events: 280, threats: 42 }, { hour: "06:00", events: 390, threats: 67 },
  { hour: "08:00", events: 580, threats: 93 }, { hour: "10:00", events: 490, threats: 75 },
  { hour: "12:00", events: 720, threats: 121 }, { hour: "14:00", events: 610, threats: 88 },
  { hour: "16:00", events: 840, threats: 143 }, { hour: "18:00", events: 700, threats: 105 },
  { hour: "20:00", events: 790, threats: 126 }, { hour: "22:00", events: 655, threats: 94 },
];
export const severityData = [
  { name: "Critical", value: 142, color: "var(--severity-critical)" },
  { name: "High", value: 621, color: "var(--severity-high)" },
  { name: "Medium", value: 1850, color: "var(--severity-medium)" },
  { name: "Low", value: 4281, color: "var(--severity-low)" },
  { name: "Informational", value: 5500, color: "var(--severity-info)" },
];
export const metrics = [
  { label: "TOTAL LOGS", value: "12,584", change: "+12.8%", icon: "database" },
  { label: "PROCESSED", value: "12,394", change: "98.5% rate", icon: "check" },
  { label: "DUPLICATES REMOVED", value: "190", change: "1.5% of total", icon: "layers" },
  { label: "INVALID RECORDS", value: "17", change: "0.1% of total", icon: "alert" },
  { label: "UNIQUE IPs", value: "427", change: "+34 today", icon: "globe" },
  { label: "FAILED EVENTS", value: "763", change: "6.2% of events", icon: "shield" },
];
