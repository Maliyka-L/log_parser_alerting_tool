#imports python modules
import datetime #timestamps
import os #file paths
import requests #sending discord webhook alerts
import json #reading config
import csv #exporting alerts
import argparse #command-line arguments

#builds paths from this file's location so the tool works no matter which folder it is run from
SRC_DIR = os.path.dirname(os.path.abspath(__file__))
BASE_DIR = os.path.dirname(SRC_DIR)

#loads secrets such as the Discord webhook from a .env file in the project folder (never uploaded to GitHub)
try:
    from dotenv import load_dotenv
    load_dotenv(os.path.join(BASE_DIR, ".env"))
except ImportError:
    pass

with open(os.path.join(SRC_DIR, "config.json"), "r") as cfg:
    CONFIG = json.load(cfg)

#the webhook URL acts like a password, so it is read from the DISCORD_WEBHOOK_URL environment variable
#instead of being stored in config.json
WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL", "")

#rules as config files and stores them as variables for easy access. Adds easy flexibility
LOG_FILE_PATH = CONFIG["log_file_path"]
FAILED_STATUS_CODES = set(CONFIG["failed_status_codes"])
MAX_FAILED_ATTEMPTS = CONFIG["max_failed_attempts"]
TIME_WINDOW_SECONDS = CONFIG["bruteforce_time_window"]
ALLOW_LIST = set(CONFIG["allow_list"])
SUSPICIOUS_USER_AGENTS = CONFIG["suspicious_user_agents"]
HIGH_VOLUME_THRESHOLD = CONFIG["high_volume_threshold"]
HIGH_VOLUME_WINDOW = CONFIG["high_volume_window"]
ENDPOINT_SCAN_THRESHOLD = CONFIG["endpoint_scan_threshold"]
ENDPOINT_SCAN_WINDOW = CONFIG["endpoint_scan_window"]
SEVERITY_OVERRIDES = CONFIG["severity"]
SEVERITY_COLOURS_CFG = CONFIG["severity_colours"]
RULES_ENABLED = CONFIG["rules"]

#Discord rejects messages that are too long, so only this many alerts are included per message
MAX_DISCORD_ALERTS = 10

#Adds visual indicators for severity levels in the console output
SEVERITY_ICONS = {
    "high": "🔴",
    "medium": "🟠",
    "low": "🟢"
}

#Splits each log line into components, validates the format
#converts the timestamp string to a python datetime object, returns a dictionary with the parsed data, or None if the line is invalid.
def parse_log_line(line):
    parts = line.strip().split()
    if len(parts) < 7:
        return None

    timestamp_str = f"{parts[0]} {parts[1]}"
    ip = parts[2]
    method = parts[3]
    path = parts[4]
    status = parts[5]
    user_agent = " ".join(parts[6:])

    try:
        timestamp = datetime.datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None

    return {
        "timestamp": timestamp,
        "ip": ip,
        "method": method,
        "path": path,
        "status": status,
        "user_agent": user_agent
    }

#finds a log file whether the path is relative to the current folder or to the project folder
def resolve_path(path):
    if os.path.isabs(path) or os.path.exists(path):
        return path
    return os.path.join(BASE_DIR, path)

#reads the log file line by line, uses parse_log_line to parse each line, and collects valid events into a list. Returns the list of events.
def load_logs(path):
    events = []
    with open(resolve_path(path), "r", encoding="utf-8") as f:
        for line in f:
            parsed = parse_log_line(line)
            if parsed:
                events.append(parsed)
    return events

#Detects brute force attacks by checking for multiple failed login attempts from the same IP within a specified time window. If the number of failed attempts exceeds the configured threshold, it flags the IP as suspicious and adds it to the list of alerts.
def detect_bruteforce(events):
    if not RULES_ENABLED["bruteforce"]:
        return []

    suspicious = []
    events = sorted(events, key=lambda e: e["timestamp"])
    last_flagged_until = {}

    for i, event in enumerate(events):
        if event["ip"] in ALLOW_LIST:
            continue

        if event["status"] not in FAILED_STATUS_CODES:
            continue

        window_start = event["timestamp"]
        ip = event["ip"]

        if ip in last_flagged_until and window_start <= last_flagged_until[ip]:
            continue

        failed_count = 1
        last_failed_time = window_start

        for j in range(i + 1, len(events)):
            next_event = events[j]
            if next_event["ip"] != ip:
                continue

            delta = (next_event["timestamp"] - window_start).total_seconds()
            if delta > TIME_WINDOW_SECONDS:
                break

            if next_event["status"] in FAILED_STATUS_CODES:
                failed_count += 1
                last_failed_time = next_event["timestamp"]

        if failed_count >= MAX_FAILED_ATTEMPTS:
            suspicious.append({
                "ip": ip,
                "time": window_start,
                "reason": f"{failed_count} failed login attempts in {TIME_WINDOW_SECONDS}s",
                "type": "bruteforce",
                "severity": SEVERITY_OVERRIDES["bruteforce"]
            })

    return suspicious

#detects after-hours activity between 00:00 and 06:00, flags any activity from IPs not in the allow list during this time as suspicious.
def detect_after_hours(events):
    if not RULES_ENABLED["after_hours"]:
        return []

    suspicious = []

    for event in events:
        if event["ip"] in ALLOW_LIST:
            continue

        hour = event["timestamp"].hour
        if hour < 6:
            suspicious.append({
                "ip": event["ip"],
                "time": event["timestamp"],
                "reason": "Activity outside normal hours",
                "type": "after_hours",
                "severity": SEVERITY_OVERRIDES["after_hours"]
            })

    return suspicious

#detects access to /admin endpoints, flags any access attempts to /admin paths from IPs not in the allow list as suspicious.
def detect_admin_access(events):
    if not RULES_ENABLED["admin_access"]:
        return []

    suspicious = []

    for event in events:
        if event["ip"] in ALLOW_LIST:
            continue

        if event["path"].startswith("/admin"):
            suspicious.append({
                "ip": event["ip"],
                "time": event["timestamp"],
                "reason": "Accessed /admin page",
                "type": "admin_access",
                "severity": SEVERITY_OVERRIDES["admin_access"]
            })

    return suspicious

#detects high volume requests from the same IP within a specified time window. If the number of requests exceeds the configured threshold, it flags the IP as suspicious and adds it to the list of alerts.
def detect_high_volume(events):
    if not RULES_ENABLED["high_volume"]:
        return []

    suspicious = []
    events = sorted(events, key=lambda e: e["timestamp"])

    for i, event in enumerate(events):
        if event["ip"] in ALLOW_LIST:
            continue

        ip = event["ip"]
        start_time = event["timestamp"]
        count = 1

        for j in range(i + 1, len(events)):
            next_event = events[j]
            if next_event["ip"] != ip:
                continue

            delta = (next_event["timestamp"] - start_time).total_seconds()
            if delta > HIGH_VOLUME_WINDOW:
                break

            count += 1

        if count >= HIGH_VOLUME_THRESHOLD:
            suspicious.append({
                "ip": ip,
                "time": start_time,
                "reason": f"{count} requests in {HIGH_VOLUME_WINDOW}s",
                "type": "high_volume",
                "severity": SEVERITY_OVERRIDES["high_volume"]
            })

    return suspicious

#detects endpoint scanning by checking for multiple unique paths accessed from the same IP within a specified time window. If the number of unique paths exceeds the configured threshold, it flags the IP as suspicious and adds it to the list of alerts.
def detect_endpoint_scanning(events):
    if not RULES_ENABLED["endpoint_scan"]:
        return []

    suspicious = []
    events = sorted(events, key=lambda e: e["timestamp"])

    for i, event in enumerate(events):
        if event["ip"] in ALLOW_LIST:
            continue

        ip = event["ip"]
        start_time = event["timestamp"]
        paths_seen = {event["path"]}

        for j in range(i + 1, len(events)):
            next_event = events[j]
            if next_event["ip"] != ip:
                continue

            delta = (next_event["timestamp"] - start_time).total_seconds()
            if delta > ENDPOINT_SCAN_WINDOW:
                break

            paths_seen.add(next_event["path"])

        if len(paths_seen) >= ENDPOINT_SCAN_THRESHOLD:
            suspicious.append({
                "ip": ip,
                "time": start_time,
                "reason": f"{len(paths_seen)} unique endpoints scanned",
                "type": "endpoint_scan",
                "severity": SEVERITY_OVERRIDES["endpoint_scan"]
            })

    return suspicious

#detects suspicious user agents by checking if the user agent string of each event contains any known suspicious patterns. If a match is found, it flags the IP as suspicious and adds it to the list of alerts.
def detect_suspicious_user_agents(events):
    if not RULES_ENABLED["suspicious_user_agent"]:
        return []

    suspicious = []

    for event in events:
        if event["ip"] in ALLOW_LIST:
            continue

        ua = event["user_agent"].lower()

        for bad in SUSPICIOUS_USER_AGENTS:
            if bad in ua:
                suspicious.append({
                    "ip": event["ip"],
                    "time": event["timestamp"],
                    "reason": f"Suspicious user-agent: '{event['user_agent']}'",
                    "type": "suspicious_user_agent",
                    "severity": SEVERITY_OVERRIDES["suspicious_user_agent"]
                })
                break

    return suspicious

#keeps only the strongest alert for each IP and type combination, based on the severity of the reason. This prevents multiple alerts for the same issue from cluttering the output.
def dedupe_alerts(alerts):
    strongest = {}

    for alert in alerts:
        key = (alert["ip"], alert["type"])

        if key not in strongest:
            strongest[key] = alert
            continue

        existing = strongest[key]

        if alert["type"] in ("bruteforce", "high_volume", "endpoint_scan"):
            if int(alert["reason"].split()[0]) > int(existing["reason"].split()[0]):
                strongest[key] = alert

        else:
            continue

    return list(strongest.values())

#exports alerts to a JSON file for offline analysis, SIEM ingestion, or audit logging.
def export_json(alerts):
    alerts_dir = os.path.join(BASE_DIR, "alerts")
    os.makedirs(alerts_dir, exist_ok=True)
    filename = os.path.join(alerts_dir, f"{datetime.datetime.now(datetime.UTC).strftime('%Y-%m-%dT%H-%M-%S')}.json")

    serializable = []
    for alert in alerts:
        serializable.append({
            "ip": alert["ip"],
            "time": alert["time"].strftime("%Y-%m-%d %H:%M:%S"),
            "reason": alert["reason"],
            "type": alert["type"],
            "severity": alert["severity"],
            "geoip": alert.get("geoip", {})
        })

    with open(filename, "w", encoding="utf-8") as f:
        json.dump(serializable, f, indent=4)

    print(f"Saved alerts to {filename}")

#exports alerts to a CSV file for analysts, spreadsheets, or SIEM ingestion tools that prefer tabular formats.
def export_csv(alerts):
    alerts_dir = os.path.join(BASE_DIR, "alerts")
    os.makedirs(alerts_dir, exist_ok=True)
    filename = os.path.join(alerts_dir, f"{datetime.datetime.now(datetime.UTC).strftime('%Y-%m-%dT%H-%M-%S')}.csv")

    #csv.writer handles commas inside values (e.g. ISP names) so columns never get mixed up
    with open(filename, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["ip", "time", "reason", "type", "severity", "country", "region", "city", "isp", "org", "asn"])
        for alert in alerts:
            geo = alert.get("geoip", {})
            writer.writerow([
                alert["ip"],
                alert["time"].strftime("%Y-%m-%d %H:%M:%S"),
                alert["reason"],
                alert["type"],
                alert["severity"],
                geo.get("country", "Unknown"),
                geo.get("region", "Unknown"),
                geo.get("city", "Unknown"),
                geo.get("isp", "Unknown"),
                geo.get("org", "Unknown"),
                geo.get("asn", "Unknown")
            ])

    print(f"Saved alerts to {filename}")

#enriches alerts with GeoIP information such as country, region, city, ISP, and ASN using the ip-api.com service.
def enrich_geoip(alerts):
    for alert in alerts:
        ip = alert["ip"]

        try:
            response = requests.get(
                f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,isp,org,as",
                timeout=10
            )
            data = response.json()

            if data.get("status") == "success":
                alert["geoip"] = {
                    "country": data.get("country", "Unknown"),
                    "region": data.get("regionName", "Unknown"),
                    "city": data.get("city", "Unknown"),
                    "isp": data.get("isp", "Unknown"),
                    "org": data.get("org", "Unknown"),
                    "asn": data.get("as", "Unknown")
                }
            else:
                alert["geoip"] = {
                    "country": "Unknown",
                    "region": "Unknown",
                    "city": "Unknown",
                    "isp": "Unknown",
                    "org": "Unknown",
                    "asn": "Unknown"
                }

        except Exception:
            alert["geoip"] = {
                "country": "Unknown",
                "region": "Unknown",
                "city": "Unknown",
                "isp": "Unknown",
                "org": "Unknown",
                "asn": "Unknown"
            }

    return alerts

#builds a discord embed and sends it using the webhook URL. It includes the highest severity alert in the embed color and lists all alerts with their details.
def send_alert(alerts):
    if not WEBHOOK_URL:
        print("Discord webhook not set (add DISCORD_WEBHOOK_URL to your .env file). Skipping alert.")
        return

    severity_icons = {
        "high": "🔴",
        "medium": "🟠",
        "low": "🟢"
    }

    highest = max(alerts, key=lambda a: {"high": 3, "medium": 2, "low": 1}[a["severity"]])
    colour = SEVERITY_COLOURS_CFG[highest["severity"]]

    embed = {
        "title": "Suspicious Activity Detected",
        "description": "Security monitoring detected suspicious activity requiring investigation.",
        "color": colour,
        "fields": [],
        "timestamp": datetime.datetime.now(datetime.UTC).isoformat()
    }

    #adds one field per alert so every alert appears in the Discord message
    #(Discord limits the size of a message, so a maximum of 10 alerts are shown)
    for alert in alerts[:MAX_DISCORD_ALERTS]:
        icon = severity_icons.get(alert.get("severity"), "⚪")

        geo = alert.get("geoip", {}) or {}

        country = geo.get("country", "Unknown")
        region = geo.get("region", "Unknown")
        city = geo.get("city", "Unknown")
        isp = geo.get("isp", "Unknown")
        asn = geo.get("asn", "Unknown")

        embed["fields"].append({
            "name": f"{icon} {alert['type'].replace('_', ' ').title()}",
            "value":
                f"**IP:** `{alert['ip']}`\n"
                f"**Country:** {country}\n"
                f"**Region:** {region}\n"
                f"**City:** {city}\n"
                f"**ISP:** {isp}\n"
                f"**ASN:** {asn}\n"
                f"**Reason:** {alert['reason']}\n"
                f"**Time:** `{alert['time'].strftime('%Y-%m-%d %H:%M:%S')}`",
            "inline": False
        })

    if len(alerts) > MAX_DISCORD_ALERTS:
        embed["footer"] = {"text": f"Showing {MAX_DISCORD_ALERTS} of {len(alerts)} alerts. See the JSON/CSV export for the full list."}

    payload = {"embeds": [embed]}

    try:
        response = requests.post(WEBHOOK_URL, json=payload, timeout=10)
        response.raise_for_status()
        print("Embed alert sent to Discord.")
    except Exception as e:
        print(f"Failed to send embed alert: {e}")

#parses command-line arguments to allow overriding log paths, disabling exports, or enabling specific rules.
def parse_cli_args():
    parser = argparse.ArgumentParser(description="Log Parser Alerting Tool")

    parser.add_argument("--log", help="Override log file path")
    parser.add_argument("--no-discord", action="store_true", help="Disable Discord alerts")
    parser.add_argument("--no-json", action="store_true", help="Disable JSON export")
    parser.add_argument("--no-csv", action="store_true", help="Disable CSV export")
    parser.add_argument("--rules", help="Comma-separated list of rules to enable")

    return parser.parse_args()

#loads logs, runs all detection functions, deduplicates alerts, enriches them with GeoIP, prints them to the console, exports them to JSON and CSV, and sends them to Discord if any are found.
def main():
    args = parse_cli_args()

    global LOG_FILE_PATH
    if args.log:
        LOG_FILE_PATH = args.log

    if args.rules:
        enabled = [rule.strip() for rule in args.rules.split(",")]
        for rule in RULES_ENABLED:
            RULES_ENABLED[rule] = rule in enabled

    events = load_logs(LOG_FILE_PATH)

    alerts = []
    alerts += detect_bruteforce(events)
    alerts += detect_admin_access(events)
    alerts += detect_after_hours(events)
    alerts += detect_high_volume(events)
    alerts += detect_endpoint_scanning(events)
    alerts += detect_suspicious_user_agents(events)

    alerts = dedupe_alerts(alerts)
    alerts = enrich_geoip(alerts)

    if alerts:
        print("[!] Suspicious activity detected:")
        for alert in alerts:
            icon = SEVERITY_ICONS.get(alert["severity"], "⚪")
            print(f"{icon} IP {alert['ip']} at {alert['time']}: {alert['reason']}")

        if not args.no_json:
            export_json(alerts)

        if not args.no_csv:
            export_csv(alerts)

        if not args.no_discord:
            send_alert(alerts)

    else:
        print("No suspicious activity detected.")

#runs the program by calling the main function when the script is executed directly.
if __name__ == "__main__":
    main()
