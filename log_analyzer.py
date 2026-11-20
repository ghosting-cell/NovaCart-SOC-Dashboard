import json
from datetime import datetime, timedelta, timezone
def parse_log_timestamp(timestamp_text):
    timestamp = datetime.fromisoformat(timestamp_text)

    ist = timezone(timedelta(hours=5, minutes=30))

    if timestamp.tzinfo is None:
        cutoff = datetime(2026, 11, 14, 1, 46, 9)

        if timestamp < cutoff:
            timestamp = timestamp.replace(
                tzinfo=timezone.utc
            ).astimezone(ist)
        else:
            timestamp = timestamp.replace(tzinfo=ist)

    else:
        timestamp = timestamp.astimezone(ist)

    return timestamp

log_file = "/var/log/novacart/security.log"

alert_file = "/root/novacart-soc/alerts.jsonl"

def save_alert(ip, severity, attempts, window_start, event_types):

    alert_id = f"{ip}|REPEATED_FAILED_LOGIN|{window_start.isoformat()}|{seve>

    alert_record = {
        "alert_id": alert_id,
        "event": "REPEATED_FAILED_LOGIN",
        "ip": ip,
        "severity": severity,
        "attempts_in_window": attempts,
        "event_types": event_types,
        "window_minutes": 5,
        "window_start": window_start.isoformat(),
        "detected_at": datetime.now().astimezone().isoformat(timespec="secon>
    }

    existing_ids = set()

    try:
        with open(alert_file, "r") as file:
            for line in file:
                try:
                    existing_record = json.loads(line)
                    existing_ids.add(existing_record.get("alert_id"))
                except json.JSONDecodeError:
                    continue

    except FileNotFoundError:
        pass
 if alert_id in existing_ids:
        return False

    try:
        with open(alert_file, "a") as file:
            json.dump(alert_record, file)
            file.write("\n")

    except PermissionError:
        print("ERROR: Permission denied while writing alert file!")
        return False

    return True

try:
    with open(log_file, "r") as file:
        logs = file.readlines()

except FileNotFoundError:
    print("ERROR: Security log file not found!")
    exit()

except PermissionError:
    print("ERROR: Permission denied while reading security log!")
    exit()

print("Total log entries:", len(logs))

# Login statistics
login_success = 0
login_failure = 0
unknown_user = 0

for log in logs:
    if "[LOGIN_SUCCESS]" in log:
        login_success += 1
    elif "[LOGIN_FAILURE]" in log:
        login_failure += 1
    elif "[UNKNOWN_USER]" in log:
        unknown_user += 1

print("\n--- LOGIN STATISTICS ---")
print("Successful logins:", login_success)
print("Failed logins:", login_failure)
print("Unknown user attempts:", unknown_user)

# IP address extraction
print("\n--- IP ADDRESS EXTRACTION ---")

for log in logs:
    if "IP=" in log:
        ip = log.split("IP=")[1].split()[0]
        print(ip)

# Failed logins grouped by IP
print("\n--- FAILED LOGINS BY IP ---")

failed_by_ip = {}

for log in logs:
    if "[LOGIN_FAILURE]" in log or "[UNKNOWN_USER]" in log:
        if "IP=" in log:
            ip = log.split("IP=")[1].split()[0]
            failed_by_ip[ip] = failed_by_ip.get(ip, 0) + 1

for ip, count in failed_by_ip.items():
    print(f"{ip}: {count} failed attempts")

# Timestamp analysis
print("\n--- TIMESTAMP ANALYSIS ---")

for log in logs:
    try:
        timestamp_text = log.split("]")[0].replace("[", "")
        timestamp = parse_log_timestamp(timestamp_text)
        print(timestamp)
    except ValueError:
        print("Invalid timestamp:", log.strip())
# Repeated failed-login detection

print("\n--- REPEATED LOGIN FAILURE DETECTION ---")

failed_events = {}

for log in logs:

    if "[LOGIN_FAILURE]" in log or "[UNKNOWN_USER]" in log:

      try:
            timestamp_text = log.split("]")[0].replace("[", "")

            timestamp = parse_log_timestamp(timestamp_text)


            ip = log.split("IP=")[1].split()[0]

            if ip == "UNKNOWN":
                continue

            event_type = (
                "LOGIN_FAILURE"
                if "[LOGIN_FAILURE]" in log
                else "UNKNOWN_USER"
            )

            failed_events.setdefault(ip, []).append(
                (timestamp, event_type)
            )

        except (ValueError, IndexError):
            continue

for ip, timestamps in failed_events.items():

    timestamps.sort(key=lambda event: event[0])
    max_attempts = 0
    best_window_start = None
   best_event_types = []

    for i in range(len(timestamps)):

        window_end = timestamps[i][0] + timedelta(minutes=5)

        attempts = [
            event for event in timestamps
            if timestamps[i][0] <= event[0] <= window_end
        ]

        if len(attempts) > max_attempts:
            max_attempts = len(attempts)
            best_window_start = timestamps[i][0]
            best_event_types = sorted(set(event[1] for event in attempts))

    if max_attempts >= 5:
        severity = "HIGH"

    elif max_attempts >= 3:
        severity = "MEDIUM"

    elif max_attempts >= 1:
        severity = "LOW"

    else:
        severity = "NONE"

    if severity != "NONE":
        print(
            f"{severity} ALERT: {ip} had "
            f"{max_attempts} failed attempts "
            f"within 5 minutes!"
        )

    if severity in ("MEDIUM", "HIGH"):
        saved = save_alert(
            ip,
            severity,
            max_attempts,
            best_window_start,
            best_event_types
        )

        if saved:
            print("Alert saved successfully!")
        else:
            print("Duplicate alert skipped.")











def save_alert(ip, severity, attempts, window_start, event_types):
