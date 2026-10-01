import re
from collections import defaultdict

from database import add_alert


FAILED_LOGIN_PATTERN = re.compile(
    r"Failed password for (?:invalid user )?(\w+) from ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)"
)


def analyze_log(filename, threshold=5):
    failures = defaultdict(list)

    with open(filename, "r", encoding="utf-8", errors="ignore") as log_file:
        for line in log_file:
            match = FAILED_LOGIN_PATTERN.search(line)

            if not match:
                continue

            username = match.group(1)
            ip_address = match.group(2)

            failures[ip_address].append(username)

    alerts = []

    for ip_address, usernames in failures.items():
        attempts = len(usernames)

        if attempts >= threshold:
            username = usernames[-1]

            add_alert(
                ip_address,
                username,
                attempts,
                "Possible brute-force attack"
            )

            alerts.append({
                "ip": ip_address,
                "username": username,
                "attempts": attempts,
                "type": "Possible brute-force attack"
            })

    return alerts
