"""
Detection rule: flags likely SQL injection attempts in HTTP request logs.
Uses pattern matching for common SQLi syntax, not a full parser -
this mirrors how many real-world WAF/IDS signature rules work
(fast, pattern-based, with known tradeoffs around false positives/negatives).
"""
import json
import re
import sys

# Common SQLi indicators - intentionally a short, explainable list
# rather than an exhaustive one, so each pattern's purpose is clear
SQLI_PATTERNS = [
    (r"'\s*--", "Comment injection (closes string, comments out rest of query)"),
    (r"'\s*OR\s*'?1'?\s*=\s*'?1", "Classic tautology-based auth bypass"),
    (r"UNION\s+SELECT", "UNION-based injection (data extraction)"),
    (r";\s*DROP\s+TABLE", "Statement chaining / destructive injection"),
]

def load_logs(path):
    with open(path) as f:
        return json.load(f)

def check_sqli(text):
    """Returns the matched pattern description if SQLi-like syntax is found, else None."""
    for pattern, description in SQLI_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            return description
    return None

def detect(events):
    alerts = []
    for event in events:
        match = check_sqli(event.get("body", ""))
        if match:
            alerts.append({
                "severity": "HIGH",
                "rule": "SQLI_PATTERN_MATCH",
                "timestamp": event["timestamp"],
                "source_ip": event["source_ip"],
                "path": event["path"],
                "detail": match,
                "raw_event": event
            })
    return alerts

if __name__ == "__main__":
    log_path = sys.argv[1] if len(sys.argv) > 1 else "mock_access_logs.json"
    events = load_logs(log_path)

    print(f"Analyzing {len(events)} HTTP requests...\n")
    alerts = detect(events)

    if not alerts:
        print("No alerts triggered.")
    else:
        print(f"⚠️  {len(alerts)} ALERT(S) TRIGGERED\n")
        for alert in alerts:
            print(f"[{alert['severity']}] {alert['rule']}")
            print(f"  Time: {alert['timestamp']}")
            print(f"  Source IP: {alert['source_ip']}")
            print(f"  Path: {alert['path']}")
            print(f"  Detail: {alert['detail']}")
            print()

    print(f"Summary: {len(events)} requests analyzed, {len(alerts)} alert(s), {len(events) - len(alerts)} benign")
