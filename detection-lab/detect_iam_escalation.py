"""
Detection rule: flags IAM privilege escalation attempts in CloudTrail-style logs.
Specifically looks for a principal attaching a policy to THEMSELVES (self-escalation),
especially when the policy grants broad/admin access.
"""
import json
import sys

ADMIN_POLICY_INDICATORS = ["AdministratorAccess", "FullAccess", "*"]

def load_logs(path):
    with open(path) as f:
        return json.load(f)

def is_self_attachment(event):
    """True if the user attached a policy to their own account."""
    if event["eventName"] != "AttachUserPolicy":
        return False
    actor = event["userIdentity"]["userName"]
    target = event["requestParameters"].get("userName")
    return actor == target

def is_admin_policy(event):
    arn = event["requestParameters"].get("policyArn", "")
    return any(indicator in arn for indicator in ADMIN_POLICY_INDICATORS)

def detect(events):
    alerts = []
    for event in events:
        if is_self_attachment(event) and is_admin_policy(event):
            alerts.append({
                "severity": "CRITICAL",
                "rule": "IAM_SELF_PRIVILEGE_ESCALATION",
                "timestamp": event["eventTime"],
                "actor": event["userIdentity"]["userName"],
                "action": event["eventName"],
                "detail": f"{event['userIdentity']['userName']} attached an admin-level policy to their own account",
                "raw_event": event
            })
    return alerts

if __name__ == "__main__":
    log_path = sys.argv[1] if len(sys.argv) > 1 else "mock_cloudtrail_logs.json"
    events = load_logs(log_path)

    print(f"Analyzing {len(events)} log events...\n")
    alerts = detect(events)

    if not alerts:
        print("No alerts triggered.")
    else:
        print(f"⚠️  {len(alerts)} ALERT(S) TRIGGERED\n")
        for alert in alerts:
            print(f"[{alert['severity']}] {alert['rule']}")
            print(f"  Time: {alert['timestamp']}")
            print(f"  Actor: {alert['actor']}")
            print(f"  Action: {alert['action']}")
            print(f"  Detail: {alert['detail']}")
            print()

    print(f"Summary: {len(events)} events analyzed, {len(alerts)} alert(s), {len(events) - len(alerts)} benign")
