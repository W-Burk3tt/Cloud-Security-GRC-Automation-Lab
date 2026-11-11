"""
Simple SOC-style triage summary: runs both detection rules and produces
a unified incident report, the kind of first-pass output an analyst
would use to decide what needs immediate escalation.
"""
import subprocess
import json
import sys

def run_detection(script, log_file):
    """Run a detection script and capture its structured findings by re-importing its logic directly."""
    result = subprocess.run(
        ["python3", script, log_file],
        capture_output=True, text=True
    )
    return result.stdout

def main():
    print("=" * 60)
    print("INCIDENT TRIAGE SUMMARY")
    print("=" * 60)

    print("\n--- IAM Privilege Escalation Detection ---")
    print(run_detection("detect_iam_escalation.py", "mock_cloudtrail_logs.json"))

    print("--- SQL Injection Detection ---")
    print(run_detection("detect_sqli.py", "mock_access_logs.json"))

    print("=" * 60)
    print("TRIAGE NOTES")
    print("=" * 60)
    print("""
Both alerts in this run represent CONFIRMED incidents from controlled testing
(IAM Lab 3 and Juice Shop SQLi testing), not false positives. In a real SOC
workflow, next steps for each would be:

IAM_SELF_PRIVILEGE_ESCALATION (CRITICAL):
  1. Immediately disable the affected IAM user's access keys
  2. Review CloudTrail for any actions taken using the escalated privileges
  3. Rotate credentials for any resources the user could have accessed post-escalation
  4. Confirm the underlying policy misconfiguration is remediated (see Lab 3)

SQLI_PATTERN_MATCH (HIGH):
  1. Review application logs for the source IP's full session activity
  2. Confirm whether authentication was actually bypassed (check for admin session tokens issued)
  3. Patch the underlying injection vulnerability (parameterized queries / input validation)
  4. Consider blocking the source IP at the WAF/firewall level pending investigation
""")

if __name__ == "__main__":
    main()
