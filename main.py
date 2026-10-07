from collections import Counter
from datetime import datetime
blocked_file = "blocked_ips.txt"
actions_file = "actions.log"
log_file = "security.log"

failed_logins = []

with open(log_file, "r") as file:
    for line in file:
        parts = line.split()

        ip_address = parts[2]
        event = parts[3]

        if event == "LOGIN_FAILED":
            failed_logins.append(ip_address)

login_counts = Counter(failed_logins)

print("=== MINI SOC SECURITY MONITOR ===")
print()

for ip, count in login_counts.items():

    if count >= 5:
        print("🚨 BRUTE-FORCE ATTACK DETECTED")
        print(f"Source IP: {ip}")
        print(f"Failed attempts: {count}")
        print("Severity: HIGH")
        print("Recommended action: Investigate source IP and account activity.")
        print("-" * 50)

    elif count >= 3:
        print("⚠️ SUSPICIOUS LOGIN ACTIVITY")
        print(f"Source IP: {ip}")
        print(f"Failed attempts: {count}")
        print("Severity: MEDIUM")
        print("-" * 50)

    else:
        print("ℹ️ NORMAL LOGIN ACTIVITY")
        print(f"Source IP: {ip}")
        print(f"Failed attempts: {count}")
        print("Severity: LOW")
        print("-" * 50)
# # Generate security report
with open("security_report.txt", "w") as report:
    report.write("=== MINI SOC SECURITY REPORT ===\n\n")

    for ip, count in login_counts.items():
        if count >= 3:
            risk = "HIGH RISK"
        else:
            risk = "LOW RISK"

        report.write(f"{risk} - {ip} - {count} failed login attempt(s)\n")

print("\nSecurity report created: security_report.txt")
# Check for security alerts
print("\n=== SECURITY ALERTS ===")

for ip, count in login_counts.items():
    if count >= 3:
        print(f"[ALERT] Suspicious activity detected from {ip}")
        print(f"        Failed login attempts: {count}")
        print("        Recommended action: Block this IP.")

        with open(blocked_file, "r") as blocked:
            blocked_ips = set(line.strip() for line in blocked if line.strip())
if ip not in blocked_ips:
    with open(blocked_file, "a") as blocked:
        blocked.write(ip + "\n")

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open(actions_file, "a") as actions:
        actions.write(f"[{timestamp}] BLOCKED {ip} - {count} failed login attempts\n")

    print(f"Action: {ip} has been blocked.")
# Detect successful login after failed attempts
failed_ips = set()
success_after_failure = set()

with open(log_file, "r") as log:
    for line in log:
        parts = line.strip().split()

        if len(parts) >= 4:
            ip = parts[2]
            status = parts[3]

            if status == "LOGIN_FAILED":
                failed_ips.add(ip)

            elif status == "LOGIN_SUCCESS" and ip in failed_ips:
                success_after_failure.add(ip)

if success_after_failure:
    print("\n⚠️ SUCCESSFUL LOGIN AFTER FAILED ATTEMPTS")

    for ip in success_after_failure:
        print(f"Warning: {ip} had failed attempts before a successful login.")

    print("Recommended action: Investigate this IP.")
            # Security Dashboard
print("\n================================")
print("       MINI SOC DASHBOARD")
print("================================")

total_ips = len(login_counts)
total_failed = sum(login_counts.values())
high_risk = sum(1 for count in login_counts.values() if count >= 3)
medium_risk = sum(1 for count in login_counts.values() if 3 <= count < 5)

with open(blocked_file, "r") as blocked:
    blocked_ips = set(line.strip() for line in blocked if line.strip())

print(f"Total IPs monitored: {total_ips}")
print(f"Failed login attempts: {total_failed}")
print(f"High-risk IPs: {high_risk}")
print(f"Blocked IPs: {len(blocked_ips)}")
print(f"Medium-risk IPs: {medium_risk}")

print("\nHIGH-RISK SOURCES")

for ip, count in login_counts.items():
    if count >= 3:
        print(f"{ip} -> {count} failed attempts")

if high_risk > 0:
    print("\nSTATUS: SECURITY THREAT DETECTED")
else:
    print("\nSTATUS: SYSTEM NORMAL")

print("================================")
# Generate security report
with open("security_report.txt", "w") as report:
    report.write("MINI SOC SECURITY REPORT\n")
    report.write("========================\n")
    report.write(f"Total IPs monitored: {total_ips}\n")
    report.write(f"Failed login attempts: {total_failed}\n")
    report.write(f"High-risk IPs: {high_risk}\n")
    report.write(f"Medium-risk IPs: {medium_risk}\n")
    report.write(f"Blocked IPs: {len(blocked_ips)}\n\n")

    report.write("HIGH-RISK SOURCES\n")
    report.write("=================\n")

    for ip, count in login_counts.items():
        if count >= 3:
            report.write(f"{ip} -> {count} failed attempts\n")

    report.write("\nSUCCESSFUL LOGINS AFTER FAILED ATTEMPTS\n")
    report.write("=======================================\n")

    for ip in success_after_failure:
        report.write(f"{ip} had failed attempts before a successful login.\n")

print("\nSecurity report generated successfully.")