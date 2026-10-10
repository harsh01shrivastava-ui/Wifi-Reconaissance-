import subprocess
import re
import json
from datetime import datetime
import os

def generate_reports(networks, profiles):
    os.makedirs("reports", exist_ok=True)

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # =========================
    # TXT REPORT
    # =========================

    txt_path = os.path.join(
        "reports",
        "wifi_report.txt"
    )

    with open(txt_path, "w", encoding="utf-8") as file:

        file.write("=" * 80 + "\n")
        file.write("WiFiRecon Security Report\n")
        file.write("=" * 80 + "\n\n")

        file.write(f"Generated: {timestamp}\n\n")

        file.write("NEARBY NETWORKS\n")
        file.write("-" * 80 + "\n\n")

        for network in networks:

            score, risk, findings = analyze_security(network)

            file.write(f"SSID: {network['SSID']}\n")
            file.write(
                f"Authentication: "
                f"{network['Authentication']}\n"
            )
            file.write(
                f"Encryption: "
                f"{network['Encryption']}\n"
            )
            file.write(f"Security Score: {score}/100\n")
            file.write(f"Risk Level: {risk}\n")

            file.write("\nAccess Points:\n")

            for ap in network["AccessPoints"]:

                file.write(
                    f"  BSSID: {ap['BSSID']}\n"
                )
                file.write(
                    f"  Signal: {ap['Signal']}\n"
                )
                file.write(
                    f"  Band: {ap['Band']}\n"
                )
                file.write(
                    f"  Channel: {ap['Channel']}\n"
                )

            file.write("\nFindings:\n")

            for finding in findings:
                file.write(f"  - {finding}\n")

            file.write("\n" + "-" * 80 + "\n")

        file.write("\nSAVED WI-FI PROFILES\n")
        file.write("-" * 80 + "\n\n")

        for profile in profiles:

            details = get_profile_details(profile)
            risk = analyze_profile(details)

            file.write(
                f"Profile: {details['Profile']}\n"
            )
            file.write(
                f"Authentication: "
                f"{details['Authentication']}\n"
            )
            file.write(
                f"Encryption: "
                f"{details['Encryption']}\n"
            )
            file.write(
                f"Connection Mode: "
                f"{details['Connection Mode']}\n"
            )
            file.write(
                f"Risk Level: {risk}\n"
            )
            file.write(
                "Password: [HIDDEN]\n\n"
            )

    # =========================
    # JSON REPORT
    # =========================

    json_path = os.path.join(
        "reports",
        "wifi_report.json"
    )

    report_data = {
        "tool": "WiFiRecon",
        "generated": timestamp,
        "nearby_networks": networks,
        "saved_profiles": []
    }

    for profile in profiles:

        details = get_profile_details(profile)

        report_data["saved_profiles"].append(details)

    with open(
        json_path,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            report_data,
            file,
            indent=4
        )

    print("\n[+] Reports generated:")
    print(f"    TXT  : {txt_path}")
    print(f"    JSON : {json_path}")
# ==============================
# COMMAND EXECUTION
# ==============================

def run_command(command):
    result = subprocess.run(
        command,
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        return ""

    return result.stdout


# ==============================
# NEARBY WI-FI SCANNER
# ==============================

def scan_wifi():
    return run_command(
        ["netsh", "wlan", "show", "networks", "mode=bssid"]
    )


def parse_networks(output):
    networks = []
    current_network = None
    current_ap = None

    for line in output.splitlines():
        line = line.strip()

        # New SSID
        if line.startswith("SSID ") and ":" in line:

            if current_network:
                networks.append(current_network)

            current_network = {
                "SSID": line.split(":", 1)[1].strip(),
                "Authentication": "Unknown",
                "Encryption": "Unknown",
                "AccessPoints": []
            }

            current_ap = None

        elif current_network:

            if line.startswith("Authentication") and ":" in line:
                current_network["Authentication"] = (
                    line.split(":", 1)[1].strip()
                )

            elif line.startswith("Encryption") and ":" in line:
                current_network["Encryption"] = (
                    line.split(":", 1)[1].strip()
                )

            elif re.match(r"BSSID \d+\s*:", line):

                bssid = line.split(":", 1)[1].strip()

                current_ap = {
                    "BSSID": bssid,
                    "Signal": "Unknown",
                    "Band": "Unknown",
                    "Channel": "Unknown"
                }

                current_network["AccessPoints"].append(current_ap)

            elif current_ap:

                if line.startswith("Signal") and ":" in line:
                    current_ap["Signal"] = (
                        line.split(":", 1)[1].strip()
                    )

                elif line.startswith("Band") and ":" in line:
                    current_ap["Band"] = (
                        line.split(":", 1)[1].strip()
                    )

                elif line.startswith("Channel") and ":" in line:
                    current_ap["Channel"] = (
                        line.split(":", 1)[1].strip()
                    )

    if current_network:
        networks.append(current_network)

    return networks


# ==============================
# SECURITY ANALYSIS
# ==============================

def analyze_security(network):

    auth = network["Authentication"].lower()
    encryption = network["Encryption"].lower()

    findings = []

    if auth == "open" or encryption == "none":

        score = 20
        risk = "HIGH"

        findings.append(
            "Open network with no wireless encryption."
        )

        findings.append(
            "Avoid sending sensitive information over this network."
        )

    elif "wep" in auth or "wep" in encryption:

        score = 25
        risk = "CRITICAL"

        findings.append(
            "WEP is obsolete and insecure."
        )

        findings.append(
            "Upgrade to WPA2 or WPA3."
        )

    elif "wpa3" in auth:

        score = 95
        risk = "LOW"

        findings.append(
            "Modern WPA3 authentication detected."
        )

    elif "wpa2" in auth:

        score = 85
        risk = "LOW"

        findings.append(
            "WPA2 authentication detected."
        )

        findings.append(
            "Consider WPA3 if supported by the router."
        )

    elif "wpa" in auth:

        score = 65
        risk = "MEDIUM"

        findings.append(
            "Older WPA authentication detected."
        )

    else:

        score = 50
        risk = "UNKNOWN"

        findings.append(
            "Security configuration could not be classified."
        )

    return score, risk, findings


def display_networks(networks):

    print("\n" + "=" * 90)
    print("                     Nearby Wi-Fi Networks")
    print("=" * 90)

    for index, network in enumerate(networks, start=1):

        score, risk, findings = analyze_security(network)

        print(f"\n[{index}] {network['SSID']}")
        print("-" * 70)

        print(f"    Authentication : {network['Authentication']}")
        print(f"    Encryption     : {network['Encryption']}")
        print(f"    Security Score : {score}/100")
        print(f"    Risk Level     : {risk}")
        print(f"    Access Points  : {len(network['AccessPoints'])}")

        for ap in network["AccessPoints"]:

            print(
                f"\n      BSSID   : {ap['BSSID']}"
                f"\n      Signal  : {ap['Signal']}"
                f"\n      Band    : {ap['Band']}"
                f"\n      Channel : {ap['Channel']}"
            )

        print("\n    Findings:")

        for finding in findings:
            print(f"      [!] {finding}")

    print("\n" + "=" * 90)
    print(f"[+] Networks detected: {len(networks)}")
    print("=" * 90)


# ==============================
# SAVED WI-FI PROFILES
# ==============================

def get_saved_profiles():

    output = run_command(
        ["netsh", "wlan", "show", "profiles"]
    )

    profiles = []

    for line in output.splitlines():

        if "All User Profile" in line:

            profile = line.split(":", 1)[1].strip()

            if profile:
                profiles.append(profile)

    return profiles


def get_profile_details(profile):

    output = run_command(
        ["netsh", "wlan", "show", "profile", f"name={profile}"]
    )

    details = {
        "Profile": profile,
        "Authentication": "Unknown",
        "Encryption": "Unknown",
        "Connection Mode": "Unknown"
    }

    for line in output.splitlines():

        line = line.strip()

        if line.startswith("Authentication") and ":" in line:

            details["Authentication"] = (
                line.split(":", 1)[1].strip()
            )

        elif line.startswith("Cipher") and ":" in line:

            details["Encryption"] = (
                line.split(":", 1)[1].strip()
            )

        elif line.startswith("Connection mode") and ":" in line:

            details["Connection Mode"] = (
                line.split(":", 1)[1].strip()
            )

    return details


def analyze_profile(details):

    auth = details["Authentication"].lower()

    if "wpa3" in auth:
        return "LOW"

    if "wpa2" in auth:
        return "LOW"

    if "wpa" in auth:
        return "MEDIUM"

    if "wep" in auth:
        return "CRITICAL"

    if auth == "open":
        return "HIGH"

    return "UNKNOWN"


def display_saved_profiles(profiles):

    print("\n" + "=" * 75)
    print("                    Saved Wi-Fi Profiles")
    print("=" * 75)

    if not profiles:

        print("\n[-] No saved profiles found.")
        return

    print(f"\n[+] Profiles found: {len(profiles)}")

    for index, profile in enumerate(profiles, start=1):

        details = get_profile_details(profile)
        risk = analyze_profile(details)

        print("\n" + "-" * 75)

        print(f"[{index}] {details['Profile']}")
        print(f"    Authentication : {details['Authentication']}")
        print(f"    Encryption     : {details['Encryption']}")
        print(f"    Connection     : {details['Connection Mode']}")
        print(f"    Credential     : Stored/Configured")
        print(f"    Password       : ********")
        print(f"    Risk Level     : {risk}")

    print("\n" + "=" * 75)


# ==============================
# FULL AUDIT
# ==============================

def full_audit():

    print("\n" + "=" * 75)
    print("                     FULL WI-FI AUDIT")
    print("=" * 75)

    print("\n[*] Scanning nearby networks...")

    raw_output = scan_wifi()

    networks = []

    if raw_output:
        networks = parse_networks(raw_output)

        if networks:
            display_networks(networks)
        else:
            print("[-] No nearby networks detected.")

    print("\n[*] Reading saved Wi-Fi profiles...")

    profiles = get_saved_profiles()

    display_saved_profiles(profiles)

    print("\n[*] Generating reports...")

    generate_reports(networks, profiles)

# ==============================
# MAIN MENU
# ==============================

def main():

    while True:

        print("\n")
        print("=" * 45)
        print("              WiFiRecon")
        print("=" * 45)

        print("1. Scan Nearby Networks")
        print("2. Analyze Saved Profiles")
        print("3. Full Wi-Fi Audit")
        print("4. Exit")

        print("=" * 45)

        choice = input("\nSelect option: ").strip()

        if choice == "1":

            raw_output = scan_wifi()

            if raw_output:

                networks = parse_networks(raw_output)

                if networks:
                    display_networks(networks)
                else:
                    print("[-] No networks detected.")

        elif choice == "2":

            profiles = get_saved_profiles()
            display_saved_profiles(profiles)

        elif choice == "3":

            full_audit()

        elif choice == "4":

            print("\n[+] Exiting WiFiRecon...")
            break

        else:

            print("\n[-] Invalid option.")


if __name__ == "__main__":
    main()