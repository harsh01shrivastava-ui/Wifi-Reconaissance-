import tkinter as tk
from tkinter import ttk, messagebox
import subprocess
import re
import wifi_recon


# =========================
# SECURITY ANALYSIS
# =========================

def security_score(auth, encryption):
    auth = auth.lower()
    encryption = encryption.lower()

    if "open" in auth or encryption == "none":
        return 20, "HIGH"

    if "wep" in auth:
        return 25, "CRITICAL"

    if "wpa3" in auth:
        return 95, "LOW"

    if "wpa2" in auth:
        return 85, "LOW"

    if "wpa" in auth:
        return 65, "MEDIUM"

    return 50, "UNKNOWN"


def security_findings(auth, encryption):
    findings = []
    recommendations = []

    auth_lower = auth.lower()
    encryption_lower = encryption.lower()

    if "open" in auth_lower or encryption_lower == "none":
        findings.append("No wireless authentication/encryption detected.")
        findings.append("Sensitive traffic may be exposed on an open network.")
        recommendations.append("Prefer WPA2 or WPA3 protected networks.")

    elif "wep" in auth_lower:
        findings.append("WEP encryption detected.")
        findings.append("WEP is obsolete and insecure.")
        recommendations.append("Avoid WEP networks and use WPA2/WPA3.")

    elif "wpa3" in auth_lower:
        findings.append("Modern WPA3 authentication detected.")
        recommendations.append("WPA3 provides strong modern wireless protection.")

    elif "wpa2" in auth_lower:
        findings.append("WPA2 authentication detected.")
        recommendations.append("WPA2 is generally suitable when configured with a strong password.")

    elif "wpa" in auth_lower:
        findings.append("Older WPA authentication detected.")
        recommendations.append("Prefer WPA2 or WPA3 where available.")

    else:
        findings.append("Security configuration could not be fully classified.")
        recommendations.append("Verify the network configuration manually.")

    return findings, recommendations


# =========================
# WIFI SCANNER
# =========================

def scan_wifi(strict=False):
    try:
        result = subprocess.run(
            ["netsh", "wlan", "show", "networks", "mode=bssid"],
            capture_output=True,
            text=True
        )
    except OSError as error:
        if strict:
            raise RuntimeError(f"Unable to run the Wi-Fi network scan: {error}") from error
        return []

    if result.returncode != 0:
        if strict:
            message = result.stderr.strip() or "netsh could not scan nearby Wi-Fi networks."
            raise RuntimeError(message)
        return []

    output = result.stdout

    networks = []
    current_network = None
    current_ap = None

    for line in output.splitlines():

        line = line.strip()

        # -------------------------
        # SSID
        # -------------------------
        ssid_match = re.match(r"SSID\s+\d+\s*:\s*(.*)", line)

        if ssid_match:
            ssid = ssid_match.group(1).strip()

            current_network = {
                "SSID": ssid,
                "Authentication": "Unknown",
                "Encryption": "Unknown",
                "AccessPoints": []
            }

            networks.append(current_network)
            current_ap = None
            continue

        if current_network is None:
            continue

        # -------------------------
        # Authentication
        # -------------------------
        auth_match = re.match(r"Authentication\s*:\s*(.*)", line)

        if auth_match and current_ap is None:
            current_network["Authentication"] = auth_match.group(1).strip()
            continue

        # -------------------------
        # Encryption
        # -------------------------
        encryption_match = re.match(r"Encryption\s*:\s*(.*)", line)

        if encryption_match and current_ap is None:
            current_network["Encryption"] = encryption_match.group(1).strip()
            continue

        # -------------------------
        # BSSID
        # -------------------------
        bssid_match = re.match(r"BSSID\s+\d+\s*:\s*(.*)", line)

        if bssid_match:
            current_ap = {
                "BSSID": bssid_match.group(1).strip(),
                "Signal": "Unknown",
                "Band": "Unknown",
                "Channel": "Unknown"
            }

            current_network["AccessPoints"].append(current_ap)
            continue

        if current_ap is None:
            continue

        # -------------------------
        # Signal
        # -------------------------
        signal_match = re.match(r"Signal\s*:\s*(.*)", line)

        if signal_match:
            current_ap["Signal"] = signal_match.group(1).strip()
            continue

        # -------------------------
        # Channel
        # -------------------------
        channel_match = re.match(r"Channel\s*:\s*(.*)", line)

        if channel_match:
            current_ap["Channel"] = channel_match.group(1).strip()
            continue

        # -------------------------
        # Radio type / Band
        # -------------------------
        radio_match = re.match(r"Radio type\s*:\s*(.*)", line)

        if radio_match:
            radio = radio_match.group(1).strip()

            if "802.11a" in radio or "802.11ac" in radio or "802.11ax" in radio:
                current_ap["Band"] = "5 GHz"
            else:
                current_ap["Band"] = "2.4 GHz"

    return networks


# =========================
# GUI
# =========================

root = tk.Tk()

root.title("WiFiRecon - Wi-Fi Security Analyzer")
root.geometry("1250x720")
root.minsize(900, 600)


# =========================
# HEADER
# =========================

header = tk.Frame(root)
header.pack(fill="x", padx=20, pady=(15, 5))

title = tk.Label(
    header,
    text="WiFiRecon",
    font=("Segoe UI", 24, "bold")
)
title.pack(anchor="w")

subtitle = tk.Label(
    header,
    text="Wi-Fi Security Analyzer",
    font=("Segoe UI", 11)
)
subtitle.pack(anchor="w")


# =========================
# BUTTONS
# =========================

button_frame = tk.Frame(root)
button_frame.pack(fill="x", padx=20, pady=10)

scan_button = tk.Button(
    button_frame,
    text="Scan Nearby Networks",
    width=20,
    command=lambda: perform_scan()
)

scan_button.pack(side="left")

full_audit_button = tk.Button(
    button_frame,
    text="Full Wi-Fi Audit",
    width=18,
    command=lambda: run_full_audit()
)
full_audit_button.pack(side="left", padx=10)

exit_button = tk.Button(
    button_frame,
    text="Exit",
    width=10,
    command=root.destroy
)

exit_button.pack(side="left", padx=10)


# =========================
# MAIN CONTENT
# =========================

content = tk.Frame(root)
content.pack(fill="both", expand=True, padx=20, pady=5)

notebook = ttk.Notebook(content)
notebook.pack(fill="both", expand=True)

nearby_tab = ttk.Frame(notebook)
profiles_tab = ttk.Frame(notebook)
notebook.add(nearby_tab, text="Nearby Networks")
notebook.add(profiles_tab, text="Saved Profiles")

# Left side: network table
left_frame = tk.Frame(nearby_tab)
left_frame.pack(side="left", fill="both", expand=True)


columns = (
    "SSID",
    "Security",
    "Encryption",
    "Signal",
    "Band",
    "Channel",
    "Score",
    "Risk"
)

tree = ttk.Treeview(
    left_frame,
    columns=columns,
    show="headings",
    height=20
)

for column in columns:

    tree.heading(
        column,
        text=column
    )

    tree.column(
        column,
        width=100,
        anchor="center"
    )


tree.column("SSID", width=130)
tree.column("Security", width=80)
tree.column("Encryption", width=85)
tree.column("Signal", width=75)
tree.column("Band", width=75)
tree.column("Channel", width=75)
tree.column("Score", width=75)
tree.column("Risk", width=75)

tree.pack(
    side="left",
    fill="both",
    expand=True
)


scrollbar = ttk.Scrollbar(
    left_frame,
    orient="vertical",
    command=tree.yview
)

scrollbar.pack(
    side="right",
    fill="y"
)

tree.configure(
    yscrollcommand=scrollbar.set
)


# =========================
# DETAILS PANEL
# =========================

details_frame = tk.LabelFrame(
    nearby_tab,
    text="Network Details",
    padx=12,
    pady=10,
    width=400
)

details_frame.pack(
    side="right",
    fill="both",
    padx=(15, 0)
)

details_frame.pack_propagate(False)

details_text = tk.Text(
    details_frame,
    width=48,
    height=25,
    font=("Consolas", 10),
    wrap="word",
    state="disabled"
)

details_scroll = ttk.Scrollbar(
    details_frame,
    orient="vertical",
    command=details_text.yview
)

details_scroll.pack(
    side="right",
    fill="y"
)

details_text.pack(
    side="left",
    fill="both",
    expand=True
)

details_text.configure(
    yscrollcommand=details_scroll.set
)


# =========================
# SAVED PROFILES
# =========================

profiles_table_frame = ttk.Frame(profiles_tab)
profiles_table_frame.pack(
    side="left",
    fill="both",
    expand=True,
    padx=(0, 12),
    pady=10
)

profile_columns = (
    "Profile",
    "Authentication",
    "Encryption",
    "Connection",
    "Credential",
    "Risk"
)

profiles_tree = ttk.Treeview(
    profiles_table_frame,
    columns=profile_columns,
    show="headings",
    height=20
)

for column in profile_columns:
    profiles_tree.heading(column, text=column)
    profiles_tree.column(column, anchor="center", width=125)

profiles_tree.column("Profile", width=190, anchor="w")
profiles_tree.column("Authentication", width=150)
profiles_tree.column("Encryption", width=110)
profiles_tree.column("Connection", width=150)
profiles_tree.column("Credential", width=115)
profiles_tree.column("Risk", width=90)

profiles_vertical_scroll = ttk.Scrollbar(
    profiles_table_frame,
    orient="vertical",
    command=profiles_tree.yview
)
profiles_horizontal_scroll = ttk.Scrollbar(
    profiles_table_frame,
    orient="horizontal",
    command=profiles_tree.xview
)
profiles_tree.configure(
    yscrollcommand=profiles_vertical_scroll.set,
    xscrollcommand=profiles_horizontal_scroll.set
)
profiles_tree.grid(row=0, column=0, sticky="nsew")
profiles_vertical_scroll.grid(row=0, column=1, sticky="ns")
profiles_horizontal_scroll.grid(row=1, column=0, sticky="ew")
profiles_table_frame.rowconfigure(0, weight=1)
profiles_table_frame.columnconfigure(0, weight=1)

profile_details_frame = tk.LabelFrame(
    profiles_tab,
    text="Profile Details",
    padx=12,
    pady=10,
    width=350
)
profile_details_frame.pack(
    side="right",
    fill="both",
    padx=(0, 5),
    pady=10
)
profile_details_frame.pack_propagate(False)

profile_details_text = tk.Text(
    profile_details_frame,
    width=40,
    height=25,
    font=("Consolas", 10),
    wrap="word",
    state="disabled"
)
profile_details_scroll = ttk.Scrollbar(
    profile_details_frame,
    orient="vertical",
    command=profile_details_text.yview
)
profile_details_scroll.pack(side="right", fill="y")
profile_details_text.pack(side="left", fill="both", expand=True)
profile_details_text.configure(yscrollcommand=profile_details_scroll.set)


# =========================
# STATUS BAR
# =========================

status = tk.Label(
    root,
    text="Ready",
    anchor="w"
)

status.pack(
    fill="x",
    padx=20,
    pady=(5, 10)
)


# =========================
# GLOBAL DATA
# =========================

network_data = []
profile_data = []


# =========================
# DISPLAY DETAILS
# =========================

def show_details(event=None):

    selected = tree.selection()

    if not selected:
        return

    index = int(tree.item(selected[0], "tags")[0])

    network = network_data[index]

    ssid = network["SSID"]
    auth = network["Authentication"]
    encryption = network["Encryption"]

    score, risk = security_score(
        auth,
        encryption
    )

    findings, recommendations = security_findings(
        auth,
        encryption
    )

    details = ""

    details += f"SSID\n"
    details += f"  {ssid}\n\n"

    details += f"Security\n"
    details += f"  {auth}\n\n"

    details += f"Encryption\n"
    details += f"  {encryption}\n\n"

    details += f"Security Score\n"
    details += f"  {score}/100\n\n"

    details += f"Risk Level\n"
    details += f"  {risk}\n\n"

    details += "Access Points\n"
    details += "────────────────────────\n"

    for i, ap in enumerate(network["AccessPoints"], 1):

        details += f"\nAP {i}\n"
        details += f"BSSID:   {ap['BSSID']}\n"
        details += f"Signal:  {ap['Signal']}\n"
        details += f"Band:    {ap['Band']}\n"
        details += f"Channel: {ap['Channel']}\n"

    details += "\n\nSecurity Findings\n"
    details += "────────────────────────\n"

    for finding in findings:
        details += f"• {finding}\n"

    details += "\nRecommendations\n"
    details += "────────────────────────\n"

    for recommendation in recommendations:
        details += f"• {recommendation}\n"

    details_text.config(state="normal")
    details_text.delete("1.0", tk.END)
    details_text.insert("1.0", details)
    details_text.config(state="disabled")


# =========================
# SCAN FUNCTION
# =========================

def perform_scan(networks=None):

    global network_data

    status.config(text="Scanning...")
    root.update_idletasks()

    tree.delete(*tree.get_children())

    network_data = scan_wifi() if networks is None else networks

    for index, network in enumerate(network_data):

        auth = network["Authentication"]
        encryption = network["Encryption"]

        score, risk = security_score(
            auth,
            encryption
        )

        access_points = network["AccessPoints"]

        if access_points:

            try:
                strongest = max(
                    access_points,
                    key=lambda x: int(
                        x["Signal"].replace("%", "")
                    )
                )
            except:
                strongest = access_points[0]

            signal = strongest["Signal"]
            band = strongest["Band"]
            channel = strongest["Channel"]

        else:

            signal = "Unknown"
            band = "Unknown"
            channel = "Unknown"

        tree.insert(
            "",
            "end",
            values=(
                network["SSID"],
                auth,
                encryption,
                signal,
                band,
                channel,
                f"{score}/100",
                risk
            ),
            tags=(str(index),)
        )

    status.config(
        text=f"Scan complete | {len(network_data)} networks detected"
    )

    if network_data:
        first_item = tree.get_children()[0]
        tree.selection_set(first_item)
        tree.focus(first_item)
        show_details()


# Read only profile configuration fields; password-related output is never requested or parsed.
def load_saved_profiles(strict=False):
    global profile_data

    profiles_tree.delete(*profiles_tree.get_children())
    profile_details_text.config(state="normal")
    profile_details_text.delete("1.0", tk.END)
    profile_details_text.config(state="disabled")
    status.config(text="Loading saved Wi-Fi profiles...")
    root.update_idletasks()

    try:
        result = subprocess.run(
            ["netsh", "wlan", "show", "profiles"],
            capture_output=True,
            text=True
        )
    except OSError as error:
        profile_data = []
        status.config(text=f"Unable to load saved profiles: {error}")
        if strict:
            raise RuntimeError(f"Unable to load saved Wi-Fi profiles: {error}") from error
        return profile_data

    if result.returncode != 0:
        profile_data = []
        message = result.stderr.strip() or "netsh could not list saved Wi-Fi profiles."
        status.config(text=message)
        if strict:
            raise RuntimeError(message)
        return profile_data

    profile_names = []
    for line in result.stdout.splitlines():
        match = re.match(r"\s*(?:All User Profile|User Profile)\s*:\s*(.*?)\s*$", line, re.IGNORECASE)
        if match:
            profile_names.append(match.group(1))

    profile_data = []
    for profile_name in profile_names:
        try:
            profile_result = subprocess.run(
                ["netsh", "wlan", "show", "profile", f'name="{profile_name}"'],
                capture_output=True,
                text=True
            )
        except OSError as error:
            if strict:
                raise RuntimeError(f"Unable to load profile '{profile_name}': {error}") from error
            profile_result = None

        profile = {
            "Profile": profile_name,
            "Authentication": "Unknown",
            "Encryption": "Unknown",
            "Connection": "Unknown",
            "Credential": "Configured"
        }

        if profile_result and profile_result.returncode == 0:
            for line in profile_result.stdout.splitlines():
                field_match = re.match(
                    r"\s*(Authentication|Cipher|Connection mode)\s*:\s*(.*?)\s*$",
                    line,
                    re.IGNORECASE
                )
                if field_match:
                    field_name = field_match.group(1).lower()
                    value = field_match.group(2)
                    if field_name == "authentication":
                        profile["Authentication"] = value
                    elif field_name == "cipher":
                        profile["Encryption"] = value
                    else:
                        profile["Connection"] = value
        elif strict:
            message = profile_result.stderr.strip() if profile_result else ""
            message = message or f"netsh could not load profile '{profile_name}'."
            raise RuntimeError(message)

        if "wep" in profile["Authentication"].lower() or "wep" in profile["Encryption"].lower():
            risk = "CRITICAL"
        else:
            _, risk = security_score(
                profile["Authentication"],
                profile["Encryption"]
            )
        profile["Risk"] = risk
        profile_data.append(profile)

        profiles_tree.insert(
            "",
            "end",
            values=(
                profile["Profile"],
                profile["Authentication"],
                profile["Encryption"],
                profile["Connection"],
                profile["Credential"],
                profile["Risk"]
            ),
            tags=(str(len(profile_data) - 1),)
        )

    status.config(text=f"Saved profiles loaded | {len(profile_data)} profiles detected")
    return profile_data


def show_profile_details(event=None):
    selected = profiles_tree.selection()
    if not selected:
        return

    index = int(profiles_tree.item(selected[0], "tags")[0])
    profile = profile_data[index]
    findings, recommendations = security_findings(
        profile["Authentication"],
        profile["Encryption"]
    )
    if profile["Risk"] == "CRITICAL":
        recommendation = "Avoid WEP and use WPA2 or WPA3."
    else:
        recommendation = recommendations[0] if recommendations else "Verify the profile security configuration."

    details = (
        f"Profile\n  {profile['Profile']}\n\n"
        f"Authentication\n  {profile['Authentication']}\n\n"
        f"Encryption\n  {profile['Encryption']}\n\n"
        f"Connection Mode\n  {profile['Connection']}\n\n"
        f"Credential status\n  {profile['Credential']}\n\n"
        f"Risk Level\n  {profile['Risk']}\n\n"
        "Password\n  [HIDDEN]\n\n"
        f"Security Recommendation\n  {recommendation}"
    )

    profile_details_text.config(state="normal")
    profile_details_text.delete("1.0", tk.END)
    profile_details_text.insert("1.0", details)
    profile_details_text.config(state="disabled")


def run_full_audit():
    full_audit_button.config(state="disabled")
    status.config(text="Running full Wi-Fi audit...")
    root.update_idletasks()

    error_message = None
    try:
        networks = scan_wifi(strict=True)
        perform_scan(networks)

        profiles = load_saved_profiles(strict=True)
        profile_names = [profile["Profile"] for profile in profiles]

        high_critical_count = 0
        finding_count = 0
        for network in networks:
            _, risk = security_score(
                network["Authentication"],
                network["Encryption"]
            )
            findings, _ = security_findings(
                network["Authentication"],
                network["Encryption"]
            )
            finding_count += len(findings)
            if risk in ("HIGH", "CRITICAL"):
                high_critical_count += 1

        wifi_recon.generate_reports(networks, profile_names)
    except Exception as error:
        error_message = str(error) or error.__class__.__name__
        status.config(text="Full Wi-Fi audit failed")
    finally:
        full_audit_button.config(state="normal")

    if error_message:
        messagebox.showerror(
            "Full Wi-Fi Audit Failed",
            f"The full Wi-Fi audit could not be completed.\n\n{error_message}"
        )
        return

    status.config(
        text=f"Full audit complete | {len(networks)} networks | {len(profiles)} saved profiles"
    )
    messagebox.showinfo(
        "Full Wi-Fi Audit Complete",
        "Full Wi-Fi Audit Complete\n\n"
        f"Nearby Networks: {len(networks)}\n"
        f"High/Critical Risk Networks: {high_critical_count}\n"
        f"Saved Profiles: {len(profiles)}\n"
        f"Security Findings: {finding_count}\n\n"
        "Reports generated:\n"
        "- reports/wifi_report.txt\n"
        "- reports/wifi_report.json"
    )


# =========================
# CLICK EVENT
# =========================

tree.bind(
    "<<TreeviewSelect>>",
    show_details
)

profiles_tree.bind(
    "<<TreeviewSelect>>",
    show_profile_details
)


def on_tab_changed(event=None):
    if notebook.select() == str(profiles_tab):
        load_saved_profiles()


notebook.bind("<<NotebookTabChanged>>", on_tab_changed)


# =========================
# START GUI
# =========================

root.mainloop()