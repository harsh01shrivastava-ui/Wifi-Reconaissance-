# 📡 WiFiRecon

### Wi-Fi Security Analyzer for Windows

WiFiRecon is a Python-based Wi-Fi reconnaissance and security analysis tool for Windows.

It scans nearby wireless networks, analyzes their security configuration, evaluates potential risks, inspects saved Wi-Fi profile configurations, and generates security reports in TXT and JSON formats.

> **Note:** WiFiRecon does not extract, reveal, crack, or display Wi-Fi passwords.

---

## 🚀 Features

### 🔎 Nearby Network Scanner

- Detect nearby Wi-Fi networks
- Identify SSIDs
- Detect authentication methods
- Detect encryption types
- Identify BSSIDs
- Display signal strength
- Detect Wi-Fi band
- Detect wireless channel
- Handle multiple access points

### 🛡️ Security Analysis

WiFiRecon assigns a security score based on the detected wireless configuration.

| Configuration | Score | Risk |
|---|---:|---|
| WPA3 | 95/100 | LOW |
| WPA2 | 85/100 | LOW |
| WPA | 65/100 | MEDIUM |
| WEP | 25/100 | CRITICAL |
| Open / None | 20/100 | HIGH |
| Unknown | 50/100 | UNKNOWN |

The tool also provides security findings and recommendations.

---

## 📋 Network Details

Select a detected network to view:

- SSID
- Authentication
- Encryption
- Security score
- Risk level
- BSSID
- Signal strength
- Band
- Channel
- Security findings
- Recommendations

---

## 📡 Saved Profile Analysis

WiFiRecon can analyze Wi-Fi profiles configured on the local Windows machine.

It displays:

- Profile name
- Authentication
- Encryption / Cipher
- Connection mode
- Credential configuration status
- Risk classification

For security and privacy:

```text
Password: [HIDDEN]
The audit provides a consolidated view of the wireless security environment.
📊 Reports
WiFiRecon can generate:
TXT Report
Human-readable security report:
reports/wifi_report.txt

JSON Report
Structured report suitable for further processing:
reports/wifi_report.json

Example JSON structure:
{
  "tool": "WiFiRecon",
  "generated": "timestamp",
  "nearby_networks": [],
  "saved_profiles": []
}

Generated reports are excluded from Git using .gitignore.
🖥️ Interface
WiFiRecon provides a Tkinter-based graphical interface with:
WiFiRecon
│
├── Nearby Networks
│   ├── Network Scanner
│   ├── Security Analysis
│   └── Network Details
│
├── Saved Profiles
│   ├── Configuration Analysis
│   └── Risk Assessment
│
└── Full Wi-Fi Audit
    └── Report Generation

⚙️ Requirements
- Windows 10/11
- Python 3.x
- Tkinter
- Windows netsh WLAN functionality
No external Python packages are currently required.
🔧 Installation
Clone the repository:
git clone https://github.com/harsh01shrivastava-ui/Wifi-Reconnaissance-.git

Enter the project directory:
cd Wifi-Reconnaissance-

Run the GUI:
python wifi_gui.py

🖥️ Command-Line Version
The project also includes the command-line Wi-Fi analyzer:
python wifi_recon.py

The CLI provides options for:
1. Scan Nearby Networks
2. Analyze Saved Profiles
3. Full Wi-Fi Audit
4. Exit

📁 Project Structure
Wifi-Reconnaissance-
│
├── wifi_gui.py
├── wifi_recon.py
├── reports/
│
├── .gitignore
├── README.md
└── LICENSE

🔐 Security & Privacy
WiFiRecon is designed for defensive security analysis and authorized environments.
The tool:
- Uses Windows WLAN information available to the local system
- Does not perform password cracking
- Does not reveal stored Wi-Fi passwords
- Does not capture wireless handshakes
- Does not perform credential theft
- Does not attempt unauthorized access to networks
Only analyze networks and systems you own or have permission to assess.
🎯 Project Goals
The main goals of WiFiRecon are to:
1. Understand wireless network reconnaissance.
2. Analyze Wi-Fi security configurations.
3. Build a practical security assessment tool.
4. Learn Windows networking interfaces.
5. Practice Python automation and GUI development.
6. Generate structured security reports.
🔮 Future Improvements
Planned improvements include:
- [ ] Improved dashboard
- [ ] Risk-colored network table
- [ ] Security statistics
- [ ] Advanced channel analysis
- [ ] Historical scan comparison
- [ ] Export to CSV
- [ ] Improved report visualization
- [ ] Modular project architecture
- [ ] Additional wireless security checks
🛠️ Technologies
- Python
- Tkinter
- Windows netsh
- Regular Expressions
- JSON
- Git & GitHub
👨‍💻 Author
Harshvardhan Shrivastava
Computer Science Engineering
Cybersecurity
GitHub:
https://github.com/harsh01shrivastava-ui
LinkedIn:
https://linkedin.com/in/harshvardhan-shrivastava
📜 License
This project is licensed under the MIT License.