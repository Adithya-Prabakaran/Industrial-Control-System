# 🛡️ Real-Time Threat Detection Engine for ICS and SCADA Environments
### Hybrid Deep Packet Inspection + Statistical Anomaly Detection for Industrial Control Networks

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=for-the-badge&logo=python&logoColor=white)
![Streamlit](https://img.shields.io/badge/Frontend-Streamlit-red?style=for-the-badge&logo=streamlit&logoColor=white)
![Scapy](https://img.shields.io/badge/Network-Scapy-green?style=for-the-badge)
![Security](https://img.shields.io/badge/Security-ICS%2FSCADA-orange?style=for-the-badge)

## 📌 Overview

**A purpose-built threat detection engine for Industrial Control System (ICS) and SCADA networks** — targeting attack vectors that are completely invisible to conventional IDS tools.

Unlike general-purpose IDS solutions that focus on web-layer threats (SQL injection, XSS), this system performs **Deep Packet Inspection at the industrial protocol level** — detecting unauthorized Modbus write commands, DNP3 Direct Operate sequences, and Siemens S7comm CPU Stop commands in real time. These are the exact attack techniques used in Stuxnet, the 2015 Ukrainian power grid attack, and the Triton/TRISIS ICS malware campaign.

It combines **ICS Protocol DPI** for known attack signatures with a **Statistical Anomaly Engine** trained on baseline ICS traffic — and features a **Human-in-the-Loop Adaptive Learning System** that reduces false positives over time through analyst feedback.

---

## 🚀 Key Features

### 1. ⚙️ ICS/SCADA Protocol Deep Packet Inspection
Detects attacks targeting industrial protocols at the byte level:

| Protocol | Attack Detected | Severity |
| :--- | :--- | :--- |
| **Modbus TCP** | Write Register (FC=6) — unauthorized PLC register modification | 🔴 HIGH |
| **Modbus TCP** | Illegal Function Code (FC=90) — protocol abuse / fuzzing | 🔴 CRITICAL |
| **DNP3** | Direct Operate — unauthorized actuator control command | 🔴 HIGH |
| **Siemens S7comm** | CPU Stop Command — remote PLC shutdown | 🔴 CRITICAL |
| **SMBv1** | EternalBlue signature — lateral movement in OT network | 🔴 CRITICAL |

### 2. 🌐 Web & IT Layer Signatures
Covers the full attack surface of hybrid OT/IT networks:
* **SQL Injection** (`UNION SELECT` pattern matching)
* **Remote Code Execution** (`powershell`, `cmd.exe`, `/bin/bash`)
* **XSS Payloads** (`<script>` tags, `alert()`)
* **Scanner Tools** (`sqlmap`, `nmap`, `nikto`, `hydra`)

### 3. 🧠 Adaptive Intelligence (Human-in-the-Loop)
* **Real-Time Triage:** Analysts mark alerts as **✅ True Positive** or **❌ False Positive** directly in the dashboard.
* **Persistent Learning:** False Positive IPs are added to a persistent **Trusted Allowlist** (`trusted_ips.json`), permanently suppressing future noise from that source across sessions.

### 4. 🎥 Context-Aware Anomaly Engine
Trained on your network's own baseline traffic — distinguishes legitimate ICS polling from actual attacks:
* *Scenario A:* High-bandwidth traffic on Port 443 (HTTPS) → **Ignored** (streaming/normal).
* *Scenario B:* High-bandwidth traffic on Port 12345 (UDP) → **ALERT** (data exfiltration).
* **Sliding Window Rate Analysis:** Computes traffic velocity over 5-second windows, preventing long-lived flows from drifting above thresholds.

---

## ⚙️ Tech Stack

| Component | Technology |
| :--- | :--- |
| **Core Logic** | Python 3.10+ |
| **Packet Capture & Injection** | Scapy (`AsyncSniffer`, `sendp`, `Ether/IP/TCP/UDP`) |
| **DPI Engine** | Python `re` module — compiled byte-level regex |
| **Anomaly Detection** | NumPy — log1p scaling, IQR normalization, kNN distance scoring |
| **Dashboard** | Streamlit — real-time Live Triage Console |
| **Blocking** | `iptables` (Linux, auto-mode) / Alert-only (macOS/Windows) |
| **State Persistence** | JSON (`trusted_ips.json`) |

---

## 📂 Repository Structure

```text
Industrial-Control-System/
├── data/                       ← Captured baseline PCAPs for training (gitignored)
├── main.py                     ← Main Application (Streamlit)
├── test_ics_attack.py          ← ICS/SCADA attack simulation script (Scapy sendp)
├── requirements.txt            ← Python dependencies
├── trusted_ips.json            ← Persistent memory for learned Safe IPs
└── .gitignore                  ← Ignores heavy PCAP files
```

---

## ⚠️ Installation & Setup

### 1. Clone the Repository

```bash
git clone https://github.com/Adithya-Prabakaran/Industrial-Control-System.git
cd Industrial-Control-System
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. (Optional) Train the Anomaly Engine

The Signature Detection engine works immediately with no training required. To also enable the Anomaly Detection engine:

1. Switch to **Monitor Mode** → click **START RECORDING**
2. Browse normally for 3–5 minutes (multiple websites, streaming)
3. Click **STOP & SAVE** to capture a baseline PCAP
4. Switch to **Train Mode** → select your PCAP → click **Train Model**
5. Enable **Anomaly Detection (ML)** in the sidebar

---

## 🖥️ Usage Guide

### Start the Dashboard

**Mac / Linux:** (Requires root for packet sniffing)

```bash
sudo ./venv/bin/streamlit run main.py
```

**Windows:**

```bash
streamlit run main.py
```

### Modes of Operation

1. **Monitor Mode:** Captures live traffic to build a baseline `.pcap` file for anomaly training.
2. **Train Mode:** Reads the PCAP and trains the Statistical Anomaly Model (Median/IQR thresholds + kNN scoring).
3. **Active Detect:** Core detection mode. Sniffs live traffic, applies Signature + Anomaly engines, displays alerts in the **Live Triage Console**.
4. **Demo Mode:** Simulates attacks via button clicks — no terminal commands needed. Useful for safe demonstrations.

---

## 🧪 Live Attack Simulation

Test the detection engine in real time using a **second terminal** while the app is running in **Active Detect** mode with **Signature Detection ON**.

### Web / IT Attacks
```bash
# SQL Injection → 🔴 SQL Injection (HIGH)
curl "http://1.0.0.1/search?q=UNION+SELECT+password"

# Scanner Tool → 🟡 Scanner Tool (MEDIUM)
curl -A "sqlmap" http://1.0.0.1
```

### ICS / SCADA Protocol Attacks
Run the attack simulator script (requires root for raw packet injection):

```bash
# All ICS attacks in sequence
sudo ./venv/bin/python3 test_ics_attack.py --test all

# Individual attacks
sudo ./venv/bin/python3 test_ics_attack.py --test modbus_write   # → Modbus Write Register (HIGH)
sudo ./venv/bin/python3 test_ics_attack.py --test illegal_fc     # → Modbus Illegal FC (CRITICAL)
sudo ./venv/bin/python3 test_ics_attack.py --test dnp3           # → DNP3 Direct Operate (HIGH)
sudo ./venv/bin/python3 test_ics_attack.py --test s7             # → S7comm CPU Stop (CRITICAL)
sudo ./venv/bin/python3 test_ics_attack.py --test rce            # → RCE Attempt (CRITICAL)
sudo ./venv/bin/python3 test_ics_attack.py --test smb            # → SMBv1 Exploit (CRITICAL)
```

> ⚠️ **Note:** Start the app and switch to **Active Detect** mode *before* running these commands. Alerts appear in the Triage Console within seconds.
>
> 🍎 **macOS:** The attack script auto-detects your IP via `ipconfig getifaddr en0`. To override: `--target YOUR_IP`

---

## 📊 Detection Coverage

| Attack | Detection Method | Engine | Status |
| :--- | :--- | :--- | :--- |
| **SQL Injection** | Regex payload match | SIG | ✅ Detected |
| **RCE (PowerShell/bash)** | Regex payload match | SIG | ✅ Detected |
| **SMBv1 Exploit (EternalBlue)** | Magic byte sequence | SIG | ✅ Detected |
| **Scanner Tools (sqlmap/nmap)** | User-agent / payload match | SIG | ✅ Detected |
| **Modbus Write Register (FC=6)** | Binary protocol DPI | SIG | ✅ Detected |
| **Modbus Illegal Function Code** | Binary protocol DPI | SIG | ✅ Detected |
| **DNP3 Direct Operate** | Binary protocol DPI | SIG | ✅ Detected |
| **S7comm CPU Stop** | Binary protocol DPI | SIG | ✅ Detected |
| **ICMP Flood** | Packet rate threshold | SIG | ✅ Detected |
| **Data Exfiltration (volume)** | Byte rate anomaly | ANOM | ✅ Detected |
| **Port Scan** | SYN count heuristic | SIG | ✅ Detected |
| **YouTube / HTTPS Streaming** | Context-aware filter | Filter | 🔇 Correctly Ignored |

---

## 🔮 Future Roadmap

* [ ] **Deep Learning:** Replace kNN statistical model with Autoencoders for complex ICS pattern recognition.
* [ ] **Extended ICS Protocols:** Add EtherNet/IP (CIP), IEC 61850 GOOSE, and OPC-UA signatures.
* [ ] **SIEM Integration:** Forward structured alerts to Splunk or ELK Stack via syslog.
* [ ] **Dataset Benchmarking:** Evaluate against SWaT (Secure Water Treatment) labeled dataset for quantitative precision/recall metrics.
* [ ] **Email Alerts:** Automated SMTP notifications for CRITICAL severity threats.

---

*Project developed by Adithya Prabakaran*
