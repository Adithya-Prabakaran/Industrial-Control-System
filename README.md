# 🛡️ Hybrid Network Traffic Analysis & Anomaly Detection Engine
### High-Throughput Real-Time Data Processing with Context-Aware Filtering

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=for-the-badge&logo=python&logoColor=white)
![Streamlit](https://img.shields.io/badge/Frontend-Streamlit-red?style=for-the-badge&logo=streamlit&logoColor=white)
![Scapy](https://img.shields.io/badge/Network-Scapy-green?style=for-the-badge)
![Security](https://img.shields.io/badge/Security-Adaptive_IDS-orange?style=for-the-badge)

## 📌 Overview
**A production-grade Network Intrusion Detection & Prevention System (NIDS/IPS)** designed to solve the biggest challenge in modern cybersecurity: **False Positives.**

Unlike traditional academic IDS projects that flag *any* high-bandwidth traffic (like YouTube or Netflix) as an attack, this system uses a **Context-Aware Hybrid Engine**. It combines **Signature Matching** for known threats (SQLi, XSS, RCE) with **Statistical Anomaly Detection** that intelligently distinguishes between legitimate streaming traffic and actual data exfiltration.

It features a **"Human-in-the-Loop" Adaptive Learning System**, allowing analysts to flag False Positives in real-time, permanently teaching the model to ignore safe traffic.

## 🚀 Key Features

### 1. 🧠 Adaptive Intelligence (Human-in-the-Loop)
* **Real-Time Triage:** The dashboard allows analysts to mark alerts as **✅ True Positive** or **❌ False Positive**.
* **Persistent Learning:** Marking an IP as "False Positive" adds it to a persistent **Trusted Allowlist** (`trusted_ips.json`), preventing future spam alerts from that source.

### 2. 🎥 Context-Aware Anomaly Engine
* **Streaming vs. Exfiltration:** Uses a **Smart Protocol Filter** to validate high-bandwidth traffic.
    * *Scenario A:* 15 MB/s on Port 443 (HTTPS) → **Ignored** (Likely YouTube/Netflix).
    * *Scenario B:* 15 MB/s on Port 12345 (UDP) → **ALERT** (Data Exfiltration).
* **Windowed Rate Analysis:** Calculates traffic velocity (Bytes/Sec) over sliding windows rather than cumulative totals, preventing long-duration connections from drifting into "anomaly" territory.

### 3. ⚡ Hybrid Detection Logic
* **Signature Engine:** Regex-based detection for:
    * SQL Injection (`UNION SELECT`)
    * Remote Code Execution (RCE) via `cmd.exe`, `powershell`, `/bin/sh`
    * XSS Payloads (`<script>`, `alert()`)
    * Nmap/Sqlmap Scans
* **Anomaly Engine:** Robust Scaler (Median/IQR) statistical model trained on baseline traffic to detect zero-day volume attacks.

---

## ⚙️ Tech Stack

| Component | Technology |
| :--- | :--- |
| **Core Logic** | Python 3.10+ |
| **Packet Sniffing** | Scapy (`AsyncSniffer`) |
| **Math & Stats** | NumPy (Log-scaled Feature Extraction) |
| **Dashboard** | Streamlit (Real-time Visualization) |
| **Blocking** | `iptables` (Linux) / Simulated (Windows/Mac) |

---

## 📂 Repository Structure

```text
Intrusion-Detection-System/
├── data/                       
│   └── (Empty by default - Download PCAPs from Releases)
├── main.py                     ← Main Application (Streamlit)
├── requirements.txt            ← Dependencies
├── trusted_ips.json            ← Persistent memory for learned Safe IPs
└── .gitignore                  ← Ignores heavy PCAP files

## ⚠️ Installation & Setup

### 1. Clone the Repository

```bash
git clone [https://github.com/Adithya-Prabakaran/Intrusion-Detection-System.git](https://github.com/Adithya-Prabakaran/Intrusion-Detection-System.git)
cd Intrusion-Detection-System

```

### 2. Download Training Data (CRITICAL STEP)

The training PCAP files are **NOT** included in the source code due to GitHub file size limits.

1. Go to the **[Releases Page](https://www.google.com/search?q=../../releases)** of this repository.
2. Download the `.pcap` dataset files.
3. Create a folder named `data` inside the project directory.
4. **Move the downloaded `.pcap` files into the `data/` folder.**

### 3. Install Dependencies

```bash
pip install -r requirements.txt

```

---

## 🖥️ Usage Guide

### Start the Dashboard

**Windows:**

```bash
streamlit run main.py

```

**Mac / Linux:** (Requires root for packet sniffing)

```bash
sudo streamlit run main.py

```

### Modes of Operation

1. **Monitor Mode:** Captures live traffic to build a custom baseline `.pcap` file.
2. **Train Mode:** Reads the PCAP files from `data/` and trains the Statistical Anomaly Model (calculates Median/IQR thresholds).
3. **Active Detect:** The core IDS mode. Sniffs live traffic, applies Signature + Anomaly logic, and displays alerts in the **Triage Console**.
4. **Demo Mode:** Simulates attacks (e.g., "Simulate Exfil") to demonstrate the alert system without needing actual attack tools.

---
## 🧪 Live Attack Simulation

Test the detection engine in real-time using the following commands in a **second terminal** while the app is running in **Active Detect** mode.

| Command | Expected Alert |
| :--- | :--- |
| `curl "http://1.0.0.1/search?q=UNION+SELECT+password"` | 🔴 SQL Injection (HIGH) |
| `curl -A "sqlmap" http://1.0.0.1` | 🟡 Scanner Tool (MEDIUM) |
| `python test_exfil.py` | 🔴 Data Exfiltration (HIGH) |
| `sudo ping -f -c 200 1.0.0.1` | 🟡 ICMP Flood (MEDIUM) |

> ⚠️ **Note:** Start the app and switch to **Active Detect** mode *before* running these commands. Alerts will appear in the Triage Console within seconds.
>
> 🛑 **Danger Zone: Using `ping -f` (Flood Ping)**
> The `sudo ping -f` command is an aggressive stress-testing tool that sends packets without waiting for a reply, effectively pushing traffic as fast as your hardware allows. **Use it with caution on your local network.** > * **Self-DoS Risk:** Because it consumes maximum CPU cycles and bandwidth, you can unintentionally DoS (Denial of Service) your own machine or network.
> * **Network Instability:** Flooding your local network can instantly fill up your router's buffers, causing severe network latency, packet loss, and dropped internet connections for other devices sharing your Wi-Fi. 
> * **Safe Alternative:** If your internet connection drops while testing, remove the `-f` flag or manually slow down the interval (e.g., `ping -i 0.2 -c 200 1.0.0.1`).

## 📊 Performance & Logic

| Attack Type | Detection Method | Status |
| --- | --- | --- |
| **SQL Injection** | Signature (Regex) | ✅ Detected |
| **RCE (PowerShell)** | Signature (Regex) | ✅ Detected |
| **Data Exfiltration** | Anomaly (Volume/Rate) | ✅ Detected |
| **YouTube Streaming** | **Context Filter** | 🔇 **Ignored (Correctly)** |
| **Port Scanning** | Heuristic (Syn Count) | ✅ Detected |

---

## 🔮 Future Roadmap

* [ ] **Deep Learning:** Replace Statistical model with Autoencoders for complex pattern recognition.
* [ ] **SIEM Integration:** Forward logs to Splunk or ELK Stack.
* [ ] **Email Alerts:** Automated SMTP notifications for CRITICAL threats.

---

*Project developed by Adithya Prabakaran*

```

```
