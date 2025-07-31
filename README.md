# 🔐 Intrusion Detection System (IDS) – Internship Project

This is a lightweight, rule-based Intrusion Detection System (IDS) developed using Python during my internship at Fachhochschule Innovation Technology Park (FITP), KP. It monitors network traffic and detects suspicious activity based on port scans, large packets, blacklisted IPs, and known malicious patterns.

---

## ⚙️ Features

- Packet sniffing using Scapy
- Signature-based detection (YAML rules)
- Blacklist IP detection
- Large packet alerting
- Port scan detection
- Real-time logging to `ids.log`
- Streamlit dashboard for visual alerts

---

## 🧰 Tech Stack

- **Python** – Core logic
- **Scapy** – Packet sniffing & crafting
- **Streamlit** – Web interface
- **YAML** – Signature rule format

---

## 🗂 Project Structure

| File               | Description                             |
|--------------------|-----------------------------------------|
| `main.py`          | Starts packet monitoring                |
| `app.py`           | Streamlit dashboard for alerts          |
| `large_packet.py`  | Detects oversized packets               |
| `port_scan.py`     | Detects potential port scans            |
| `signature_engine.py` | Signature-based packet matching     |
| `suspicious_ip.py` | Flags suspicious source IPs             |
| `blacklist.txt`    | Contains blacklisted IP addresses       |
| `.yaml`            | Contains detection rules                |
| `ids.log`          | Logs triggered alerts                   |

---

## 🚀 How to Run

1. Install dependencies:
   ```bash
   pip install scapy streamlit pyyaml
sudo python main.py
streamlit run app.py
