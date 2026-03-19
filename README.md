# Automated Network Vulnerability Scanner 🛡️

## Overview
This is a robust Bash script designed to automate the reconnaissance phase of penetration testing. It leverages **Nmap** and **NSE scripts** to discover live hosts, identify open ports, detect operating systems, and find potential vulnerabilities.

## 🛠️ Features
- **Automated Discovery:** Pings the target range to find live devices.
- **Intelligent Scanning:** Uses aggressive OS detection and version tracing.
- **Vulnerability Mapping:** Runs NSE scripts to fetch CVEs and known exploits.
- **Reporting:** Generates a color-coded HTML report for easy analysis.

## 💻 How to Use
1. Download the script:
   ```bash
   wget https://raw.githubusercontent.com/has5eeb/Automated-Network-Scanner/main/robustscan.sh
