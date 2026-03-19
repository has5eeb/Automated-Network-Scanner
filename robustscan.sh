#!/bin/bash

# ============================================================
# ROBUST VULNERABILITY SCANNER (Better Detection)
# ============================================================

TARGET="150.1.7.0/24"
REPORT_FILE="robust_report.html"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

# Check for root
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}[!] Please run as root (sudo ./robustscan.sh)${NC}"
  exit
fi

echo -e "${BLUE}[*] Initializing Robust Scanner...${NC}"

# 1. SETUP HTML
cat <<EOF > $REPORT_FILE
<!DOCTYPE html>
<html>
<head>
<title>Robust Scan Report - $TARGET</title>
<style>
    body { font-family: 'Segoe UI', sans-serif; background-color: #1e1e1e; color: #e0e0e0; padding: 20px; }
    h1 { color: #00adb5; border-bottom: 2px solid #00adb5; }
    table { width: 100%; border-collapse: collapse; margin-top: 20px; background-color: #252a34; }
    th, td { padding: 12px 15px; text-align: left; border-bottom: 1px solid #393e46; vertical-align: top;}
    th { background-color: #00adb5; color: white; }
    tr:nth-child(even) { background-color: #2c313c; }
    .cve-box { font-size: 0.85em; color: #ff6b6b; font-family: monospace; }
    .port-box { font-family: monospace; color: #98c379; }
</style>
</head>
<body>
<h1>Network Scan Results</h1>
<table>
    <thead>
        <tr>
            <th width="15%">IP Address</th>
            <th width="20%">OS Guess</th>
            <th width="25%">Open Ports</th>
            <th width="40%">Vulnerabilities</th>
        </tr>
    </thead>
    <tbody>
EOF

# 2. DISCOVERY (Using -PE to force ICMP echo)
echo -e "${GREEN}[+] Finding live hosts...${NC}"
LIVE_HOSTS=$(nmap -sn -PE $TARGET | grep "Nmap scan report for" | cut -d " " -f 5)

if [ -z "$LIVE_HOSTS" ]; then
    echo -e "${RED}[!] No hosts found. Are you on the VPN/Network?${NC}"
    exit 1
fi

# 3. SCANNING LOOP
for IP in $LIVE_HOSTS; do
    echo -e "${BLUE}[+] Scanning $IP... (Please wait)${NC}"
    
    # SCAN COMMAND EXPLANATION:
    # -sS: SYN Scan (Stealthier)
    # -p 1-3000: Checks top 3000 ports (More than default 1000)
    # --osscan-guess: Forces Nmap to guess the OS even if not 100% sure
    # --open: Only creates output if ports are actually open
    # -sV: Version detection
    
    nmap -sS -sV -O --osscan-guess --script vuln -p 1-3000 -T4 --open $IP > "temp_nmap_$IP.txt"
    
    # --- INTELLIGENT OS PARSING ---
    # 1. Try exact match
    OS_INFO=$(grep "OS details:" "temp_nmap_$IP.txt" | cut -d ":" -f 2 | head -n 1)
    
    # 2. If empty, try "Aggressive Guess" (fuzzy match)
    if [ -z "$OS_INFO" ]; then
        OS_INFO=$(grep "Aggressive OS guesses:" "temp_nmap_$IP.txt" | cut -d ":" -f 2 | head -n 1)
    fi
    
    # 3. If still empty, check if ports were even found
    if [ -z "$OS_INFO" ]; then
        if grep -q "No exact OS matches" "temp_nmap_$IP.txt"; then
             OS_INFO="Fingerprint failed (Firewall enabled?)"
        else
             OS_INFO="Unknown / Scan Blocked"
        fi
    fi

    # --- PORT PARSING ---
    PORTS=$(grep "^[0-9]" "temp_nmap_$IP.txt" | awk '{print $1 " " $3}' | sed 's/$/<br>/')
    if [ -z "$PORTS" ]; then
        PORTS="<span style='color:#777'>No open ports found (Host likely up but firewalled)</span>"
    fi

    # --- VULN PARSING ---
    # Clean up the output to remove technical junk
    VULNS=$(grep "|_" "temp_nmap_$IP.txt" | sed 's/|_//g' | sed 's/^/<br>• /')
    if [ -z "$VULNS" ]; then
        VULNS="<span style='color:#777'>No specific vulnerabilities detected</span>"
    fi

    # WRITE TO HTML
    echo "<tr>
            <td><strong>$IP</strong></td>
            <td>$OS_INFO</td>
            <td class='port-box'>$PORTS</td>
            <td class='cve-box'>$VULNS</td>
          </tr>" >> $REPORT_FILE

    # CLEANUP
    rm "temp_nmap_$IP.txt"
done

# 4. FINISH
echo "</tbody></table><p>Scan completed at $(date)</p></body></html>" >> $REPORT_FILE
echo -e "${GREEN}[V] Success! Report saved to: $REPORT_FILE${NC}"
