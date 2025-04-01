#!/bin/bash
# install_howzit.sh
# Version: 1.2.0

set -e

# ASCII Header
cat << "EOF"
 _    _  ____  _     _ _     _      
| |  | |/ __ \| |   (_) |   | |     
| |__| | |  | | |__  _| |__ | | ___ 
|  __  | |  | | '_ \| | '_ \| |/ _ \
| |  | | |__| | |_) | | |_) | |  __/
|_|  |_|\____/|_.__/|_|_.__/|_|\___|
EOF

echo -e "
[32mHowzit Captive Portal Installation Script - v1.2.0[0m
"

# --- Check for updates from GitHub ---
SCRIPT_URL="https://raw.githubusercontent.com/Drew-CodeRGV/CrowdSurfer/main/install_howzit.sh"
LOCAL_VERSION="1.1.5"

check_for_update() {
  echo "Checking for updates..."
  remote_script=$(curl -fsSL "$SCRIPT_URL" || true)
  remote_version=$(echo "$remote_script" | grep '^# Version:' | awk '{print $3}')
  if [[ "$remote_version" > "$LOCAL_VERSION" ]]; then
    echo -e "\033[33mA newer version ($remote_version) is available. Updating...\033[0m"
    echo "$remote_script" > "$0"
    chmod +x "$0"
    exec "$0" "$@"
  else
    echo "Up-to-date. Proceeding with installation."
  fi
}

check_for_update "$@"

# --- Rollback if previously installed ---
if systemctl is-active --quiet howzit.service; then
  echo -e "\n\033[33mExisting Howzit installation found. Rolling back...\033[0m"
  systemctl stop howzit.service || true
  systemctl disable howzit.service || true
  rm -f /etc/systemd/system/howzit.service
  rm -f /usr/local/bin/howzit.py
  rm -rf /var/www/howzit
  sed -i '/^interface=.*$/d' /etc/dnsmasq.conf || true
  sed -i '/^dhcp-range=.*$/d' /etc/dnsmasq.conf || true
  sed -i '/^dhcp-option=.*$/d' /etc/dnsmasq.conf || true
  iptables -t nat -F
  echo -e "\033[32mRollback complete.\033[0m"
fi

# Step 1: Set default values
DEVICE_NAME="Howzit01"
CP_INTERFACE="eth0"
INTERNET_INTERFACE="wlan0"
CSV_TIMEOUT="300"
CSV_EMAIL="cs@drewlentz.com"
REDIRECT_MODE="original"
FIXED_REDIRECT_URL=""

# Step 2: Prompt for Config
read -p "Device Name [Howzit01]: " input && DEVICE_NAME=${input:-$DEVICE_NAME}
read -p "Captive Portal Interface [eth0]: " input && CP_INTERFACE=${input:-$CP_INTERFACE}
read -p "Internet Interface [wlan0]: " input && INTERNET_INTERFACE=${input:-$INTERNET_INTERFACE}
read -p "CSV Registration Timeout (seconds) [300]: " input && CSV_TIMEOUT=${input:-$CSV_TIMEOUT}
read -p "Email to send CSV [cs@drewlentz.com]: " input && CSV_EMAIL=${input:-$CSV_EMAIL}
echo "Redirect Options:\n 1) Original URL\n 2) Fixed URL\n 3) No Redirect"
read -p "Choose Redirect Mode [1]: " input
case $input in
  2)
    REDIRECT_MODE="fixed"
    read -p "Enter fixed redirect URL: " FIXED_REDIRECT_URL
    ;;
  3)
    REDIRECT_MODE="none"
    ;;
  *)
    REDIRECT_MODE="original"
    ;;
esac

# Step 3: Install required packages
apt-get update
apt-get install -y python3 python3-pip dnsmasq net-tools iptables postfix curl
pip3 install flask pandas

# Step 4: Setup directories
mkdir -p /var/www/howzit/uploads
mkdir -p /var/www/howzit/data

# Step 5: Write howzit.py
cat << 'EOF' > /usr/local/bin/howzit.py
#!/usr/bin/env python3
print("Starting Howzit Flask app...")
from flask import Flask, request, render_template_string, redirect, send_from_directory, jsonify
from datetime import datetime
from threading import Timer, Lock
import pandas as pd
import os, csv, random, string, smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication

app = Flask(__name__)
upload_folder = "/var/www/howzit/uploads"
data_folder = "/var/www/howzit/data"
os.makedirs(upload_folder, exist_ok=True)
os.makedirs(data_folder, exist_ok=True)

csv_lock = Lock()
entries = []
timer = None
csv_filename = ""
redirect_mode = os.environ.get("HOWZIT_REDIRECT_MODE", "original")
fixed_url = os.environ.get("HOWZIT_FIXED_URL", "")
timeout_secs = int(os.environ.get("HOWZIT_TIMEOUT", 300))
email_target = os.environ.get("HOWZIT_EMAIL", "cs@drewlentz.com")

# HTML pages here (unchanged)
# ... existing HTML_SPLASH, HTML_THANKYOU, HTML_CLOSE ...

@app.route("/")
def index():
    files = os.listdir(upload_folder)
    image_url = next((f"/uploads/{f}" for f in files if f.lower().endswith(('.png', '.jpg', '.jpeg', '.gif'))), None)
    return render_template_string(HTML_SPLASH, image_url=image_url)

@app.route("/uploads/<filename>")
def uploads(filename):
    return send_from_directory(upload_folder, filename)

@app.route("/admin")
def admin():
    files = [f for f in os.listdir(data_folder) if f.endswith(".csv")]
    total = len(entries)
    by_zip = {}
    by_age = {"18-24": 0, "25-40": 0, "41-55": 0, "56-65": 0, "65+": 0}
    for e in entries:
        zipc = e.get("ZIP", "00000")
        by_zip[zipc] = by_zip.get(zipc, 0) + 1
        try:
            bdate = datetime.strptime(e["DOB"], "%m/%d/%Y")
            age = (datetime.now() - bdate).days // 365
            if age < 25: by_age["18-24"] += 1
            elif age <= 40: by_age["25-40"] += 1
            elif age <= 55: by_age["41-55"] += 1
            elif age <= 65: by_age["56-65"] += 1
            else: by_age["65+"] += 1
        except: pass
    return jsonify({"registered": total, "by_zip": by_zip, "by_age": by_age, "files": files})

# ... other routes: /register, email, save_csv ...

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=80)
EOF
chmod +x /usr/local/bin/howzit.py

# Step 6: Configure network interface
ip link set $CP_INTERFACE up
ip addr add 10.69.0.1/24 dev $CP_INTERFACE || true

# Step 7: Configure dnsmasq
cat << EOF > /etc/dnsmasq.conf
interface=$CP_INTERFACE
dhcp-range=10.69.0.10,10.69.0.254,15m
dhcp-option=option:dns-server,8.8.8.8,10.69.0.1
EOF
systemctl restart dnsmasq

# Step 8: iptables forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -F
iptables -t nat -A POSTROUTING -o $INTERNET_INTERFACE -j MASQUERADE
iptables -t nat -A PREROUTING -i $CP_INTERFACE -p tcp --dport 80 -j DNAT --to-destination 10.69.0.1:80
iptables -t nat -A PREROUTING -i $CP_INTERFACE -p tcp --dport 443 -j DNAT --to-destination 10.69.0.1:80

# Step 9: Create systemd service
cat << EOF > /etc/systemd/system/howzit.service
[Unit]
Description=Howzit Captive Portal
After=network.target

[Service]
Environment=HOWZIT_REDIRECT_MODE=$REDIRECT_MODE
Environment=HOWZIT_FIXED_URL=$FIXED_REDIRECT_URL
Environment=HOWZIT_TIMEOUT=$CSV_TIMEOUT
Environment=HOWZIT_EMAIL=$CSV_EMAIL
ExecStart=/usr/bin/python3 /usr/local/bin/howzit.py
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reexec
systemctl daemon-reload
systemctl enable howzit.service
systemctl start howzit.service

clear
echo -e "\n\033[32mHowzit has been installed and started. Access the portal at http://10.69.0.1\033[0m"
