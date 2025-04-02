#!/bin/bash
# install_howzit.sh
# Version: 1.5.3

cat << "HEADER"
 _                       _ _   _ 
| |__   _____      _____(_) |_| |
| '_ \ / _ \ \ /\ / /_  / | __| |
| | | | (_) \ V  V / / /| | |_|_|
|_| |_|\___/ \_/\_/ /___|_|\__(_)
HEADER

echo -e "\n\033[32mHowzit Captive Portal Installation Script - 1.5.3\033[0m\n"

# --- Rollback Routine ---
if [ -f /usr/local/bin/howzit.py ]; then
echo -e "\033[33mExisting Howzit installation detected. Rolling back...\033[0m"
systemctl stop howzit.service 2>/dev/null
systemctl disable howzit.service 2>/dev/null
rm -f /etc/systemd/system/howzit.service /usr/local/bin/howzit.py
sed -i "\|^interface=eth0\$|d" /etc/dnsmasq.conf
sed -i "\|^dhcp-range=10\.69\.0\.10,10\.69\.0\.254,15m\$|d" /etc/dnsmasq.conf
sed -i "\|^dhcp-option=option:dns-server,8\.8\.8\.8,10\.69\.0\.1\$|d" /etc/dnsmasq.conf
systemctl restart dnsmasq
/sbin/iptables -t nat -F
echo -e "\033[32mRollback complete.\033[0m"
fi

# --- Progress Update Function ---
update_status() {
  echo "[$1/$2] $3"
}

TOTAL_STEPS=6
CURRENT_STEP=1

# --- Check for Script Updates ---
REMOTE_URL="https://raw.githubusercontent.com/Drew-CodeRGV/CrowdSurfer/main/install_howzit.sh"
SCRIPT_VERSION="1.5.3"
check_for_update() {
  if ! command -v curl >/dev/null 2>&1; then
    apt-get update && apt-get install -y curl
  fi
  REMOTE_SCRIPT=$(curl -fsSL "$REMOTE_URL")
  REMOTE_VERSION=$(echo "$REMOTE_SCRIPT" | grep '^SCRIPT_VERSION=' | head -n 1 | cut -d'=' -f2 | tr -d '"')
  if [ -n "$REMOTE_VERSION" ] && [ "$REMOTE_VERSION" != "$SCRIPT_VERSION" ]; then
    echo "New version available: $REMOTE_VERSION (current: $SCRIPT_VERSION)"
    read -p "Do you want to download and install the new version automatically? (y/n) [y]: " update_choice
    update_choice=${update_choice:-y}
    if [ "$update_choice" = "y" ] || [ "$update_choice" = "Y" ]; then
      NEW_SCRIPT="/tmp/install_howzit.sh.new"
      curl -fsSL "$REMOTE_URL" -o "$NEW_SCRIPT"
      if [ $? -eq 0 ]; then
         chmod +x "$NEW_SCRIPT"
         echo "New version downloaded. Restarting script..."
         mv "$NEW_SCRIPT" "$0"
         exec "$0" "$@"
      else
         echo "Failed to download new version. Continuing with current install."
      fi
    else
      echo "Continuing with current install."
    fi
  fi
}
check_for_update

# --- Interactive Configuration ---
echo "Configuration Setup:"
read -p "Enter Device Name [Howzit01]: " DEVICE_NAME
DEVICE_NAME=${DEVICE_NAME:-Howzit01}
read -p "Enter Captive Portal Interface [eth0]: " CP_INTERFACE
CP_INTERFACE=${CP_INTERFACE:-eth0}
read -p "Enter Internet Interface [wlan0]: " INTERNET_INTERFACE
INTERNET_INTERFACE=${INTERNET_INTERFACE:-wlan0}
read -p "Enter CSV Registration Timeout in seconds [300]: " CSV_TIMEOUT
CSV_TIMEOUT=${CSV_TIMEOUT:-300}
read -p "Enter Email Address to send CSV to [cs@drewlentz.com]: " CSV_EMAIL
CSV_EMAIL=${CSV_EMAIL:-cs@drewlentz.com}
echo "Select Redirect Mode:"
echo "  1) Original requested URL"
echo "  2) Fixed URL"
echo "  3) No redirect"
read -p "Enter option number [1]: " REDIRECT_CHOICE
if [[ -z "$REDIRECT_CHOICE" || "$REDIRECT_CHOICE" == "1" ]]; then
  REDIRECT_MODE="original"
  FIXED_REDIRECT_URL=""
elif [ "$REDIRECT_CHOICE" == "2" ]; then
  REDIRECT_MODE="fixed"
  read -p "Enter fixed URL: " FIXED_REDIRECT_URL
else
  REDIRECT_MODE="none"
  FIXED_REDIRECT_URL=""
fi

echo ""
echo "Configuration Summary:"
echo "  Device Name:              $DEVICE_NAME"
echo "  Captive Portal Interface: $CP_INTERFACE"
echo "  Internet Interface:       $INTERNET_INTERFACE"
echo "  CSV Timeout:              $CSV_TIMEOUT sec"
echo "  CSV Email:                $CSV_EMAIL"
echo "  Redirect Mode:            $REDIRECT_MODE"
[ "$REDIRECT_MODE" == "fixed" ] && echo "  Fixed URL:                $FIXED_REDIRECT_URL"
echo ""

update_status $CURRENT_STEP $TOTAL_STEPS "Configuration complete."
sleep 0.5
CURRENT_STEP=$((CURRENT_STEP+1))

# --- Set System Hostname ---
NEW_HOSTNAME="${DEVICE_NAME}.cswifi.com"
echo "Setting hostname to ${NEW_HOSTNAME}"
hostnamectl set-hostname "${NEW_HOSTNAME}"

# --- Update Package Lists & Install Required Packages ---
echo "Updating package lists..."
apt-get update
echo "Installing required packages..."
REQUIRED_PACKAGES=("python3" "python3-flask" "python3-pandas" "python3-matplotlib" "dnsmasq" "net-tools" "iptables")
for pkg in "${REQUIRED_PACKAGES[@]}"; do
  if ! dpkg -s "$pkg" >/dev/null 2>&1; then
    apt-get install -y "$pkg"
  fi
done
update_status $CURRENT_STEP $TOTAL_STEPS "Packages installed."
sleep 0.5
CURRENT_STEP=$((CURRENT_STEP+1))

# --- Configure dnsmasq for DHCP ---
echo "Configuring dnsmasq for interface ${CP_INTERFACE}..."
sed -i '/^dhcp-range=/d' /etc/dnsmasq.conf
sed -i '/^interface=/d' /etc/dnsmasq.conf
echo "interface=${CP_INTERFACE}" >> /etc/dnsmasq.conf
echo "dhcp-range=10.69.0.10,10.69.0.254,15m" >> /etc/dnsmasq.conf
echo "dhcp-option=option:dns-server,8.8.8.8,10.69.0.1" >> /etc/dnsmasq.conf
systemctl restart dnsmasq
update_status $CURRENT_STEP $TOTAL_STEPS "dnsmasq configured."
sleep 0.5
CURRENT_STEP=$((CURRENT_STEP+1))

# --- Write the Captive Portal Python Application ---
cat << 'EOF' > /usr/local/bin/howzit.py
#!/usr/bin/env python3
import os
os.environ['MPLCONFIGDIR'] = '/tmp/matplotlib'
import time, random, threading, smtplib, csv, subprocess, re
from datetime import datetime
from flask import Flask, request, send_file, redirect
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
import matplotlib
matplotlib.use('Agg')
import pandas as pd

DEVICE_NAME = os.environ.get("DEVICE_NAME", "Howzit01")
CSV_TIMEOUT = int(os.environ.get("CSV_TIMEOUT", "300"))
REDIRECT_MODE = os.environ.get("REDIRECT_MODE", "original")
FIXED_REDIRECT_URL = os.environ.get("FIXED_REDIRECT_URL", "")
CP_INTERFACE = os.environ.get("CP_INTERFACE", "eth0")
CSV_EMAIL = os.environ.get("CSV_EMAIL", "cs@drewlentz.com")

app = Flask(DEVICE_NAME)
csv_lock = threading.Lock()
current_csv_filename = None
last_submission_time = None
email_timer = None
splash_header = "Welcome to the event!"

registered_clients = {}

def get_mac(ip):
  try:
    output = subprocess.check_output(["ip", "neigh", "show", ip]).decode("utf-8")
    match = re.search(r"lladdr\s+(([0-9a-f]{2}:){5}[0-9a-f]{2})", output, re.I)
    if match:
      return match.group(1)
  except Exception:
    pass
  try:
    output = subprocess.check_output(["arp", "-n", ip]).decode("utf-8")
    match = re.search(r"(([0-9a-f]{2}:){5}[0-9a-f]{2})", output, re.I)
    if match:
      return match.group(0)
  except Exception:
    return None
  return None

def add_exemption(mac):
  subprocess.call(f"/sbin/iptables -t nat -I PREROUTING -i {CP_INTERFACE} -m mac --mac-source {mac} -p tcp --dport 80 -j RETURN", shell=True)
  subprocess.call(f"/sbin/iptables -t nat -I PREROUTING -i {CP_INTERFACE} -m mac --mac-source {mac} -p tcp --dport 443 -j RETURN", shell=True)
