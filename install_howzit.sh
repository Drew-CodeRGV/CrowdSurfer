#!/bin/bash
# install_howzit.sh
# Version: 1.0.22-GDriveUpload
REMOTE_URL="https://raw.githubusercontent.com/Drew-CodeRGV/CrowdSurfer/main/install_howzit.sh"
SCRIPT_VERSION="1.0.22-GDriveUpload"

# ANSI color codes for status messages
YELLOW="\033[33m"
GREEN="\033[32m"
BLUE="\033[34m"
RESET="\033[0m"

# --- ASCII Header ---
cat << "HEADER"
 _                       _ _   _ 
| |__   _____      _____(_) |_| |
| '_ \ / _ \ \ /\ / /_  / | __| |
| | | | (_) \ V  V / / /| | |_|_|
|_| |_|\___/ \_/\_/ /___|_|\__(_)
HEADER

echo -e "${GREEN}Howzit Captive Portal Installation Script v$SCRIPT_VERSION${RESET}"
echo ""

# --- Google Drive Upload Setup ---
echo "Google Drive CSV Upload Configuration:"
read -p "Enter your Google Drive Folder ID (or leave blank to use root folder): " GDRIVE_FOLDER_ID
GDRIVE_FOLDER_ID=${GDRIVE_FOLDER_ID:-root}
echo "Please place your OAuth2 client_secret.json in /etc/howzit/"

# --- Environment Setup ---
mkdir -p /etc/howzit
chmod 700 /etc/howzit

# Save folder ID
echo "$GDRIVE_FOLDER_ID" > /etc/howzit/folder_id.txt

# Install required dependencies
echo -e "${BLUE}Installing required packages and Python libraries...${RESET}"
apt-get update
apt-get install -y python3 python3-pip dnsmasq net-tools iptables postfix curl unzip realvnc-vnc-server realvnc-vnc-viewer --purge
pip3 install flask pandas matplotlib pillow adafruit-circuitpython-st7735r google-api-python-client google-auth google-auth-oauthlib google-auth-httplib2

# --- Create systemd directory ---
mkdir -p /etc/systemd/system

# --- Write the new howzit.py with Drive upload support ---
cat << 'EOF' > /usr/local/bin/howzit.py
#!/usr/bin/env python3
import os
import io
import time
import random
import threading
import smtplib
import csv
import base64
import subprocess
import re
from datetime import datetime
from flask import Flask, request, send_file, redirect, render_template_string
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication

from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload

# Set up Flask app
app = Flask(__name__)

# Globals
DEVICE_NAME = os.environ.get("DEVICE_NAME", "Howzit01")
CSV_TIMEOUT = int(os.environ.get("CSV_TIMEOUT", "300"))
REDIRECT_MODE = os.environ.get("REDIRECT_MODE", "original")
FIXED_REDIRECT_URL = os.environ.get("FIXED_REDIRECT_URL", "")
CP_INTERFACE = os.environ.get("CP_INTERFACE", "eth0")
CSV_EMAIL = os.environ.get("CSV_EMAIL", "cs@drewlentz.com")

csv_lock = threading.Lock()
current_csv_filename = None
last_submission_time = None
email_timer = None
splash_header = "Welcome to the event!"
registered_clients = {}

SCOPES = ['https://www.googleapis.com/auth/drive.file']
CREDENTIALS_PATH = "/etc/howzit/client_secret.json"
TOKEN_PATH = "/etc/howzit/token.json"
FOLDER_ID_PATH = "/etc/howzit/folder_id.txt"

# Google Drive upload
def upload_to_drive(file_path):
    creds = None
    if os.path.exists(TOKEN_PATH):
        creds = Credentials.from_authorized_user_file(TOKEN_PATH, SCOPES)
    else:
        if os.path.exists(CREDENTIALS_PATH):
            flow = InstalledAppFlow.from_client_secrets_file(CREDENTIALS_PATH, SCOPES)
            creds = flow.run_local_server(port=0)
            with open(TOKEN_PATH, 'w') as token:
                token.write(creds.to_json())
        else:
            print("No client_secret.json found.")
            return

    try:
        service = build('drive', 'v3', credentials=creds)
        file_metadata = {'name': os.path.basename(file_path)}
        if os.path.exists(FOLDER_ID_PATH):
            with open(FOLDER_ID_PATH, 'r') as f:
                folder_id = f.read().strip()
                if folder_id and folder_id != 'root':
                    file_metadata['parents'] = [folder_id]

        media = MediaFileUpload(file_path, resumable=True)
        file = service.files().create(body=file_metadata, media_body=media, fields='id').execute()
        print(f"Uploaded to Drive with file ID: {file.get('id')}")
    except Exception as e:
        print("Failed to upload to Google Drive:", e)

# CSV handling

def generate_csv_filename():
    now = datetime.now()
    rand = random.randint(1000, 9999)
    return now.strftime("%Y-%m-%d-%H") + f"-{rand}.csv"

def init_csv():
    global current_csv_filename, last_submission_time, email_timer
    current_csv_filename = generate_csv_filename()
    with open(current_csv_filename, 'w', newline='') as f:
        csv.writer(f).writerow(["First Name", "Last Name", "Birthday", "Zip Code", "Email", "MAC", "Date Registered", "Time Registered"])
    last_submission_time = time.time()

def append_to_csv(data):
    global last_submission_time, email_timer
    with csv_lock:
        with open(current_csv_filename, 'a', newline='') as f:
            csv.writer(f).writerow(data)
    last_submission_time = time.time()
    if email_timer:
        email_timer.cancel()
    email_timer = threading.Timer(CSV_TIMEOUT, lambda: upload_to_drive(current_csv_filename))
    email_timer.start()

# MAC and exemptions

def get_mac(ip):
    try:
        output = subprocess.check_output(["ip", "neigh", "show", ip]).decode("utf-8")
        match = re.search(r"lladdr\s+(([0-9a-f]{2}:){5}[0-9a-f]{2})", output, re.I)
        if match:
            return match.group(1)
    except Exception:
        pass
    return None

def add_exemption(mac):
    subprocess.call(f"iptables -t nat -I PREROUTING -i {CP_INTERFACE} -m mac --mac-source {mac} -p tcp --dport 80 -j RETURN", shell=True)
    subprocess.call(f"iptables -t nat -I PREROUTING -i {CP_INTERFACE} -m mac --mac-source {mac} -p tcp --dport 443 -j RETURN", shell=True)

def schedule_exemption_removal(mac, key, duration=600):
    def remove_rule():
        subprocess.call(f"iptables -t nat -D PREROUTING -i {CP_INTERFACE} -m mac --mac-source {mac} -p tcp --dport 80 -j RETURN", shell=True)
        subprocess.call(f"iptables -t nat -D PREROUTING -i {CP_INTERFACE} -m mac --mac-source {mac} -p tcp --dport 443 -j RETURN", shell=True)
        registered_clients.pop(key, None)
    timer = threading.Timer(duration, remove_rule)
    timer.start()

# Flask routes
@app.route('/', methods=['GET', 'POST'])
def splash():
    original_url = request.args.get('url', '')
    if request.method == 'POST':
        original_url = request.form.get('url', original_url)
        client_ip = request.remote_addr
        mac = get_mac(client_ip)
        email = request.form.get('email')
        key = f"{mac}_{email}"
        if key not in registered_clients:
            registered_clients[key] = time.time() + 600
            if mac:
                add_exemption(mac)
                schedule_exemption_removal(mac, key, duration=600)
        now = datetime.now()
        reg_date = now.strftime("%Y-%m-%d")
        reg_time = now.strftime("%H:%M:%S")
        append_to_csv([
            request.form.get('first_name'),
            request.form.get('last_name'),
            request.form.get('birthday'),
            request.form.get('zip_code'),
            email,
            mac if mac else "unknown",
            reg_date,
            reg_time
        ])
        target_url = FIXED_REDIRECT_URL if REDIRECT_MODE == "fixed" else original_url
        return f"""
        <html><body>
        <p>Thank you! Redirecting...</p>
        <script>setTimeout(function(){{window.location='{target_url}'}}, 5000);</script>
        </body></html>
        """
    return f"""
    <html><body><form method='post'>
    First Name: <input name='first_name'><br>
    Last Name: <input name='last_name'><br>
    Birthday: <input name='birthday' type='date'><br>
    Zip Code: <input name='zip_code'><br>
    Email: <input name='email'><br>
    <input type='submit' value='Register'>
    </form></body></html>
    """

@app.route('/admin', methods=['GET'])
def admin():
    return f"""
    <html><body>
    <h1>{DEVICE_NAME} Admin Panel</h1>
    <p>CSV Filename: {current_csv_filename}</p>
    <p><a href='/download_csv'>Download CSV</a></p>
    </body></html>
    """

@app.route('/download_csv')
def download_csv():
    return send_file(current_csv_filename, as_attachment=True)

if __name__ == '__main__':
    init_csv()
    app.run(host='10.69.0.1', port=80)
EOF

chmod +x /usr/local/bin/howzit.py

# --- Create systemd unit ---
cat << EOF > /etc/systemd/system/howzit.service
[Unit]
Description=Howzit Captive Portal Service
After=network.target

[Service]
Type=simple
Environment="DEVICE_NAME=Howzit01"
Environment="CSV_TIMEOUT=300"
Environment="CSV_EMAIL=cs@drewlentz.com"
Environment="REDIRECT_MODE=original"
Environment="FIXED_REDIRECT_URL="
Environment="CP_INTERFACE=eth0"
ExecStartPre=/sbin/ifconfig eth0 10.69.0.1 netmask 255.255.255.0 up
ExecStartPre=/bin/sh -c "echo 1 > /proc/sys/net/ipv4/ip_forward"
ExecStartPre=/sbin/iptables -t nat -F
ExecStartPre=/sbin/iptables -t nat -A POSTROUTING -o wlan0 -j MASQUERADE
ExecStartPre=/sbin/iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 80 -j DNAT --to-destination 10.69.0.1:80
ExecStartPre=/sbin/iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 443 -j DNAT --to-destination 10.69.0.1:80
ExecStart=/usr/bin/python3 /usr/local/bin/howzit.py
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF

# Enable and start service
systemctl daemon-reload
systemctl enable howzit.service
systemctl restart howzit.service

echo -e "${GREEN}Howzit installed and running. Visit http://10.69.0.1 to access the portal.${RESET}"
