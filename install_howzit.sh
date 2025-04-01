#!/bin/bash
# install_howzit.sh
# Version: 1.0.23-GDriveAdminUpload
REMOTE_URL="https://raw.githubusercontent.com/Drew-CodeRGV/CrowdSurfer/main/install_howzit.sh"
SCRIPT_VERSION="1.0.23-GDriveAdminUpload"

# ANSI color codes for status messages
YELLOW="\033[33m"
GREEN="\033[32m"
BLUE="\033[34m"
RESET="\033[0m"

cat << "HEADER"
 _                       _ _   _ 
| |__   _____      _____(_) |_| |
| '_ \ / _ \ \ /\ / /_  / | __| |
| | | | (_) \ V  V / / /| | |_|_|
|_| |_|\___/ \_/\_/ /___|_|\__(_)
HEADER

echo -e "${GREEN}Howzit Captive Portal Installation Script v$SCRIPT_VERSION${RESET}"
echo ""

# Setup Howzit folder
mkdir -p /etc/howzit
chmod 700 /etc/howzit

# Google Drive Folder ID setup prompt
read -p "Enter your Google Drive Folder ID (leave blank to use root folder): " GDRIVE_FOLDER_ID
GDRIVE_FOLDER_ID=${GDRIVE_FOLDER_ID:-root}
echo "$GDRIVE_FOLDER_ID" > /etc/howzit/folder_id.txt

# Install system dependencies
apt-get update
apt-get install -y python3 python3-pip dnsmasq net-tools iptables postfix curl unzip realvnc-vnc-server realvnc-vnc-viewer --purge
pip3 install flask pandas matplotlib pillow adafruit-circuitpython-st7735r google-api-python-client google-auth google-auth-oauthlib google-auth-httplib2

# Create the Python application
cat << 'EOF' > /usr/local/bin/howzit.py
#!/usr/bin/env python3
import os
import io
import time
import random
import threading
import csv
import subprocess
import re
from datetime import datetime
from flask import Flask, request, send_file, redirect, render_template_string
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload

app = Flask(__name__)

DEVICE_NAME = os.environ.get("DEVICE_NAME", "Howzit01")
CSV_TIMEOUT = int(os.environ.get("CSV_TIMEOUT", "300"))
REDIRECT_MODE = os.environ.get("REDIRECT_MODE", "original")
FIXED_REDIRECT_URL = os.environ.get("FIXED_REDIRECT_URL", "")
CP_INTERFACE = os.environ.get("CP_INTERFACE", "eth0")

csv_lock = threading.Lock()
current_csv_filename = None
email_timer = None
splash_header = "Welcome to the event!"
registered_clients = {}

SCOPES = ['https://www.googleapis.com/auth/drive.file']
CREDENTIALS_PATH = "/etc/howzit/client_secret.json"
TOKEN_PATH = "/etc/howzit/token.json"
FOLDER_ID_PATH = "/etc/howzit/folder_id.txt"

# Google Drive upload function
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
            print("client_secret.json not found.")
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

# CSV functions
def generate_csv_filename():
    now = datetime.now()
    rand = random.randint(1000, 9999)
    return now.strftime("%Y-%m-%d-%H") + f"-{rand}.csv"

def init_csv():
    global current_csv_filename, email_timer
    current_csv_filename = generate_csv_filename()
    with open(current_csv_filename, 'w', newline='') as f:
        csv.writer(f).writerow(["First Name", "Last Name", "Birthday", "Zip Code", "Email", "MAC", "Date Registered", "Time Registered"])
    email_timer = threading.Timer(CSV_TIMEOUT, lambda: upload_to_drive(current_csv_filename))
    email_timer.start()

def append_to_csv(data):
    global email_timer
    with csv_lock:
        with open(current_csv_filename, 'a', newline='') as f:
            csv.writer(f).writerow(data)
    if email_timer:
        email_timer.cancel()
    email_timer = threading.Timer(CSV_TIMEOUT, lambda: upload_to_drive(current_csv_filename))
    email_timer.start()

def get_mac(ip):
    try:
        output = subprocess.check_output(["ip", "neigh", "show", ip]).decode("utf-8")
        match = re.search(r"lladdr\s+(([0-9a-f]{2}:){5}[0-9a-f]{2})", output, re.I)
        return match.group(1) if match else None
    except Exception:
        return None

def add_exemption(mac):
    subprocess.call(f"iptables -t nat -I PREROUTING -i {CP_INTERFACE} -m mac --mac-source {mac} -p tcp --dport 80 -j RETURN", shell=True)
    subprocess.call(f"iptables -t nat -I PREROUTING -i {CP_INTERFACE} -m mac --mac-source {mac} -p tcp --dport 443 -j RETURN", shell=True)

def schedule_exemption_removal(mac, key, duration=600):
    def remove_rule():
        subprocess.call(f"iptables -t nat -D PREROUTING -i {CP_INTERFACE} -m mac --mac-source {mac} -p tcp --dport 80 -j RETURN", shell=True)
        subprocess.call(f"iptables -t nat -D PREROUTING -i {CP_INTERFACE} -m mac --mac-source {mac} -p tcp --dport 443 -j RETURN", shell=True)
        registered_clients.pop(key, None)
    threading.Timer(duration, remove_rule).start()

@app.route('/', methods=['GET', 'POST'])
def splash():
    if request.method == 'POST':
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
        append_to_csv([
            request.form.get('first_name'), request.form.get('last_name'), request.form.get('birthday'),
            request.form.get('zip_code'), email, mac if mac else "unknown",
            now.strftime("%Y-%m-%d"), now.strftime("%H:%M:%S")
        ])
        return "<p>Thank you for registering. You are now online.</p>"
    return "<form method='post'>First Name: <input name='first_name'><br>Last Name: <input name='last_name'><br>Email: <input name='email'><br><input type='submit'></form>"

@app.route('/admin', methods=['GET', 'POST'])
def admin():
    msg = ""
    if request.method == 'POST':
        if 'folder_id' in request.form:
            folder_id = request.form['folder_id']
            with open(FOLDER_ID_PATH, 'w') as f:
                f.write(folder_id.strip())
            msg += "Folder ID updated. "
        if 'client_secret' in request.files:
            f = request.files['client_secret']
            f.save(CREDENTIALS_PATH)
            msg += "client_secret.json uploaded."
    return f"""
    <h1>{DEVICE_NAME} Admin Panel</h1>
    <p>{msg}</p>
    <form method='post' enctype='multipart/form-data'>
    Google Drive Folder ID: <input name='folder_id'><br>
    Upload client_secret.json: <input type='file' name='client_secret'><br>
    <input type='submit'>
    </form>
    <p><a href='/download_csv'>Download CSV</a></p>
    """

@app.route('/download_csv')
def download_csv():
    return send_file(current_csv_filename, as_attachment=True)

if __name__ == '__main__':
    init_csv()
    app.run(host='10.69.0.1', port=80)
EOF

chmod +x /usr/local/bin/howzit.py

# Systemd service
cat << EOF > /etc/systemd/system/howzit.service
[Unit]
Description=Howzit Captive Portal
After=network.target

[Service]
Type=simple
Environment="DEVICE_NAME=Howzit01"
Environment="CSV_TIMEOUT=300"
Environment="CP_INTERFACE=eth0"
Environment="REDIRECT_MODE=original"
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

systemctl daemon-reload
systemctl enable howzit.service
systemctl restart howzit.service

echo -e "${GREEN}Howzit is now installed and running with Google Drive upload support via /admin.${RESET}"
