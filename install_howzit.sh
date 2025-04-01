#!/bin/bash
# install_howzit.sh
# Version: 1.3.0

set -e

# ASCII Header
cat << "EOF"

██   ██  ██████  ██     ██ ███████ ██ ████████ 
██   ██ ██    ██ ██     ██    ███  ██    ██    
███████ ██    ██ ██  █  ██   ███   ██    ██    
██   ██ ██    ██ ██ ███ ██  ███    ██    ██    
██   ██  ██████   ███ ███  ███████ ██    ██    
                                               
                                       
EOF

echo -e "\n\033[32mHowzit Captive Portal Installation Script - v1.3.0\033[0m\n"

# --- Check for updates from GitHub ---
SCRIPT_URL="https://raw.githubusercontent.com/Drew-CodeRGV/CrowdSurfer/main/install_howzit.sh"
LOCAL_VERSION="1.3.0"

check_for_update() {
  echo "Checking for updates..."
  remote_script=$(curl -fsSL "$SCRIPT_URL" || echo "")
  remote_version=$(echo "$remote_script" | grep '^# Version:' | awk '{print $3}')

  if [[ -z "$remote_version" ]]; then
    echo "⚠️  Could not determine remote version. Skipping auto-update."
    return
  fi

  echo "Remote version: $remote_version | Local version: $LOCAL_VERSION"

  if [[ "$remote_version" > "$LOCAL_VERSION" ]]; then
    echo -e "[33mA newer version ($remote_version) is available.[0m"
    echo "1) Update to newer version ($remote_version)"
    echo "2) Keep current version ($LOCAL_VERSION)"
    read -p "Choose an option [1]: " choice
    choice=${choice:-1}
    if [[ "$choice" == "1" ]]; then
      echo "Downloading and launching updated version..."
      echo "$remote_script" > "$0"
      chmod +x "$0"
      exec "$0" "$@"
    fi
  else
    echo "Up-to-date. Proceeding with installation."
  fi
}
  else
    echo -e"Up-to-date. Proceeding with installation."
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
echo -e "Redirect Options:
 1) Original URL
 2) Fixed URL
 3) No Redirect"
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
python3 -m venv /opt/howzit-env
source /opt/howzit-env/bin/activate
pip install flask pandas

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

HTML_SPLASH = '''
<html><body><h1>Welcome to the event!</h1>
<form method="POST" action="/register">
  First Name: <input name="first"><br>
  Last Name: <input name="last"><br>
  Birthday: <input name="dob"><br>
  ZIP: <input name="zip"><br>
  Email: <input name="email"><br>
  <input type="submit" value="Register">
</form></body></html>'''

HTML_THANKYOU = '''
<html><body><h1>Thank you for registering!</h1>
<p>You will be redirected shortly...</p>
<script>
setTimeout(function() {
  window.location.href = "{{ redirect_url }}";
}, 10000);
</script></body></html>'''

HTML_CLOSE = '''
<html><body><p>Ok, good luck!</p>
<script>setTimeout(()=>{window.close()},2000)</script>
</body></html>'''

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

def send_csv_email(filepath):
    msg = MIMEMultipart()
    msg['From'] = "howzit@localhost"
    msg['To'] = email_target
    msg['Subject'] = "Howzit CSV Registration Data"
    msg.attach(MIMEText("Attached is the latest registration export.", 'plain'))
    with open(filepath, "rb") as f:
        part = MIMEApplication(f.read(), Name=os.path.basename(filepath))
        part['Content-Disposition'] = f'attachment; filename="{os.path.basename(filepath)}"'
        msg.attach(part)
    try:
        s = smtplib.SMTP('localhost')
        s.send_message(msg)
        s.quit()
        print(f"[Howzit] Sent email with {filepath} to {email_target}")
    except Exception as e:
        print(f"[Howzit] Email failed: {e}")

def save_csv():
    global csv_filename, entries
    timestamp = datetime.now().strftime("%Y-%m-%d-%H%M")
    rand = ''.join(random.choices(string.digits, k=4))
    csv_filename = f"{timestamp}-{rand}.csv"
    path = os.path.join(data_folder, csv_filename)
    with open(path, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=["First", "Last", "DOB", "ZIP", "Email", "MAC", "Date", "Time"])
        writer.writeheader()
        writer.writerows(entries)
    entries = []
    print(f"[Howzit] Saved CSV: {csv_filename}")
    send_csv_email(path)

@app.route("/register", methods=["POST"])
def register():
    global entries, timer
    info = request.form.to_dict()
    info["MAC"] = request.remote_addr
    now = datetime.now()
    info["Date"] = now.strftime("%Y-%m-%d")
    info["Time"] = now.strftime("%H:%M:%S")
    with csv_lock:
        entries.append(info)
        if timer:
            timer.cancel()
        timer = Timer(timeout_secs, save_csv)
        timer.start()

    if redirect_mode == "fixed":
        return render_template_string(HTML_THANKYOU, redirect_url=fixed_url)
    elif redirect_mode == "none":
        return render_template_string(HTML_CLOSE)
    else:
        return render_template_string(HTML_THANKYOU, redirect_url="http://example.com")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=80)
EOF

chmod +x /usr/local/bin/howzit.py

# Step 6: Configure network interface
ip link set $CP_INTERFACE up
ip addr flush dev $CP_INTERFACE
ip addr add 10.69.0.1/24 dev $CP_INTERFACE

# Step 7: Configure dnsmasq
cat << EOF > /etc/dnsmasq.conf
interface=$CP_INTERFACE
dhcp-range=10.69.0.10,10.69.0.254,15m
dhcp-option=option:dns-server,8.8.8.8,10.69.0.1
EOF
systemctl restart dnsmasq

# Step 8: iptables forwarding
echo -e1 > /proc/sys/net/ipv4/ip_forward
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
ExecStartPre=/bin/bash -c '
echo -e"[Howzit] Waiting for $CP_INTERFACE to come up and get IP 10.69.0.1..."
while true; do
  if ip addr show $CP_INTERFACE | grep -q "inet 10.69.0.1"; then
    echo -e"[Howzit] $CP_INTERFACE is up and has 10.69.0.1. Proceeding."
    break
  fi
  echo -e"[Howzit] $CP_INTERFACE not ready. Retrying in 5 seconds..."
  ip link set $CP_INTERFACE up
  ip addr flush dev $CP_INTERFACE
  ip addr add 10.69.0.1/24 dev $CP_INTERFACE
  sleep 5
done'
ExecStart=/opt/howzit-env/bin/python /usr/local/bin/howzit.py
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
echo -e "\n\033[32m🎉 Congratulations! Howzit has been installed and started.\033[0m"
echo -e "Access the captive portal at: \033[1mhttp://10.69.0.1\033[0m"
