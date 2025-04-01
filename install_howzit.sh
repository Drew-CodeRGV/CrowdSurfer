#!/bin/bash
# install_howzit.sh
# Version: 1.1.4

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

echo -e "\n\033[32mHowzit Captive Portal Installation Script - v1.1.4\033[0m\n"

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
from flask import Flask, request, render_template_string, redirect, send_from_directory
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
<html><head><title>Howzit Portal</title>
<style>
body { font-family: sans-serif; background: #f0f2f5; text-align: center; margin-top: 40px; }
form { background: white; padding: 20px; margin: auto; border-radius: 12px; width: 300px; box-shadow: 0 0 8px rgba(0,0,0,0.1); }
input { width: 90%; padding: 10px; margin: 8px 0; border-radius: 6px; border: 1px solid #ccc; }
button { background: #007aff; color: white; border: none; padding: 10px 20px; border-radius: 6px; cursor: pointer; }
</style></head><body>
<h1>Welcome to the event!</h1>
<form action="/register" method="post">
<input name="first" placeholder="First Name" required><br>
<input name="last" placeholder="Last Name" required><br>
<input name="dob" placeholder="Birthday (MM/DD/YYYY)" required><br>
<input name="zip" placeholder="ZIP Code" required><br>
<input name="email" placeholder="Email Address" required><br>
<button type="submit">Register</button>
</form></body></html>'''

HTML_THANKYOU = '''
<html><head><title>Registered</title><style>body { text-align: center; font-family: sans-serif; margin-top: 60px; }</style></head>
<body><h2>Thank you for registering!</h2>
<p>You’ll be redirected in <span id="countdown">10</span> seconds...</p>
<script>
var seconds = 10;
var countdown = document.getElementById("countdown");
setInterval(function() {
  seconds--; countdown.textContent = seconds;
  if (seconds === 0) { window.location.href = "{{ redirect_url }}"; }
}, 1000);
</script>
</body></html>'''

HTML_CLOSE = '''
<html><head><title>Complete</title></head><body style="text-align:center;font-family:sans-serif;margin-top:60px;">
<p>Ok, good luck!</p><script>setTimeout(()=>{window.close()},2000)</script></body></html>'''

@app.route("/")
def index():
    return render_template_string(HTML_SPLASH)

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
