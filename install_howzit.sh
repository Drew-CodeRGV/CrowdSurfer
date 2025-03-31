#!/bin/bash
# install_howzit.sh
# SCRIPT_VERSION must be updated on each new release.
SCRIPT_VERSION="1.0.12"
REMOTE_URL="https://raw.githubusercontent.com/Drew-CodeRGV/CrowdSurfer/main/install_howzit.sh"

# ANSI color codes for the status bar:
YELLOW="\033[33m"
GREEN="\033[32m"
BLUE="\033[34m"
RESET="\033[0m"

# --- Function: Check for script update from GitHub ---
check_for_update() {
    if ! command -v curl >/dev/null 2>&1; then
        echo -e "${YELLOW}curl not found. Installing curl...${RESET}"
        apt-get update && apt-get install -y curl
    fi
    echo -e "${BLUE}Checking for script updates...${RESET}"
    REMOTE_SCRIPT=$(curl -fsSL "$REMOTE_URL")
    if [ $? -ne 0 ] || [ -z "$REMOTE_SCRIPT" ]; then
        echo -e "${YELLOW}Unable to retrieve remote script. Skipping update check.${RESET}"
        return
    fi
    REMOTE_VERSION=$(echo "$REMOTE_SCRIPT" | grep '^SCRIPT_VERSION=' | head -n 1 | cut -d'=' -f2 | tr -d '"')
    if [ -z "$REMOTE_VERSION" ]; then
        echo -e "${YELLOW}Unable to determine remote version. Skipping update.${RESET}"
        return
    fi
    if [ "$REMOTE_VERSION" != "$SCRIPT_VERSION" ]; then
        echo -e "${YELLOW}New version available ($REMOTE_VERSION). Updating...${RESET}"
        NEW_SCRIPT="/tmp/install_howzit.sh.new"
        curl -fsSL "$REMOTE_URL" -o "$NEW_SCRIPT"
        if [ $? -eq 0 ]; then
            chmod +x "$NEW_SCRIPT"
            echo -e "${YELLOW}Update downloaded. Replacing current script and restarting...${RESET}"
            mv "$NEW_SCRIPT" "$0"
            exec "$0" "$@"
        else
            echo -e "${YELLOW}Failed to download the new version. Continuing with current version.${RESET}"
        fi
    else
        echo -e "${GREEN}Script is up-to-date (version $SCRIPT_VERSION).${RESET}"
    fi
}

check_for_update

# --- Main Installation Script ---
# This script installs and configures the Howzit Captive Portal Service on a fresh Raspberry Pi.
# It uses the 10.69.0.0/24 subnet:
#   - Sets CP_INTERFACE (default eth0) with static IP 10.69.0.1/24.
#   - Configures dnsmasq with a DHCP pool from 10.69.0.10 to 10.69.0.254 with a 15m lease.
#   - Adds iptables rules (using DNAT) so that any HTTP traffic on CP_INTERFACE is forced to 10.69.0.1:80.
#   - Writes a Python/Flask captive portal (with admin page at /admin) whose CSV timer starts only on the first registration.
#   - Optionally supports a 1.5" OLED for status output.
#   - Creates a systemd service to autostart the captive portal.
#
# Note: The captive portal now intercepts all HTTP requests on eth0 by using a DNAT rule.

if [ "$EUID" -ne 0 ]; then 
    echo -e "${YELLOW}Please run as root.${RESET}"
    exit 1
fi

# --- Ask if OLED display is to be used ---
read -p "Use OLED display to show status? [Y/n]: " USE_OLED_CHOICE
if [[ -z "$USE_OLED_CHOICE" || "$USE_OLED_CHOICE" =~ ^[Yy] ]]; then
    USE_OLED_PY="True"
else
    USE_OLED_PY="False"
fi

# --- Function: Persistent Colored Status Bar ---
update_status() {
    local step=$1
    local total=$2
    local message=$3
    echo -ne "\033[s\033[999;0H"
    printf "${YELLOW}[%d/%d] ${GREEN}%s${RESET}\033[K\n" "$step" "$total" "$message"
    echo -ne "\033[u"
}

TOTAL_STEPS=8
CURRENT_STEP=1
clear

# --- Display ASCII Art Header ---
cat << "EOF"
 _                       _ _   _ 
| |__   _____      _____(_) |_| |
| '_ \ / _ \ \ /\ / /_  / | __| |
| | | | (_) \ V  V / / /| | |_|_|
|_| |_|\___/ \_/\_/ /___|_|\__(_)
EOF

echo ""
echo -e "${GREEN}Welcome to the Howzit Captive Portal Setup Wizard!${RESET}"
echo ""
update_status $CURRENT_STEP $TOTAL_STEPS "Step 1: Header displayed."
sleep 0.5
CURRENT_STEP=$((CURRENT_STEP+1))

# --- Interactive Configuration ---
echo "Configuration Setup:"
read -p "Enter Device Name [Howzit01]: " DEVICE_NAME
DEVICE_NAME=${DEVICE_NAME:-Howzit01}
read -p "Enter Captive Portal Interface [eth0]: " CP_INTERFACE
CP_INTERFACE=${CP_INTERFACE:-eth0}
read -p "Enter Internet Interface [eth1]: " INTERNET_INTERFACE
INTERNET_INTERFACE=${INTERNET_INTERFACE:-eth1}
read -p "Enter CSV Registration Timeout in seconds [300]: " CSV_TIMEOUT
CSV_TIMEOUT=${CSV_TIMEOUT:-300}
read -p "Enter Email Address to send CSV to [cs@drewlentz.com]: " CSV_EMAIL
CSV_EMAIL=${CSV_EMAIL:-cs@drewlentz.com}

echo ""
echo "Configuration Summary:"
echo "  Device Name:              $DEVICE_NAME"
echo "  Captive Portal Interface: $CP_INTERFACE"
echo "  Internet Interface:       $INTERNET_INTERFACE"
echo "  CSV Timeout (sec):        $CSV_TIMEOUT"
echo "  CSV Email:                $CSV_EMAIL"
echo "  Use OLED Display:         $USE_OLED_PY"
echo ""
update_status $CURRENT_STEP $TOTAL_STEPS "Step 2: Configuration complete."
sleep 0.5
CURRENT_STEP=$((CURRENT_STEP+1))

# --- Update System & Remove VNC Packages ---
echo "Updating package lists..."
apt-get update
echo "Removing RealVNC packages (not needed)..."
apt-get purge -y realvnc-vnc-server realvnc-vnc-viewer
apt-get autoremove -y
echo "Upgrading packages..."
apt-get -y upgrade
update_status $CURRENT_STEP $TOTAL_STEPS "Step 3: System updated and VNC removed."
sleep 0.5
CURRENT_STEP=$((CURRENT_STEP+1))

# --- Dependency Check & Installation ---
echo "Verifying and installing required packages..."
REQUIRED_PACKAGES=("python3" "python3-flask" "python3-pandas" "python3-matplotlib" "dnsmasq" "net-tools" "iptables" "postfix")
for pkg in "${REQUIRED_PACKAGES[@]}"; do
    if dpkg -s "$pkg" &>/dev/null; then
        echo "$pkg is installed; checking for updates..."
        apt-get install --only-upgrade -y "$pkg"
    else
        echo "$pkg is missing; installing..."
        apt-get install -y "$pkg"
    fi
done
if [ "$USE_OLED_PY" = "True" ]; then
    apt-get install -y python3-pip
    pip3 install luma.oled pillow
fi
update_status $CURRENT_STEP $TOTAL_STEPS "Step 4: Dependencies verified."
sleep 0.5
CURRENT_STEP=$((CURRENT_STEP+1))

# --- Configure dnsmasq for DHCP on CP_INTERFACE ---
echo "Configuring dnsmasq for DHCP on interface ${CP_INTERFACE}..."
# Remove any conflicting lines.
sed -i '/^dhcp-range=/d' /etc/dnsmasq.conf
sed -i '/^interface=/d' /etc/dnsmasq.conf
# For a /24 network, set DHCP pool from 10.69.0.10 to 10.69.0.254 with a 15m lease.
echo "interface=${CP_INTERFACE}" >> /etc/dnsmasq.conf
echo "dhcp-range=10.69.0.10,10.69.0.254,15m" >> /etc/dnsmasq.conf
echo "dhcp-option=option:dns-server,8.8.8.8,10.69.0.1" >> /etc/dnsmasq.conf
systemctl restart dnsmasq
update_status $CURRENT_STEP $TOTAL_STEPS "Step 5: dnsmasq configured (Pool: 10.69.0.10-10.69.0.254, Lease: 15m)."
sleep 0.5
CURRENT_STEP=$((CURRENT_STEP+1))

# --- Write the Captive Portal Python Application ---
# Unquoted heredoc for variable expansion.
cat << EOF > /usr/local/bin/howzit.py
#!/usr/bin/env python3
import os
os.environ['MPLCONFIGDIR'] = '/tmp/matplotlib'
import time, random, threading, smtplib, csv, io, base64
from datetime import datetime, date
from flask import Flask, request, send_file
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import pandas as pd

# Global configuration
DEVICE_NAME = "${DEVICE_NAME}"
CSV_TIMEOUT = ${CSV_TIMEOUT}

# Use OLED display if enabled.
USE_OLED = "${USE_OLED_PY}" == "True"

app = Flask(DEVICE_NAME)

csv_lock = threading.Lock()
current_csv_filename = None
last_submission_time = None
email_timer = None
splash_header = "Welcome to the event!"

def generate_csv_filename():
    now = datetime.now()
    rand = random.randint(1000, 9999)
    return now.strftime("%Y-%m-%d-%H") + f"-{rand}.csv"

def init_csv():
    global current_csv_filename, last_submission_time, email_timer
    current_csv_filename = generate_csv_filename()
    with open(current_csv_filename, 'w', newline='') as f:
        csv.writer(f).writerow(["First Name", "Last Name", "Birthday", "Zip Code", "Email", "Gender"])
    last_submission_time = time.time()
    # Do not start the timer until the first registration is received.

def append_to_csv(data):
    global last_submission_time, email_timer
    with csv_lock:
        with open(current_csv_filename, 'a', newline='') as f:
            csv.writer(f).writerow(data)
    last_submission_time = time.time()
    if email_timer:
        email_timer.cancel()
    email_timer = threading.Timer(CSV_TIMEOUT, send_csv_via_email)
    email_timer.start()

def send_csv_via_email():
    global current_csv_filename
    with csv_lock, open(current_csv_filename, 'rb') as f:
        content = f.read()
    msg = MIMEMultipart()
    msg['Subject'] = "Howzit CSV Submission"
    msg['From'] = "no-reply@example.com"
    msg['To'] = "${CSV_EMAIL}"
    msg.attach(MIMEText("Attached is the CSV file for the session."))
    part = MIMEApplication(content, Name=current_csv_filename)
    part['Content-Disposition'] = f'attachment; filename="{current_csv_filename}"'
    msg.attach(part)
    try:
        s = smtplib.SMTP('localhost')
        s.send_message(msg)
        s.quit()
        print(f"Email sent for {current_csv_filename}")
    except Exception as e:
        print("Error sending email:", e)
    init_csv()

@app.route('/', methods=['GET', 'POST'])
def splash():
    global splash_header
    if request.method == 'POST':
        append_to_csv([request.form.get('first_name'),
                       request.form.get('last_name'),
                       request.form.get('birthday'),
                       request.form.get('zip_code'),
                       request.form.get('email'),
                       request.form.get('gender')])
        return "Thank you for registering!"
    return f"""
    <html>
      <head><title>{splash_header}</title></head>
      <body>
        <h1>{splash_header}</h1>
        <form method="post">
          First Name: <input type="text" name="first_name" required><br>
          Last Name: <input type="text" name="last_name" required><br>
          Birthday (YYYY-MM-DD): <input type="date" name="birthday" required><br>
          Zip Code: <input type="text" name="zip_code" required><br>
          Email: <input type="email" name="email" required><br>
          Gender: <select name="gender">
                    <option value="Male">Male</option>
                    <option value="Female">Female</option>
                    <option value="Other">Other</option>
                    <option value="Prefer not to say">Prefer not to say</option>
                  </select><br>
          <input type="submit" value="Register">
        </form>
      </body>
    </html>
    """

@app.route('/admin', methods=['GET', 'POST'])
def admin():
    global splash_header
    msg = ""
    if request.method == 'POST' and 'header' in request.form:
        new_header = request.form.get('header')
        if new_header:
            splash_header = new_header
            msg = "Header updated successfully."
    try:
        df = pd.read_csv(current_csv_filename)
    except Exception:
        df = pd.DataFrame(columns=["First Name", "Last Name", "Birthday", "Zip Code", "Email", "Gender"])
    total_registrations = len(df)
    return f"""
    <html>
      <head><title>{DEVICE_NAME} - Admin</title></head>
      <body>
        <h1>{DEVICE_NAME} Admin Management</h1>
        <p>{msg}</p>
        <form method="post">
          Change Splash Header: <input type="text" name="header" value="{splash_header}">
          <input type="submit" value="Update">
        </form>
        <p>Total Registrations: {total_registrations}</p>
        <form method="post" action="/admin/revoke">
          <input type="submit" value="Revoke All Leases">
        </form>
        <h2>Download CSV</h2>
        <a href="/download_csv">Download CSV</a>
      </body>
    </html>
    """

@app.route('/admin/revoke', methods=['POST'])
def revoke_leases():
    leases_file = "/var/lib/misc/dnsmasq.leases"
    blocked_ips = []
    try:
        with open(leases_file, 'r') as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 3:
                    ip = parts[2]
                    blocked_ips.append(ip)
    except Exception as e:
        return "Error reading leases file: " + str(e)
    import subprocess
    subprocess.call("iptables -L CAPTIVE_BLOCK >/dev/null 2>&1 || iptables -N CAPTIVE_BLOCK", shell=True)
    subprocess.call("iptables -F CAPTIVE_BLOCK", shell=True)
    subprocess.call("iptables -C INPUT -j CAPTIVE_BLOCK 2>/dev/null || iptables -I INPUT -j CAPTIVE_BLOCK", shell=True)
    for ip in blocked_ips:
        subprocess.call(f"iptables -A CAPTIVE_BLOCK -s {ip} -j DROP", shell=True)
    return "Revoked privileges for the following IPs: " + ", ".join(blocked_ips)

@app.route('/download_csv')
def download_csv():
    return send_file(current_csv_filename, as_attachment=True)

# --- OLED Display Support (Optional) ---
if USE_OLED:
    try:
         from luma.core.interface.serial import i2c
         from luma.oled.device import ssd1331
         from PIL import Image, ImageDraw, ImageFont
         serial = i2c(port=1, address=0x3C)
         device = ssd1331(serial)
         font = ImageFont.load_default()
         image = Image.new("RGB", (device.width, device.height))
         draw = ImageDraw.Draw(image)
         draw.text((0,0), "Howzit!", fill="white", font=font)
         device.display(image)
    except Exception as e:
         print("OLED display initialization failed:", e)
    def oled_status_update():
         import time
         from PIL import Image, ImageDraw, ImageFont
         from luma.core.interface.serial import i2c
         from luma.oled.device import ssd1331
         serial = i2c(port=1, address=0x3C)
         device = ssd1331(serial)
         font = ImageFont.load_default()
         while True:
             try:
                 with open("/var/lib/misc/dnsmasq.leases", "r") as f:
                     leases = f.readlines()
                 active_leases = len(leases)
             except:
                 active_leases = 0
             image = Image.new("RGB", (device.width, device.height))
             draw = ImageDraw.Draw(image)
             draw.text((0,0), "System Ready", fill="white", font=font)
             draw.text((0,10), f"Leases: {active_leases} / 245", fill="white", font=font)
             device.display(image)
             time.sleep(10)
    import threading
    t = threading.Thread(target=oled_status_update, daemon=True)
    t.start()

if __name__ == '__main__':
    init_csv()
    # Bind Flask explicitly to 10.69.0.1
    app.run(host='10.69.0.1', port=80)
EOF

chmod +x /usr/local/bin/howzit.py
update_status $CURRENT_STEP $TOTAL_STEPS "Step 6: Application written."
sleep 0.5
CURRENT_STEP=$((CURRENT_STEP+1))

# --- Create systemd Service Unit ---
echo "Creating systemd service unit for Howzit..."
cat << EOF > /etc/systemd/system/howzit.service
[Unit]
Description=Howzit Captive Portal Service on ${DEVICE_NAME}
After=network.target

[Service]
Type=simple
Environment=MPLCONFIGDIR=/tmp/matplotlib
ExecStartPre=/sbin/ifconfig ${CP_INTERFACE} 10.69.0.1 netmask 255.255.255.0 up
ExecStartPre=/bin/sh -c "echo 1 > /proc/sys/net/ipv4/ip_forward"
ExecStartPre=/sbin/iptables -t nat -F
ExecStartPre=/sbin/iptables -t nat -A POSTROUTING -o ${INTERNET_INTERFACE} -j MASQUERADE
# Use DNAT to force all TCP port 80 traffic arriving on CP_INTERFACE to the captive portal
ExecStartPre=/sbin/iptables -t nat -A PREROUTING -i ${CP_INTERFACE} -p tcp --dport 80 -j DNAT --to-destination 10.69.0.1:80
ExecStart=/usr/bin/python3 /usr/local/bin/howzit.py
Restart=always
RestartSec=5
User=root
WorkingDirectory=/

[Install]
WantedBy=multi-user.target
EOF

update_status $CURRENT_STEP $TOTAL_STEPS "Step 7: systemd service created."
sleep 0.5

# --- Reload systemd and start the service ---
echo "Reloading systemd and enabling Howzit service..."
systemctl daemon-reload
systemctl enable howzit.service
systemctl restart howzit.service

update_status $TOTAL_STEPS $TOTAL_STEPS "Installation complete. Howzit is now running."
echo ""
echo -e "${GREEN}-----------------------------------------${RESET}"
echo -e "${GREEN}Installation Summary:${RESET}"
echo "  Device Name:              $DEVICE_NAME"
echo "  Captive Portal Interface: $CP_INTERFACE (IP: 10.69.0.1)"
echo "  Internet Interface:       $INTERNET_INTERFACE"
echo "  CSV Timeout (sec):        $CSV_TIMEOUT"
echo "  CSV will be emailed to:    $CSV_EMAIL"
echo "  DHCP Pool:                10.69.0.10 - 10.69.0.254 (/24)"
echo "  Lease Time:               15 minutes"
echo "  DNS for DHCP Clients:     8.8.8.8 (primary), 10.69.0.1 (secondary)"
echo "  OLED Display:             $USE_OLED_PY"
echo -e "${GREEN}-----------------------------------------${RESET}"
