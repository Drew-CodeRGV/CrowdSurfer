#!/bin/bash
# install_howzit.sh
# Version 1.0.14
REMOTE_URL="https://raw.githubusercontent.com/Drew-CodeRGV/CrowdSurfer/main/install_howzit.sh"
SCRIPT_VERSION="1.0.14"

# ANSI color codes for status messages
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
# This script installs and configures the Howzit Captive Portal Service.
# It uses the 10.69.0.0/24 subnet:
#  - Sets CP_INTERFACE (default eth0) with static IP 10.69.0.1/24.
#  - Configures dnsmasq with a DHCP pool from 10.69.0.10 to 10.69.0.254 (15m lease).
#  - Adds iptables DNAT rules so that all TCP traffic on ports 80 and 443 arriving on CP_INTERFACE is redirected to 10.69.0.1:80.
#  - Writes a Python/Flask captive portal app which:
#       * Displays a registration page that captures an optional originally requested URL (as a query parameter "url").
#       * When a user registers, it looks up the client’s MAC address (via ARP), checks that the MAC/email combination is not already registered, and then:
#           - Exempts that client from DNAT for 10 minutes (by inserting iptables rules).
#           - Starts the CSV timer (which sends the CSV email after inactivity) only on the first registration.
#           - Shows an acknowledgment page with a 10-second countdown, after which it redirects according to the chosen mode.
#  - The admin panel (at /admin) allows you to change the splash header, choose the redirect mode (original, fixed, or none) and (if fixed) set a fixed URL, as well as revoke all client exemptions.
#  - Optionally supports a Waveshare ST7735S LCD display.
#
# IMPORTANT: Remove any conflicting entries from /etc/dnsmasq.conf before running this script.

if [ "$EUID" -ne 0 ]; then 
    echo -e "${YELLOW}Please run as root.${RESET}"
    exit 1
fi

# --- Ask if ST7735 LCD display is to be used ---
read -p "Use ST7735 LCD display to show status? [Y/n]: " USE_LCD_CHOICE
if [[ -z "$USE_LCD_CHOICE" || "$USE_LCD_CHOICE" =~ ^[Yy] ]]; then
    USE_LCD="True"
else
    USE_LCD="False"
fi

# --- Persistent Colored Status Bar Function ---
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
# New: Redirect mode options:
echo "Select Redirect Mode after registration:"
echo "  1) Redirect to originally requested URL"
echo "  2) Redirect to a fixed URL (you will be prompted)"
echo "  3) No redirect (stay on captive portal)"
read -p "Enter option number [1]: " REDIRECT_CHOICE
if [[ -z "$REDIRECT_CHOICE" || "$REDIRECT_CHOICE" == "1" ]]; then
    REDIRECT_MODE="original"
    FIXED_REDIRECT_URL=""
elif [ "$REDIRECT_CHOICE" == "2" ]; then
    REDIRECT_MODE="fixed"
    read -p "Enter the fixed URL to redirect to: " FIXED_REDIRECT_URL
else
    REDIRECT_MODE="none"
    FIXED_REDIRECT_URL=""
fi

echo ""
echo "Configuration Summary:"
echo "  Device Name:              $DEVICE_NAME"
echo "  Captive Portal Interface: $CP_INTERFACE"
echo "  Internet Interface:       $INTERNET_INTERFACE"
echo "  CSV Timeout (sec):        $CSV_TIMEOUT"
echo "  CSV Email:                $CSV_EMAIL"
echo "  Redirect Mode:            $REDIRECT_MODE"
if [ "$REDIRECT_MODE" == "fixed" ]; then
    echo "  Fixed Redirect URL:       $FIXED_REDIRECT_URL"
fi
echo "  Use ST7735 LCD Display:   $USE_LCD"
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
if [ "$USE_LCD" = "True" ]; then
    apt-get install -y python3-pip
    pip3 install adafruit-circuitpython-st7735r pillow
fi
update_status $CURRENT_STEP $TOTAL_STEPS "Step 4: Dependencies verified."
sleep 0.5
CURRENT_STEP=$((CURRENT_STEP+1))

# --- Configure dnsmasq for DHCP on CP_INTERFACE ---
echo "Configuring dnsmasq for DHCP on interface ${CP_INTERFACE}..."
sed -i '/^dhcp-range=/d' /etc/dnsmasq.conf
sed -i '/^interface=/d' /etc/dnsmasq.conf
echo "interface=${CP_INTERFACE}" >> /etc/dnsmasq.conf
echo "dhcp-range=10.69.0.10,10.69.0.254,15m" >> /etc/dnsmasq.conf
echo "dhcp-option=option:dns-server,8.8.8.8,10.69.0.1" >> /etc/dnsmasq.conf
systemctl restart dnsmasq
update_status $CURRENT_STEP $TOTAL_STEPS "Step 5: dnsmasq configured (Pool: 10.69.0.10-10.69.0.254, Lease: 15m)."
sleep 0.5
CURRENT_STEP=$((CURRENT_STEP+1))

# --- Write the Captive Portal Python Application ---
cat << EOF > /usr/local/bin/howzit.py
#!/usr/bin/env python3
import os
os.environ['MPLCONFIGDIR'] = '/tmp/matplotlib'
import time, random, threading, smtplib, csv, io, base64, subprocess, re
from datetime import datetime, date
from flask import Flask, request, send_file, redirect
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
REDIRECT_MODE = "${REDIRECT_MODE}"  # "original", "fixed", or "none"
FIXED_REDIRECT_URL = "${FIXED_REDIRECT_URL}"

# Use LCD display if enabled.
USE_LCD = "${USE_LCD}" == "True"

app = Flask(DEVICE_NAME)

csv_lock = threading.Lock()
current_csv_filename = None
last_submission_time = None
email_timer = None
splash_header = "Welcome to the event!"

# Dictionary to store registered clients: key = MAC_email, value = expiration timestamp.
registered_clients = {}

def get_mac(ip):
    try:
        output = subprocess.check_output(["arp", "-n", ip]).decode("utf-8")
        match = re.search(r"(([0-9a-f]{2}:){5}[0-9a-f]{2})", output, re.I)
        if match:
            return match.group(0)
    except Exception as e:
        return None
    return None

def add_exemption(mac):
    # Add iptables rules to exempt this MAC from DNAT.
    subprocess.call(f"iptables -t nat -I PREROUTING -i {os.environ.get('CP_INTERFACE', 'eth0')} -m mac --mac-source {mac} -p tcp --dport 80 -j RETURN", shell=True)
    subprocess.call(f"iptables -t nat -I PREROUTING -i {os.environ.get('CP_INTERFACE', 'eth0')} -m mac --mac-source {mac} -p tcp --dport 443 -j RETURN", shell=True)

def remove_exemption(mac):
    # Remove the exemption rules for this MAC.
    subprocess.call(f"iptables -t nat -D PREROUTING -i {os.environ.get('CP_INTERFACE', 'eth0')} -m mac --mac-source {mac} -p tcp --dport 80 -j RETURN", shell=True)
    subprocess.call(f"iptables -t nat -D PREROUTING -i {os.environ.get('CP_INTERFACE', 'eth0')} -m mac --mac-source {mac} -p tcp --dport 443 -j RETURN", shell=True)

def schedule_exemption_removal(mac, duration=600):
    # Remove exemption after 'duration' seconds (10 minutes).
    def remove_rule():
        remove_exemption(mac)
        key = f"{mac}_{registered_clients.get(mac, '')}"
        registered_clients.pop(key, None)
    timer = threading.Timer(duration, remove_rule)
    timer.start()

def generate_csv_filename():
    now = datetime.now()
    rand = random.randint(1000, 9999)
    return now.strftime("%Y-%m-%d-%H") + f"-{rand}.csv"

def init_csv():
    global current_csv_filename, last_submission_time, email_timer
    current_csv_filename = generate_csv_filename()
    with open(current_csv_filename, 'w', newline='') as f:
        csv.writer(f).writerow(["First Name", "Last Name", "Birthday", "Zip Code", "Email", "MAC"])
    last_submission_time = time.time()

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
    original_url = request.args.get('url', '')
    client_ip = request.remote_addr
    if request.method == 'POST':
        # Lookup MAC address of client
        mac = get_mac(client_ip)
        email = request.form.get('email')
        # Check if this MAC and email combination is already registered
        key = f"{mac}_{email}"
        if key in registered_clients:
            # Already registered, do nothing (or inform the user)
            pass
        else:
            # New registration: add to registered_clients and add iptables exemption
            registered_clients[key] = time.time() + 600  # valid for 10 minutes
            if mac:
                add_exemption(mac)
                schedule_exemption_removal(mac, duration=600)
        append_to_csv([request.form.get('first_name'),
                       request.form.get('last_name'),
                       request.form.get('birthday'),
                       request.form.get('zip_code'),
                       email,
                       mac if mac else "unknown"])
        # Build the redirect page with countdown
        if REDIRECT_MODE == "original" and original_url:
            target_url = original_url
        elif REDIRECT_MODE == "fixed" and FIXED_REDIRECT_URL:
            target_url = FIXED_REDIRECT_URL
        else:
            target_url = ""
        # If target_url is empty, then no redirect is performed; show a confirmation message.
        redirect_script = ""
        if target_url:
            redirect_script = f"""
            <script>
              var seconds = 10;
              function countdown() {{
                  if(seconds <= 0) {{
                      window.location = "{target_url}";
                  }} else {{
                      document.getElementById("countdown").innerHTML = seconds;
                      seconds--;
                      setTimeout(countdown, 1000);
                  }}
              }}
              window.onload = countdown;
            </script>
            """
        else:
            redirect_script = "<p>No redirect configured.</p>"
        return f"""
        <html>
          <head>
            <title>Registration Complete</title>
            {redirect_script}
          </head>
          <body>
            <p>Thank you for registering!</p>
            <p>{ 'Redirecting in <span id="countdown">10</span> seconds...' if target_url else '' }</p>
          </body>
        </html>
        """
    else:
        return f"""
        <html>
          <head><title>{splash_header}</title></head>
          <body>
            <h1>{splash_header}</h1>
            <form method="post" action="/?url={original_url}">
              <input type="hidden" name="url" value="{original_url}">
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
    global splash_header, REDIRECT_MODE, FIXED_REDIRECT_URL
    msg = ""
    if request.method == 'POST':
        if 'header' in request.form:
            new_header = request.form.get('header')
            if new_header:
                splash_header = new_header
                msg = "Header updated successfully."
        if 'redirect_mode' in request.form:
            REDIRECT_MODE = request.form.get('redirect_mode')
            if REDIRECT_MODE == "fixed":
                FIXED_REDIRECT_URL = request.form.get('fixed_url', '')
            else:
                FIXED_REDIRECT_URL = ""
    try:
        df = pd.read_csv(current_csv_filename)
    except Exception:
        df = pd.DataFrame(columns=["First Name", "Last Name", "Birthday", "Zip Code", "Email", "MAC"])
    total_registrations = len(df)
    return f"""
    <html>
      <head><title>{DEVICE_NAME} - Admin</title></head>
      <body>
        <h1>{DEVICE_NAME} Admin Management</h1>
        <p>{msg}</p>
        <form method="post">
          Change Splash Header: <input type="text" name="header" value="{splash_header}"><br>
          Redirect Mode:
          <select name="redirect_mode">
            <option value="original" {'selected' if REDIRECT_MODE=='original' else ''}>Original Requested URL</option>
            <option value="fixed" {'selected' if REDIRECT_MODE=='fixed' else ''}>Fixed URL</option>
            <option value="none" {'selected' if REDIRECT_MODE=='none' else ''}>No Redirect</option>
          </select><br>
          Fixed Redirect URL (if applicable): <input type="text" name="fixed_url" value="{FIXED_REDIRECT_URL}"><br>
          <input type="submit" value="Update Settings">
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

# --- Initialize Redirect Global Variables ---
REDIRECT_MODE = "original"
FIXED_REDIRECT_URL = ""

# --- ST7735 LCD Display Support (for Waveshare ST7735S) ---
if USE_LCD:
    try:
         import board, digitalio
         import adafruit_st7735r
         from PIL import Image, ImageDraw, ImageFont
         spi = board.SPI()
         cs = digitalio.DigitalInOut(board.CE0)
         dc = digitalio.DigitalInOut(board.D24)
         rst = digitalio.DigitalInOut(board.D25)
         lcd = adafruit_st7735r.ST7735R(spi, cs=cs, dc=dc, rst=rst, width=128, height=160)
         font = ImageFont.load_default()
         image = Image.new("RGB", (lcd.width, lcd.height))
         draw = ImageDraw.Draw(image)
         draw.text((0,0), "Howzit!", fill="white", font=font)
         lcd.image(image)
    except Exception as e:
         print("LCD display initialization failed:", e)
    def lcd_status_update():
         import time
         from PIL import Image, ImageDraw, ImageFont
         import board, digitalio
         import adafruit_st7735r
         spi = board.SPI()
         cs = digitalio.DigitalInOut(board.CE0)
         dc = digitalio.DigitalInOut(board.D24)
         rst = digitalio.DigitalInOut(board.D25)
         lcd = adafruit_st7735r.ST7735R(spi, cs=cs, dc=dc, rst=rst, width=128, height=160)
         font = ImageFont.load_default()
         while True:
             try:
                 with open("/var/lib/misc/dnsmasq.leases", "r") as f:
                     leases = f.readlines()
                 active_leases = len(leases)
             except:
                 active_leases = 0
             image = Image.new("RGB", (lcd.width, lcd.height))
             draw = ImageDraw.Draw(image)
             draw.text((0,0), "System Ready", fill="white", font=font)
             draw.text((0,10), f"Leases: {active_leases}", fill="white", font=font)
             lcd.image(image)
             time.sleep(10)
    import threading
    t = threading.Thread(target=lcd_status_update, daemon=True)
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
# DNAT rules for both HTTP and HTTPS traffic arriving on CP_INTERFACE are forced to 10.69.0.1:80,
# unless the client's MAC is exempted.
ExecStartPre=/sbin/iptables -t nat -A PREROUTING -i ${CP_INTERFACE} -p tcp --dport 80 -j DNAT --to-destination 10.69.0.1:80
ExecStartPre=/sbin/iptables -t nat -A PREROUTING -i ${CP_INTERFACE} -p tcp --dport 443 -j DNAT --to-destination 10.69.0.1:80
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
echo "  Redirect Mode:            $REDIRECT_MODE"
if [ "$REDIRECT_MODE" == "fixed" ]; then
    echo "  Fixed Redirect URL:       $FIXED_REDIRECT_URL"
fi
echo "  ST7735 LCD Display:       $USE_LCD"
echo -e "${GREEN}-----------------------------------------${RESET}"
