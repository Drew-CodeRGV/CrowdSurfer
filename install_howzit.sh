#!/bin/bash
# install_howzit.sh
# Version: 3.2.1

export DEBIAN_FRONTEND=noninteractive
# Uncomment the following line for debugging:
# set -x

# ==============================
# ASCII Header
# ==============================
ascii_header=" _                       _ _   _ 
| |__   _____      _____(_) |_| |
| '_ \ / _ \ \ /\ / /_  / | __| |
| | | | (_) \ V  V / / /| | |_|_|
|_| |_|\___/ \_/\_/ /___|_|\__(_)"
echo "$ascii_header"
echo -e "\n\033[32mHowzit Captive Portal Installation Script - Version: 3.2.1\033[0m\n"

# ==============================
# Utility Functions
# ==============================
print_section_header() {
  echo -e "\033[1;36m=== $1 ===\033[0m"
}

print_status_bar() {
  local lines
  lines=$(tput lines)
  tput cup $((lines-1)) 0
  echo -ne "\033[7mInstall Progress: Step $CURRENT_STEP of $TOTAL_STEPS\033[0m"
}

update_status() {
  echo "[$1/$2] $3"
  print_status_bar
}

persist_iptables() {
  [ ! -d /etc/iptables ] && mkdir -p /etc/iptables
  /sbin/iptables-save > /etc/iptables/howzit.rules
}

restore_iptables() {
  if [ -f /etc/iptables/howzit.rules ]; then
    /sbin/iptables-restore < /etc/iptables/howzit.rules
  fi
}

install_packages() {
  local packages=("$@")
  for pkg in "${packages[@]}"; do
    if ! dpkg -s "$pkg" >/dev/null 2>&1; then
      apt-get install -y "$pkg" || true
    fi
  done
}

configure_dnsmasq() {
  sed -i '/^dhcp-range=/d' /etc/dnsmasq.conf || true
  sed -i '/^interface=/d' /etc/dnsmasq.conf || true
  {
      echo "address=/captive.apple.com/10.69.0.1"
      echo "address=/www.apple.com/library/test/success.html/10.69.0.1"
      echo "address=/connectivitycheck.android.com/10.69.0.1"
      echo "address=/clients3.google.com/generate_204/10.69.0.1"
    echo "interface=${CP_INTERFACE}"
    echo "dhcp-range=10.69.0.10,10.69.0.254,15m"
    echo "dhcp-option=option:dns-server,8.8.8.8,10.69.0.1"
    echo "dhcp-option=option:router,10.69.0.1"
    # DNS overrides for captive portal detection:
    echo "address=/captive.apple.com/10.69.0.1"
    echo "address=/www.apple.com/library/test/success.html/10.69.0.1"
    echo "address=/connectivitycheck.android.com/10.69.0.1"
    echo "address=/clients3.google.com/generate_204/10.69.0.1"
  } >> /etc/dnsmasq.conf
  systemctl restart dnsmasq || true
}

configure_captive_interface() {
  # Flush and assign static IP to captive portal interface
  ip addr flush dev "${CP_INTERFACE}" || true
  ip addr add 10.69.0.1/24 dev "${CP_INTERFACE}" || true
  ip link set "${CP_INTERFACE}" up || true
}

# ==============================
# Copy Local Templates Function
# ==============================
copy_templates() {
  local tpl_dir="/usr/local/bin/templates"
  mkdir -p "$tpl_dir"
  if [ ! -f "$tpl_dir/splash.html" ] && [ -f "splash.html" ]; then
    cp splash.html "$tpl_dir/"
    echo "Copied splash.html to $tpl_dir"
  fi
  if [ ! -f "$tpl_dir/admin.html" ] && [ -f "admin.html" ]; then
    cp admin.html "$tpl_dir/"
    echo "Copied admin.html to $tpl_dir"
  fi
}

# ==============================
# Total Steps
# ==============================
TOTAL_STEPS=11
CURRENT_STEP=1

# ==============================
# Section: Rollback Routine
# ==============================
print_section_header "Rollback Routine"
if [ -f /usr/local/bin/howzit.py ]; then
  echo -e "\033[33mExisting Howzit installation detected. Rolling back...\033[0m"
  systemctl stop howzit.service 2>/dev/null
  systemctl disable howzit.service 2>/dev/null
  rm -f /etc/systemd/system/howzit.service /usr/local/bin/howzit.py
  sed -i "\|^interface=${CP_INTERFACE}\$|d" /etc/dnsmasq.conf || true
  sed -i "\|^dhcp-range=10\.69\.0\.10,10\.69\.0\.254,15m\$|d" /etc/dnsmasq.conf || true
  sed -i "\|^dhcp-option=option:router,10\.69\.0\.1\$|d" /etc/dnsmasq.conf || true
  sed -i "\|^dhcp-option=option:dns-server,8\.8\.8\.8,10\.69\.0\.1\$|d" /etc/dnsmasq.conf || true
  sed -i "\|^address=/captive.apple.com/10\.69\.0\.1\$|d" /etc/dnsmasq.conf || true
  sed -i "\|^address=/www.apple.com/library/test/success.html/10\.69\.0\.1\$|d" /etc/dnsmasq.conf || true
  sed -i "\|^address=/connectivitycheck.android.com/10\.69\.0\.1\$|d" /etc/dnsmasq.conf || true
  sed -i "\|^address=/clients3.google.com/generate_204/10\.69\.0\.1\$|d" /etc/dnsmasq.conf || true
  systemctl restart dnsmasq || true
  /sbin/iptables -t nat -F || true
  persist_iptables
  echo -e "\033[32mRollback complete.\033[0m"
fi
update_status $CURRENT_STEP $TOTAL_STEPS "Rollback complete."
sleep 0.5
CURRENT_STEP=$((CURRENT_STEP+1))

# ==============================
# Section: Script Update Check
# ==============================
print_section_header "Script Update Check"
echo "Which version would you like to check for updates?"
echo "  1) Main (stable)"
echo "  2) Dev (testing)"
read -p "Enter option number [1]: " BRANCH_CHOICE
BRANCH_CHOICE=${BRANCH_CHOICE:-1}
if [[ "$BRANCH_CHOICE" == "2" ]]; then
  REMOTE_URL="https://raw.githubusercontent.com/Drew-CodeRGV/CrowdSurfer/dev/install_howzit.sh"
else
  REMOTE_URL="https://raw.githubusercontent.com/Drew-CodeRGV/CrowdSurfer/main/install_howzit.sh"
fi
SCRIPT_VERSION="3.2.1"
check_for_update() {
  if ! command -v curl >/dev/null 2>&1; then
    apt-get update && apt-get install -y curl || true
  fi
  REMOTE_SCRIPT=$(curl -fsSL "$REMOTE_URL") || true
  REMOTE_VERSION=$(echo "$REMOTE_SCRIPT" | grep '^SCRIPT_VERSION=' | head -n 1 | cut -d'=' -f2 | tr -d '"' )
  if [ -n "$REMOTE_VERSION" ] && [ "$REMOTE_VERSION" != "$SCRIPT_VERSION" ]; then
    echo "New version available: $REMOTE_VERSION (current: $SCRIPT_VERSION)"
    read -p "Download and install new version automatically? (y/n) [y]: " update_choice
    update_choice=${update_choice:-y}
    if [[ "$update_choice" =~ ^[Yy]$ ]]; then
      NEW_SCRIPT="/tmp/install_howzit.sh.new"
      curl -fsSL "$REMOTE_URL" -o "$NEW_SCRIPT" || true
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
update_status $CURRENT_STEP $TOTAL_STEPS "Script update check complete."
sleep 0.5
CURRENT_STEP=$((CURRENT_STEP+1))

# ==============================
# Section: Interactive Configuration
# ==============================
print_section_header "Interactive Configuration"
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
[ "$REDIRECT_MODE" == "fixed" ] && echo "  Fixed Redirect URL:       $FIXED_REDIRECT_URL"
echo ""
update_status $CURRENT_STEP $TOTAL_STEPS "Configuration complete."
sleep 0.5
CURRENT_STEP=$((CURRENT_STEP+1))

# ==============================
# Section: Set System Hostname & Update /etc/hosts
# ==============================
print_section_header "Set System Hostname"
NEW_HOSTNAME="${DEVICE_NAME}.cswifi.com"
echo "Setting hostname to ${NEW_HOSTNAME}"
hostnamectl set-hostname "${NEW_HOSTNAME}"
update_hosts() {
  local new_hostname="$1"
  local short_hostname
  short_hostname=$(echo "$new_hostname" | cut -d'.' -f1)
  if grep -q "$new_hostname" /etc/hosts; then
    echo "/etc/hosts already contains $new_hostname"
  else
    echo "127.0.0.1   $new_hostname $short_hostname" >> /etc/hosts
    echo "Added $new_hostname to /etc/hosts"
  fi
}
update_hosts "$NEW_HOSTNAME"
update_status $CURRENT_STEP $TOTAL_STEPS "Hostname set and /etc/hosts updated."
sleep 0.5
CURRENT_STEP=$((CURRENT_STEP+1))

# ==============================
# Section: Configure /etc/resolv.conf
# ==============================
print_section_header "Configure /etc/resolv.conf"
if ! grep -q "nameserver 8.8.8.8" /etc/resolv.conf; then
  echo "nameserver 8.8.8.8" >> /etc/resolv.conf
  echo "Added nameserver 8.8.8.8 to /etc/resolv.conf."
fi
update_status $CURRENT_STEP $TOTAL_STEPS "/etc/resolv.conf configured."
sleep 0.5
CURRENT_STEP=$((CURRENT_STEP+1))

# ==============================
# Section: Configure Captive Portal Interface
# ==============================
print_section_header "Configure Captive Portal Interface"
configure_captive_interface
update_status $CURRENT_STEP $TOTAL_STEPS "Captive portal interface configured with IP 10.69.0.1."
sleep 0.5
CURRENT_STEP=$((CURRENT_STEP+1))

# ==============================
# Section: Package Installation & Waitress Setup
# ==============================
print_section_header "Package Installation"
echo "Updating package lists..."
apt-get update || true
echo "Installing required packages..."
install_packages "python3" "python3-flask" "python3-pandas" "python3-matplotlib" "dnsmasq" "net-tools" "iptables" "python3-pip"
echo "Installing Waitress via apt-get..."
apt-get install -y python3-waitress || true
# Determine Waitress path
WAITRESS_PATH=$(command -v waitress-serve)
if [ -z "$WAITRESS_PATH" ]; then
  echo "Error: Waitress not found. Exiting."
  exit 1
else
  echo "Waitress found at: $WAITRESS_PATH"
fi
update_status $CURRENT_STEP $TOTAL_STEPS "Packages and Waitress installed."
sleep 0.5
CURRENT_STEP=$((CURRENT_STEP+1))

# ==============================
# Section: Configure dnsmasq (again)
# ==============================
print_section_header "Configure dnsmasq"
configure_dnsmasq
update_status $CURRENT_STEP $TOTAL_STEPS "dnsmasq configured."
sleep 0.5
CURRENT_STEP=$((CURRENT_STEP+1))

# ==============================
# Section: Copy Templates

# Create logo upload directory
mkdir -p /usr/local/bin/static/uploads
chmod 755 /usr/local/bin/static/uploads
# ==============================
print_section_header "Copy Templates"
copy_templates
update_status $CURRENT_STEP $TOTAL_STEPS "Templates copied."
sleep 0.5
CURRENT_STEP=$((CURRENT_STEP+1))

# ==============================
# Section: Write Captive Portal Python Application
# ==============================
print_section_header "Write Captive Portal Application"
cat > /usr/local/bin/howzit.py << 'EOF'
#!/usr/bin/env python3
import os
import threading
import time
import random
import smtplib
import csv
import subprocess
import re
from datetime import datetime
from flask import Flask, request, send_file, redirect, render_template
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
import pandas as pd
import socket

DEVICE_NAME = os.environ.get("DEVICE_NAME", "Howzit01")
CSV_TIMEOUT = int(os.environ.get("CSV_TIMEOUT", "300"))
REDIRECT_MODE = os.environ.get("REDIRECT_MODE", "original")
FIXED_REDIRECT_URL = os.environ.get("FIXED_REDIRECT_URL", "")
CP_INTERFACE = os.environ.get("CP_INTERFACE", "eth0")
CSV_EMAIL = os.environ.get("CSV_EMAIL", "cs@drewlentz.com")
UPLOAD_FOLDER = "/var/lib/howzit/uploads"
os.makedirs("/var/lib/howzit/uploads", exist_ok=True)

app = Flask(DEVICE_NAME, template_folder="/usr/local/bin/templates")
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

csv_lock = threading.Lock()
current_csv_filename = None
last_submission_time = None
email_timer = None
splash_header = "Welcome to the event!"
logo_filename = None
registered_clients = {}

def update_hosts_file(new_hostname):
    try:
        short_hostname = new_hostname.split(".")[0]
        entry = "127.0.0.1   " + new_hostname + " " + short_hostname + "\n"
        with open("/etc/hosts", "r") as f:
            hosts = f.readlines()
        if not any(new_hostname in line for line in hosts):
            with open("/etc/hosts", "a") as f:
                f.write(entry)
    except Exception as e:
        print("Error updating /etc/hosts:", e)

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
    subprocess.call(f"/sbin/iptables -t nat -I PREROUTING -i {CP_INTERFACE} -m mac --mac-source {mac} -p tcp --dport 80 -j RETURN", shell=True)
    subprocess.call(f"/sbin/iptables -t nat -I PREROUTING -i {CP_INTERFACE} -m mac --mac-source {mac} -p tcp --dport 443 -j REDIRECT --to-ports 80", shell=True)

def schedule_exemption_removal(mac, key, duration=600):
    def remove_rule():
        subprocess.call(f"/sbin/iptables -t nat -D PREROUTING -i {CP_INTERFACE} -m mac --mac-source {mac} -p tcp --dport 80 -j RETURN", shell=True)
        subprocess.call(f"/sbin/iptables -t nat -D PREROUTING -i {CP_INTERFACE} -m mac --mac-source {mac} -p tcp --dport 443 -j REDIRECT --to-ports 80", shell=True)
        registered_clients.pop(key, None)
    threading.Timer(duration, remove_rule).start()

def generate_csv_filename():
    now = datetime.now()
    rand = random.randint(1000, 9999)
    return now.strftime("%Y-%m-%d-%H") + "-" + str(rand) + ".csv"

def init_csv():
    global current_csv_filename
    current_csv_filename = generate_csv_filename()
    with open(current_csv_filename, "w", newline="") as f:
        csv.writer(f).writerow(["First Name", "Last Name", "Birthday", "Zip Code", "Email", "MAC", "Date", "Time"])

def append_to_csv(data):
    global last_submission_time, email_timer
    with csv_lock:
        with open(current_csv_filename, "a", newline="") as f:
            csv.writer(f).writerow(data)
    last_submission_time = time.time()
    if email_timer:
        email_timer.cancel()
    email_timer = threading.Timer(CSV_TIMEOUT, send_csv_via_email)
    email_timer.start()

def send_csv_via_email():
    global current_csv_filename
    with csv_lock, open(current_csv_filename, "rb") as f:
        content = f.read()
    msg = MIMEMultipart()
    msg["Subject"] = "Howzit CSV Submission"
    msg["From"] = "no-reply@example.com"
    msg["To"] = CSV_EMAIL
    msg.attach(MIMEText("Attached is the CSV file for the session."))
    part = MIMEApplication(content, Name=current_csv_filename)
    part["Content-Disposition"] = f"attachment; filename=\"{current_csv_filename}\""
    msg.attach(part)
    try:
        s = smtplib.SMTP("localhost")
        s.send_message(msg)
        s.quit()
    except Exception as e:
        print("Email error:", e)
    init_csv()

@app.route("/", methods=["GET", "POST"])
def splash():
    original_url = request.args.get("url", "")
    global logo_filename
    logo_path = f"/uploads/{logo_filename}" if logo_filename else None
    if request.method == "POST":
        original_url = request.form.get("url", original_url)
        client_ip = request.remote_addr
        mac = get_mac(client_ip)
        email = request.form.get("email")
        key = f"{mac}_{email}" if mac else f"unknown_{email}"
        if key not in registered_clients:
            registered_clients[key] = time.time() + 600
            if mac:
                add_exemption(mac)
                schedule_exemption_removal(mac, key)
        now = datetime.now()
        append_to_csv([
            request.form.get("first_name"),
            request.form.get("last_name"),
            request.form.get("birthday"),
            request.form.get("zip_code"),
            email,
            mac if mac else "unknown",
            now.strftime("%Y-%m-%d"),
            now.strftime("%H:%M:%S")
        ])
        if REDIRECT_MODE == "original" and original_url:
            return redirect(original_url)
        elif REDIRECT_MODE == "fixed" and FIXED_REDIRECT_URL:
            return redirect(FIXED_REDIRECT_URL)
        return "Registration complete."
    return render_template("splash.html", splash_header=splash_header, original_url=original_url, logo_path=logo_path)

@app.route("/admin", methods=["GET", "POST"])
def admin():
    global splash_header, logo_filename
    hostname = socket.gethostname()
    msg = ""
    if request.method == "POST":
        if "hostname" in request.form:
            new_hostname = request.form.get("hostname")
            os.system(f"hostnamectl set-hostname {new_hostname}")
            update_hosts_file(new_hostname)
            hostname = new_hostname
        splash_header = request.form.get("header", splash_header)
        mode = request.form.get("redirect_mode")
        global REDIRECT_MODE, FIXED_REDIRECT_URL
        if mode:
            REDIRECT_MODE = mode
            FIXED_REDIRECT_URL = request.form.get("fixed_url", "") if mode == "fixed" else ""
        if "logo" in request.files:
            logo = request.files["logo"]
            if logo:
                filename = "logo.png"
                logo.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))
                logo_filename = filename
    try:
        df = pd.read_csv(current_csv_filename)
    except:
        df = pd.DataFrame()
    total = len(df)
    logo_path = f"/uploads/{logo_filename}" if logo_filename else None
    return render_template("admin.html", device_name=DEVICE_NAME, current_hostname=hostname,
                           splash_header=splash_header, redirect_mode=REDIRECT_MODE,
                           fixed_redirect_url=FIXED_REDIRECT_URL, total_registrations=total,
                           logo_path=logo_path)

@app.route("/admin/revoke", methods=["POST"])
def revoke():
    subprocess.call("/sbin/iptables -F", shell=True)
    return "All exemptions revoked."

@app.route("/download_csv")
def download_csv():
    return send_file(current_csv_filename, as_attachment=True)

@app.route("/uploads/<path:filename>")
def uploaded_file(filename):
    return send_file(os.path.join(app.config["UPLOAD_FOLDER"], filename))

init_csv()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=80)
EOF

chmod +x /usr/local/bin/howzit.py
update_status $CURRENT_STEP $TOTAL_STEPS "Application written."
sleep 0.5
CURRENT_STEP=$((CURRENT_STEP+1))

# ==============================
# Section: Create systemd Service Unit using Waitress
# and restoring persisted iptables rules
# ==============================
print_section_header "Create systemd Service Unit"
service_content="[Unit]
Description=Howzit Captive Portal Service on ${DEVICE_NAME}
After=network.target

[Service]
Type=simple
Environment=\"CP_INTERFACE=${CP_INTERFACE}\"
Environment=\"DEVICE_NAME=${DEVICE_NAME}\"
Environment=\"CSV_TIMEOUT=${CSV_TIMEOUT}\"
Environment=\"CSV_EMAIL=${CSV_EMAIL}\"
Environment=\"REDIRECT_MODE=${REDIRECT_MODE}\"
Environment=\"FIXED_REDIRECT_URL=${FIXED_REDIRECT_URL}\"
Environment=\"MPLCONFIGDIR=/tmp/matplotlib\"
WorkingDirectory=/usr/local/bin
ExecStartPre=/sbin/ifconfig ${CP_INTERFACE} 10.69.0.1 netmask 255.255.255.0 up
ExecStartPre=/bin/sh -c \"echo 1 > /proc/sys/net/ipv4/ip_forward\"
ExecStartPre=/sbin/iptables -t nat -F
ExecStartPre=/sbin/iptables -t nat -A POSTROUTING -o ${INTERNET_INTERFACE} -j MASQUERADE
ExecStartPre=/sbin/iptables -t nat -A PREROUTING -i ${CP_INTERFACE} -p tcp --dport 80 -j DNAT --to-destination 10.69.0.1:80
ExecStartPre=/sbin/iptables -t nat -A PREROUTING -i ${CP_INTERFACE} -p tcp --dport 443 -j REDIRECT --to-ports 80
ExecStartPre=/sbin/iptables -I FORWARD -i ${CP_INTERFACE} -o ${INTERNET_INTERFACE} -j ACCEPT
ExecStartPre=/sbin/iptables -I FORWARD -o ${CP_INTERFACE} -j ACCEPT
ExecStartPre=/sbin/iptables -I FORWARD -p icmp -j ACCEPT
ExecStartPre=/sbin/iptables -I FORWARD -i ${INTERNET_INTERFACE} -o ${CP_INTERFACE} -m state --state RELATED,ESTABLISHED -j ACCEPT
# Reapply NAT rules after service starts
ExecStartPost=/bin/sh -c '/sbin/iptables -t nat -A POSTROUTING -o ${INTERNET_INTERFACE} -j MASQUERADE'
ExecStartPost=/bin/sh -c '/sbin/iptables -t nat -A PREROUTING -i ${CP_INTERFACE} -p tcp --dport 80 -j DNAT --to-destination 10.69.0.1:80'
ExecStartPost=/bin/sh -c '/sbin/iptables -t nat -A PREROUTING -i ${CP_INTERFACE} -p tcp --dport 443 -j REDIRECT --to-ports 80'
ExecStartPre=/bin/sh -c 'test -f /etc/iptables/howzit.rules && /sbin/iptables-restore < /etc/iptables/howzit.rules'
ExecStart=/usr/bin/waitress-serve --listen=0.0.0.0:80 howzit:app
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target"
echo "$service_content" > /etc/systemd/system/howzit.service
update_status $CURRENT_STEP $TOTAL_STEPS "Systemd service created using Waitress."
sleep 0.5
CURRENT_STEP=$((CURRENT_STEP+1))

echo "Reloading systemd and enabling Howzit service..."
systemctl daemon-reload
systemctl enable howzit.service
systemctl restart howzit.service

persist_iptables
update_status $TOTAL_STEPS $TOTAL_STEPS "Installation complete. Howzit is now running."
echo ""
echo -e "\033[32m-----------------------------------------\033[0m"
echo -e "\033[32mInstallation Summary:\033[0m"
echo "  Device Name:              $DEVICE_NAME"
echo "  Captive Portal Interface: $CP_INTERFACE (IP: 10.69.0.1)"
echo "  Internet Interface:       $INTERNET_INTERFACE"
echo "  CSV Timeout:              $CSV_TIMEOUT sec"
echo "  CSV will be emailed to:    $CSV_EMAIL"
echo "  DHCP Pool:                10.69.0.10 - 10.69.0.254 (/24)"
echo "  Lease Time:               15 minutes"
echo "  DNS for DHCP Clients:     8.8.8.8 (primary), 10.69.0.1 (secondary)"
echo "  Redirect Mode:            $REDIRECT_MODE"
[ "$REDIRECT_MODE" == "fixed" ] && echo "  Fixed Redirect URL:       $FIXED_REDIRECT_URL"
echo -e "\033[32m-----------------------------------------\033[0m"
