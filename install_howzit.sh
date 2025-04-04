#!/bin/bash
# install_howzit.sh
# Version: 2.3.1

# ==============================
# ASCII Header
# ==============================
ascii_header=" _                       _ _   _ 
| |__   _____      _____(_) |_| |
| '_ \ / _ \ \ /\ / /_  / | __| |
| | | | (_) \ V  V / / /| | |_|_|
|_| |_|\___/ \_/\_/ /___|_|\__(_)"
echo "$ascii_header"
echo -e "\n\033[32mHowzit Captive Portal Installation Script - Version 2.3.1\033[0m\n"

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
      apt-get install -y "$pkg"
    fi
  done
}

configure_dnsmasq() {
  sed -i '/^dhcp-range=/d' /etc/dnsmasq.conf
  sed -i '/^interface=/d' /etc/dnsmasq.conf
  {
    echo "interface=${CP_INTERFACE}"
    echo "dhcp-range=10.69.0.10,10.69.0.254,15m"
    echo "dhcp-option=option:dns-server,8.8.8.8,10.69.0.1"
    echo "dhcp-option=option:router,10.69.0.1"
  } >> /etc/dnsmasq.conf
  systemctl restart dnsmasq
}

configure_captive_interface() {
  # Flush and assign static IP to captive portal interface
  ip addr flush dev "${CP_INTERFACE}"
  ip addr add 10.69.0.1/24 dev "${CP_INTERFACE}"
  ip link set "${CP_INTERFACE}" up
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
  sed -i "\|^interface=${CP_INTERFACE}\$|d" /etc/dnsmasq.conf
  sed -i "\|^dhcp-range=10\.69\.0\.10,10\.69\.0\.254,15m\$|d" /etc/dnsmasq.conf
  sed -i "\|^dhcp-option=option:router,10\.69\.0\.1\$|d" /etc/dnsmasq.conf
  sed -i "\|^dhcp-option=option:dns-server,8\.8\.8\.8,10\.69\.0\.1\$|d" /etc/dnsmasq.conf
  systemctl restart dnsmasq
  /sbin/iptables -t nat -F
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
REMOTE_URL="https://raw.githubusercontent.com/Drew-CodeRGV/CrowdSurfer/main/install_howzit.sh"
SCRIPT_VERSION="2.3.1"
check_for_update() {
  if ! command -v curl >/dev/null 2>&1; then
    apt-get update && apt-get install -y curl
  fi
  REMOTE_SCRIPT=$(curl -fsSL "$REMOTE_URL")
  REMOTE_VERSION=$(echo "$REMOTE_SCRIPT" | grep '^SCRIPT_VERSION=' | head -n 1 | cut -d'=' -f2 | tr -d '"')
  if [ -n "$REMOTE_VERSION" ] && [ "$REMOTE_VERSION" != "$SCRIPT_VERSION" ]; then
    echo "New version available: $REMOTE_VERSION (current: $SCRIPT_VERSION)"
    read -p "Download and install new version automatically? (y/n) [y]: " update_choice
    update_choice=${update_choice:-y}
    if [[ "$update_choice" =~ ^[Yy]$ ]]; then
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
[ "$REDIRECT_MODE" == "fixed" ] && echo "  Fixed URL:                $FIXED_REDIRECT_URL"
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
apt-get update
echo "Installing required packages..."
install_packages "python3" "python3-flask" "python3-pandas" "python3-matplotlib" "dnsmasq" "net-tools" "iptables" "python3-pip"
echo "Installing Waitress via apt-get..."
apt-get install -y python3-waitress
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
# Section: Write Captive Portal Python Application
# ==============================
print_section_header "Write Captive Portal Application"
cat > /usr/local/bin/howzit.py << 'EOF'
#!/usr/bin/env python3
import os
os.environ["MPLCONFIGDIR"] = "/tmp/matplotlib"
import time, random, threading, smtplib, csv, subprocess, re
from datetime import datetime
from flask import Flask, request, send_file, redirect
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
import matplotlib
matplotlib.use("Agg")
import pandas as pd
import socket

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

def update_hosts_file(new_hostname):
    try:
        short_hostname = new_hostname.split(".")[0]
        entry = "127.0.0.1   " + new_hostname + " " + short_hostname + "\n"
        with open("/etc/hosts", "r") as f:
            hosts = f.readlines()
        if not any(new_hostname in line for line in hosts):
            with open("/etc/hosts", "a") as f:
                f.write(entry)
            print("/etc/hosts updated with: " + entry.strip())
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
    try:
        output = subprocess.check_output(["arp", "-n", ip]).decode("utf-8")
        match = re.search(r"(([0-9a-f]{2}:){5}[0-9a-f]{2})", output, re.I)
        if match:
            return match.group(0)
    except Exception:
        return None
    return None

def add_exemption(mac):
    subprocess.call("/sbin/iptables -t nat -I PREROUTING -i " + CP_INTERFACE +
                    " -m mac --mac-source " + mac +
                    " -p tcp --dport 80 -j RETURN", shell=True)
    subprocess.call("/sbin/iptables -t nat -I PREROUTING -i " + CP_INTERFACE +
                    " -m mac --mac-source " + mac +
                    " -p tcp --dport 443 -j RETURN", shell=True)

def schedule_exemption_removal(mac, key, duration=600):
    def remove_rule():
        subprocess.call("/sbin/iptables -t nat -D PREROUTING -i " + CP_INTERFACE +
                        " -m mac --mac-source " + mac +
                        " -p tcp --dport 80 -j RETURN", shell=True)
        subprocess.call("/sbin/iptables -t nat -D PREROUTING -i " + CP_INTERFACE +
                        " -m mac --mac-source " + mac +
                        " -p tcp --dport 443 -j RETURN", shell=True)
        registered_clients.pop(key, None)
    timer = threading.Timer(duration, remove_rule)
    timer.start()

def generate_csv_filename():
    now = datetime.now()
    rand = random.randint(1000, 9999)
    return now.strftime("%Y-%m-%d-%H") + "-" + str(rand) + ".csv"

def init_csv():
    global current_csv_filename, last_submission_time, email_timer
    current_csv_filename = generate_csv_filename()
    with open(current_csv_filename, "w", newline="") as f:
        csv.writer(f).writerow(["First Name", "Last Name", "Birthday", "Zip Code", "Email", "MAC", "Date Registered", "Time Registered"])
    last_submission_time = time.time()

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
    part["Content-Disposition"] = "attachment; filename=\"" + current_csv_filename + "\""
    msg.attach(part)
    try:
        s = smtplib.SMTP("localhost")
        s.send_message(msg)
        s.quit()
        print("Email sent for " + current_csv_filename)
    except Exception as e:
        print("Error sending email:", e)
    init_csv()

@app.route("/", methods=["GET", "POST"])
def splash():
    original_url = request.args.get("url", "")
    if request.method == "POST":
        original_url = request.form.get("url", original_url)
        client_ip = request.remote_addr
        mac = get_mac(client_ip)
        email = request.form.get("email")
        key = (mac + "_" + email) if mac else ("unknown_" + email)
        if key not in registered_clients:
            registered_clients[key] = time.time() + 600
            if mac:
                add_exemption(mac)
                schedule_exemption_removal(mac, key, duration=600)
        now = datetime.now()
        reg_date = now.strftime("%Y-%m-%d")
        reg_time = now.strftime("%H:%M:%S")
        append_to_csv([request.form.get("first_name"),
                       request.form.get("last_name"),
                       request.form.get("birthday"),
                       request.form.get("zip_code"),
                       email,
                       mac if mac else "unknown",
                       reg_date,
                       reg_time])
        if REDIRECT_MODE == "original" and original_url:
            target_url = original_url
        elif REDIRECT_MODE == "fixed" and FIXED_REDIRECT_URL:
            target_url = FIXED_REDIRECT_URL
        else:
            target_url = ""
        if target_url:
            redirect_script = (
                "<script>\n"
                "  var seconds = 10;\n"
                "  function countdown() {\n"
                "      if(seconds <= 0) { window.location = \"" + target_url + "\"; }\n"
                "      else {\n"
                "          document.getElementById(\"countdown\").innerHTML = seconds;\n"
                "          seconds--;\n"
                "          setTimeout(countdown, 1000);\n"
                "      }\n"
                "  }\n"
                "  window.onload = countdown;\n"
                "</script>\n"
            )
        else:
            redirect_script = "<p>You now have 10 minutes access. Enjoy your browsing!</p>"
        return (
            "<html>\n"
            "  <head>\n"
            "    <title>Registration Complete</title>\n"
            "    " + redirect_script + "\n"
            "    <style>\n"
            "      body { font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; background: #f7f7f7; text-align: center; padding-top: 50px; }\n"
            "    </style>\n"
            "  </head>\n"
            "  <body>\n"
            "    <p>Thank you for registering!</p>\n"
            "    <p>" + ("Redirecting in <span id=\"countdown\">10</span> seconds..." if target_url else "") + "</p>\n"
            "  </body>\n"
            "</html>\n"
        )
    else:
        return (
            "<html>\n"
            "  <head>\n"
            "    <title>" + splash_header + "</title>\n"
            "    <style>\n"
            "      body { font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; background: #f7f7f7; text-align: center; padding-top: 50px; }\n"
            "      form { display: inline-block; background: #fff; padding: 20px; border-radius: 10px; box-shadow: 0 2px 5px rgba(0,0,0,0.2); }\n"
            "      input[type='text'], input[type='email'], input[type='date'], select { width: 300px; padding: 10px; margin: 10px 0; border: 1px solid #ccc; border-radius: 5px; }\n"
            "      input[type='submit'] { background: #007bff; color: #fff; padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; font-size: 16px; }\n"
            "      input[type='submit']:hover { background: #0056b3; }\n"
            "    </style>\n"
            "  </head>\n"
            "  <body>\n"
            "    <h1>" + splash_header + "</h1>\n"
            "    <form method='post' action='/?url=" + original_url + "'>\n"
            "      <input type='hidden' name='url' value='" + original_url + "'>\n"
            "      First Name: <input type='text' name='first_name' required><br>\n"
            "      Last Name: <input type='text' name='last_name' required><br>\n"
            "      Birthday (YYYY-MM-DD): <input type='date' name='birthday' required><br>\n"
            "      Zip Code: <input type='text' name='zip_code' required><br>\n"
            "      Email: <input type='email' name='email' required><br>\n"
            "      Gender: <select name='gender'>\n"
            "                <option value='Male'>Male</option>\n"
            "                <option value='Female'>Female</option>\n"
            "                <option value='Other'>Other</option>\n"
            "                <option value='Prefer not to say'>Prefer not to say</option>\n"
            "              </select><br>\n"
            "      <input type='submit' value='Register'>\n"
            "    </form>\n"
            "  </body>\n"
            "</html>\n"
        )

@app.route("/admin", methods=["GET", "POST"])
def admin():
    import socket
    current_hostname = socket.gethostname()
    global splash_header, REDIRECT_MODE, FIXED_REDIRECT_URL
    msg = ""
    if request.method == "POST":
        if "hostname" in request.form:
            new_hostname = request.form.get("hostname")
            if new_hostname and new_hostname != current_hostname:
                try:
                    os.system("hostnamectl set-hostname " + new_hostname)
                    update_hosts_file(new_hostname)
                    msg += "Hostname updated to " + new_hostname + ". "
                except Exception as e:
                    msg += "Error updating hostname: " + str(e) + ". "
        if "header" in request.form:
            new_header = request.form.get("header")
            if new_header:
                splash_header = new_header
                msg += "Splash header updated successfully. "
        if "redirect_mode" in request.form:
            REDIRECT_MODE = request.form.get("redirect_mode")
            if REDIRECT_MODE == "fixed":
                FIXED_REDIRECT_URL = request.form.get("fixed_url", "")
            else:
                FIXED_REDIRECT_URL = ""
            msg += "Redirect settings updated."
    try:
        df = pd.read_csv(current_csv_filename)
    except Exception:
        df = pd.DataFrame(columns=["First Name", "Last Name", "Birthday", "Zip Code", "Email", "MAC", "Date Registered", "Time Registered"])
    total_registrations = len(df)
    return (
        "<html>\n"
        "  <head>\n"
        "    <title>" + DEVICE_NAME + " - Admin</title>\n"
        "    <style>\n"
        "      body { font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; background: #f7f7f7; text-align: center; padding-top: 50px; }\n"
        "      form { display: inline-block; background: #fff; padding: 20px; border-radius: 10px; box-shadow: 0 2px 5px rgba(0,0,0,0.2); }\n"
        "      input[type='text'] { width: 300px; padding: 10px; margin: 10px 0; border: 1px solid #ccc; border-radius: 5px; }\n"
        "      input[type='submit'] { background: #007bff; color: #fff; padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; font-size: 16px; }\n"
        "      input[type='submit']:hover { background: #0056b3; }\n"
        "      select { width: 320px; padding: 10px; margin: 10px 0; border: 1px solid #ccc; border-radius: 5px; }\n"
        "    </style>\n"
        "  </head>\n"
        "  <body>\n"
        "    <h1>" + DEVICE_NAME + " Admin Management</h1>\n"
        "    <form method='post'>\n"
        "      Hostname: <input type='text' name='hostname' value='" + current_hostname + "' required><br>\n"
        "      Change Splash Header: <input type='text' name='header' value='" + splash_header + "'><br>\n"
        "      Redirect Mode:\n"
        "      <select name='redirect_mode'>\n"
        "        <option value='original' " + ( "selected" if REDIRECT_MODE=="original" else "" ) + ">Original Requested URL</option>\n"
        "        <option value='fixed' " + ( "selected" if REDIRECT_MODE=="fixed" else "" ) + ">Fixed URL</option>\n"
        "        <option value='none' " + ( "selected" if REDIRECT_MODE=="none" else "" ) + ">No Redirect</option>\n"
        "      </select><br>\n"
        "      Fixed Redirect URL (if applicable): <input type='text' name='fixed_url' value='" + FIXED_REDIRECT_URL + "'><br>\n"
        "      <input type='submit' value='Update Settings'>\n"
        "    </form>\n"
        "    <p>Total Registrations: " + str(total_registrations) + "</p>\n"
        "    <form method='post' action='/admin/revoke'>\n"
        "      <input type='submit' value='Revoke All Exemptions'>\n"
        "    </form>\n"
        "    <h2>Download CSV</h2>\n"
        "    <a href='/download_csv'>Download CSV</a>\n"
        "  </body>\n"
        "</html>\n"
    )

def update_hosts_file(new_hostname):
    try:
        short_hostname = new_hostname.split(".")[0]
        entry = "127.0.0.1   " + new_hostname + " " + short_hostname + "\n"
        with open("/etc/hosts", "r") as f:
            hosts = f.readlines()
        if not any(new_hostname in line for line in hosts):
            with open("/etc/hosts", "a") as f:
                f.write(entry)
            print("/etc/hosts updated with: " + entry.strip())
    except Exception as e:
        print("Error updating /etc/hosts:", e)

@app.route("/admin/revoke", methods=["POST"])
def revoke_leases():
    leases_file = "/var/lib/misc/dnsmasq.leases"
    blocked_ips = []
    try:
        with open(leases_file, "r") as f:
            for line in f:
                if not line.strip():
                    continue
                parts = line.split()
                if len(parts) >= 3:
                    blocked_ips.append(parts[2])
    except Exception as e:
        return "Error reading leases file: " + str(e)
    import subprocess
    subprocess.call("iptables -L CAPTIVE_BLOCK >/dev/null 2>&1 || /sbin/iptables -N CAPTIVE_BLOCK", shell=True)
    subprocess.call("/sbin/iptables -F CAPTIVE_BLOCK", shell=True)
    subprocess.call("/sbin/iptables -C INPUT -j CAPTIVE_BLOCK 2>/dev/null || /sbin/iptables -I INPUT -j CAPTIVE_BLOCK", shell=True)
    for ip in blocked_ips:
        subprocess.call("/sbin/iptables -A CAPTIVE_BLOCK -s " + ip + " -j DROP", shell=True)
    return "Revoked exemptions for: " + ", ".join(blocked_ips)

@app.route("/download_csv")
def download_csv():
    return send_file(current_csv_filename, as_attachment=True)

# Initialize CSV file on import so that current_csv_filename is not None.
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
ExecStartPre=/sbin/iptables -t nat -A PREROUTING -i ${CP_INTERFACE} -p tcp --dport 443 -j DNAT --to-destination 10.69.0.1:80
ExecStartPre=/sbin/iptables -I FORWARD -i ${CP_INTERFACE} -o ${INTERNET_INTERFACE} -j ACCEPT
ExecStartPre=/sbin/iptables -I FORWARD -p icmp -j ACCEPT
ExecStartPre=/sbin/iptables -I FORWARD -i ${INTERNET_INTERFACE} -o ${CP_INTERFACE} -m state --state RELATED,ESTABLISHED -j ACCEPT
ExecStartPre=/bin/sh -c 'test -f /etc/iptables/howzit.rules && /sbin/iptables-restore < /etc/iptables/howzit.rules'
ExecStart=${WAITRESS_PATH} --listen=10.69.0.1:80 howzit:app
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
