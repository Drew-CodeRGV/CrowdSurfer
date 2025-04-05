#!/bin/bash
# install_howzit.sh
# Version: 3.3.5

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
echo -e "\n\033[32mHowzit Captive Portal Installation Script - Version: 3.3.5\033[0m\n"

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
# Check Local Files Function
# ==============================
check_local_files() {
  local tpl_dir="/usr/local/bin/templates"
  local app_dir="/usr/local/bin"
  local updated=false

  mkdir -p "$tpl_dir"
  
  # Check for splash.html
  if [ -f "splash.html" ]; then
    echo "Found splash.html in current directory. Will use this instead of default."
    cp "splash.html" "$tpl_dir/"
    updated=true
  fi

  # Check for admin.html
  if [ -f "admin.html" ]; then
    echo "Found admin.html in current directory. Will use this instead of default."
    cp "admin.html" "$tpl_dir/"
    updated=true
  fi

  # Check for howzit.py
  if [ -f "howzit.py" ]; then
    echo "Found howzit.py in current directory. Will use this instead of default."
    cp "howzit.py" "$app_dir/"
    chmod +x "$app_dir/howzit.py"
    updated=true
  fi

  if [ "$updated" = true ]; then
    echo -e "\033[32mLocal files have been used for installation.\033[0m"
    return 0
  else
    echo "No local template or application files found. Using defaults."
    return 1
  fi
}

# ==============================
# Copy Default Templates Function
# ==============================
create_default_templates() {
  local tpl_dir="/usr/local/bin/templates"
  mkdir -p "$tpl_dir"
  
  # Create splash.html if it doesn't exist
  if [ ! -f "$tpl_dir/splash.html" ]; then
    cat > "$tpl_dir/splash.html" << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>{{ splash_header }}</title>
    <style>
      body { font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; background: #f7f7f7; text-align: center; padding-top: 50px; }
      form { display: inline-block; background: #fff; padding: 20px; border-radius: 10px; box-shadow: 0 2px 5px rgba(0,0,0,0.2); }
      input[type='text'], input[type='email'], input[type='date'], select { width: 300px; padding: 10px; margin: 10px 0; border: 1px solid #ccc; border-radius: 5px; }
      input[type='submit'] { background: #007bff; color: #fff; padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; font-size: 16px; }
      input[type='submit']:hover { background: #0056b3; }
      img.logo { max-width: 200px; margin-bottom: 20px; }
      .success-message { background-color: #d4edda; color: #155724; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
    </style>
</head>
<body>
    {% if logo_url %}
        <img src="{{ logo_url }}" alt="Logo" class="logo">
    {% endif %}
    <h1>{{ splash_header }}</h1>
    
    {% if registration_complete %}
        <div class="success-message">
            <h2>Thank you for registering!</h2>
            {% if redirect_url %}
                <p>You will be redirected in <span id="countdown">5</span> seconds...</p>
                <script>
                    let seconds = 5;
                    const countdown = document.getElementById('countdown');
                    const timer = setInterval(function() {
                        seconds--;
                        countdown.textContent = seconds;
                        if (seconds <= 0) {
                            clearInterval(timer);
                            window.location.href = "{{ redirect_url }}";
                        }
                    }, 1000);
                </script>
            {% else %}
                <p>You are now connected to the internet.</p>
            {% endif %}
        </div>
    {% else %}
        <form method="post" action="/?url={{ original_url }}">
          <input type="hidden" name="url" value="{{ original_url }}">
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
          <input type="submit" value="Enter Drawing">
        </form>
    {% endif %}
</body>
</html>
EOF
  fi
  
  # Create admin.html if it doesn't exist
  if [ ! -f "$tpl_dir/admin.html" ]; then
    cat > "$tpl_dir/admin.html" << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>{{ device_name }} - Admin</title>
    <style>
      body { font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; background: #f7f7f7; text-align: center; padding-top: 50px; }
      form { display: inline-block; background: #fff; padding: 20px; border-radius: 10px; box-shadow: 0 2px 5px rgba(0,0,0,0.2); margin-bottom: 20px; }
      input[type='text'], input[type='submit'], input[type='file'] { width: 300px; padding: 10px; margin: 10px 0; border: 1px solid #ccc; border-radius: 5px; }
      input[type='submit'] { background: #007bff; color: #fff; padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; font-size: 16px; }
      input[type='submit']:hover { background: #0056b3; }
      select { width: 320px; padding: 10px; margin: 10px 0; border: 1px solid #ccc; border-radius: 5px; }
      img.logo-preview { max-width: 200px; margin-bottom: 20px; display: block; margin-left: auto; margin-right: auto; }
      .message { background-color: #d4edda; color: #155724; padding: 10px; border-radius: 5px; margin-bottom: 20px; }
      .error { background-color: #f8d7da; color: #721c24; }
    </style>
</head>
<body>
    <h1>{{ device_name }} Admin Management</h1>

    {% if msg %}
    <div class="message">{{ msg }}</div>
    {% endif %}

    {% if logo_url %}
        <img src="{{ logo_url }}" alt="Logo Preview" class="logo-preview">
    {% endif %}

    <form method="post" enctype="multipart/form-data">
      Hostname: <input type="text" name="hostname" value="{{ current_hostname }}" required><br>
      Change Splash Header: <input type="text" name="header" value="{{ splash_header }}"><br>
      Redirect Mode:
      <select name="redirect_mode">
        <option value="original" {{ 'selected' if redirect_mode=="original" else '' }}>Original Requested URL</option>
        <option value="fixed" {{ 'selected' if redirect_mode=="fixed" else '' }}>Fixed URL</option>
        <option value="none" {{ 'selected' if redirect_mode=="none" else '' }}>No Redirect</option>
      </select><br>
      Fixed Redirect URL (if applicable): <input type="text" name="fixed_url" value="{{ fixed_redirect_url }}"><br>
      Upload Logo: <input type="file" name="logo" accept="image/*"><br>
      <input type="submit" value="Update Settings">
    </form>

    <p>Total Registrations: {{ total_registrations }}</p>
    <form method="post" action="/admin/revoke">
      <input type="submit" value="Revoke All Exemptions">
    </form>

    <h2>Download CSV</h2>
    <a href="/download_csv">Download CSV</a>
</body>
</html>
EOF
  fi

  echo "Template files created in $tpl_dir"
}

# ==============================
# Total Steps
# ==============================
TOTAL_STEPS=12
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
REMOTE_URL="https://raw.githubusercontent.com/Drew-CodeRGV/CrowdSurfer/main/install_howzit.sh"
SCRIPT_VERSION="3.3.5"
check_for_update() {
  if ! command -v curl >/dev/null 2>&1; then
    apt-get update && apt-get install -y curl || true
  fi
  REMOTE_SCRIPT=$(curl -fsSL "$REMOTE_URL") || true
  REMOTE_VERSION=$(echo "$REMOTE_SCRIPT" | grep '^SCRIPT_VERSION=' | head -n 1 | cut -d'=' -f2 | tr -d '"')
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
# Section: Local File Check 
# ==============================
print_section_header "Local File Check"
check_local_files
update_status $CURRENT_STEP $TOTAL_STEPS "Local file check complete."
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
install_packages "python3" "python3-flask" "python3-pandas" "python3-matplotlib" "dnsmasq" "net-tools" "iptables" "python3-pip" "python3-werkzeug"
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
# Section: Create Templates/Static Directories
# ==============================
print_section_header "Create Directories and Templates"
# Create static directory
mkdir -p /usr/local/bin/static
chmod 755 /usr/local/bin/static

# Create default templates if they don't already exist
create_default_templates
update_status $CURRENT_STEP $TOTAL_STEPS "Directories and templates created."
sleep 0.5
CURRENT_STEP=$((CURRENT_STEP+1))

# ==============================
# Section: Write Captive Portal Python Application
# ==============================
print_section_header "Write Captive Portal Application"
# Only write the default application if there's no custom one
if [ ! -f "/usr/local/bin/howzit.py" ]; then
  cat > /usr/local/bin/howzit.py << 'EOF'
#!/usr/bin/env python3
# Version: 3.3.5
import os
os.environ["MPLCONFIGDIR"] = "/tmp/matplotlib"
import time, random, threading, smtplib, csv, subprocess, re
from datetime import datetime
from flask import Flask, request, send_file, redirect, render_template, url_for, send_from_directory
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
import matplotlib
matplotlib.use("Agg")
import pandas as pd
import socket
import werkzeug.utils

DEVICE_NAME = os.environ.get("DEVICE_NAME", "Howzit01")
CSV_TIMEOUT = int(os.environ.get("CSV_TIMEOUT", "300"))
REDIRECT_MODE = os.environ.get("REDIRECT_MODE", "original")
FIXED_REDIRECT_URL = os.environ.get("FIXED_REDIRECT_URL", "")
CP_INTERFACE = os.environ.get("CP_INTERFACE", "eth0")
CSV_EMAIL = os.environ.get("CSV_EMAIL", "cs@drewlentz.com")

# Create upload folder for logo
UPLOAD_FOLDER = '/usr/local/bin/static'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# Updated Flask instantiation to use the templates from /usr/local/bin/templates
app = Flask(DEVICE_NAME, 
           template_folder="/usr/local/bin/templates",
           static_folder=UPLOAD_FOLDER)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max upload

# --- Global variables ---
splash_header = "Welcome to the event!"
logo_filename = None

# --- Captive Portal Detection Hook ---
@app.before_request
def captive_portal_detection():
    captive_hosts = [
        "captive.apple.com",
        "www.apple.com",
        "connectivitycheck.android.com",
        "clients3.google.com",
        "www.google.com"
    ]
    if request.host in captive_hosts:
        return redirect("http://10.69.0.1", code=302)
# --- End Captive Portal Detection ---

csv_lock = threading.Lock()
current_csv_filename = None
last_submission_time = None
email_timer = None

registered_clients = {}

def update_hosts_file(new_hostname):
    try:
        short_hostname = new_hostname.split(".")[0]
        entry = "127.0.0.1   " + new_hostname +" " + short_hostname + "\n"
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
                    " -p tcp --dport 443 -j REDIRECT --to-ports 80", shell=True)

def schedule_exemption_removal(mac, key, duration=600):
    def remove_rule():
        subprocess.call("/sbin/iptables -t nat -D PREROUTING -i " + CP_INTERFACE +
                        " -m mac --mac-source " + mac +
                        " -p tcp --dport 80 -j RETURN", shell=True)
        subprocess.call("/sbin/iptables -t nat -D PREROUTING -i " + CP_INTERFACE +
                        " -m mac --mac-source " + mac +
                        " -p tcp --dport 443 -j REDIRECT --to-ports 80", shell=True)
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
        csv.writer(f).writerow(["First Name", "Last Name", "Birthday", "Zip Code", "Email", "Gender", "MAC", "Date Registered", "Time Registered"])
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

def allowed_file(filename):
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/', methods=['GET', 'POST'])
def splash():
    global splash_header
    original_url = request.args.get('url', '')
    
    # Add logo_url to context if logo exists
    logo_url = None
    if logo_filename:
        logo_url = f"/static/{logo_filename}"
    
    if request.method == 'POST':
        original_url = request.form.get('url', original_url)
        client_ip = request.remote_addr
        mac = get_mac(client_ip)
        email = request.form.get('email')
        key = ((mac or "unknown") + "_" + (email or "noemail"))
        if key not in registered_clients:
            registered_clients[key] = time.time() + 600
            if mac:
                add_exemption(mac)
                schedule_exemption_removal(mac, key, duration=600)
        now = datetime.now()
        reg_date = now.strftime("%Y-%m-%d")
        reg_time = now.strftime("%H:%M:%S")
        
        # Add gender to the data collection
        gender = request.form.get('gender', 'Not specified')
        
        append_to_csv([request.form.get('first_name'),
                       request.form.get('last_name'),
                       request.form.get('birthday'),
                       request.form.get('zip_code'),
                       email,
                       gender,
                       mac if mac else "unknown",
                       reg_date,
                       reg_time])
        
        if REDIRECT_MODE == "original" and original_url:
            target_url = original_url
        elif REDIRECT_MODE == "fixed" and FIXED_REDIRECT_URL:
            target_url = FIXED_REDIRECT_URL
        else:
            target_url = ""
            
        return render_template('splash.html',
                              registration_complete=True,
                              redirect_url=target_url,
                              splash_header=splash_header,
                              original_url=original_url,
                              logo_url=logo_url)
    else:
        return render_template('splash.html',
                              registration_complete=False,
                              splash_header=splash_header,
                              original_url=original_url,
                              logo_url=logo_url)

@app.route('/admin', methods=['GET', 'POST'])
def admin():
    global splash_header, REDIRECT_MODE, FIXED_REDIRECT_URL, logo_filename
    
    current_hostname = socket.gethostname()
    msg = ""
    
    if request.method == 'POST':
        if 'hostname' in request.form:
            new_hostname = request.form.get('hostname')
            if new_hostname and new_hostname != current_hostname:
                try:
                    os.system("hostnamectl set-hostname " + new_hostname)
                    update_hosts_file(new_hostname)
                    msg += "Hostname updated to " + new_hostname + ". "
                except Exception as e:
                    msg += "Error updating hostname: " + str(e) + ". "
        
        if 'header' in request.form:
            new_header = request.form.get('header')
            if new_header:
                splash_header = new_header
                msg += "Splash header updated successfully. "
        
        if 'redirect_mode' in request.form:
            REDIRECT_MODE = request.form.get('redirect_mode')
            if REDIRECT_MODE == "fixed":
                FIXED_REDIRECT_URL = request.form.get('fixed_url', '')
            else:
                FIXED_REDIRECT_URL = ""
            msg += "Redirect settings updated. "
        
        # Handle logo upload
        if 'logo' in request.files:
            file = request.files['logo']
            if file.filename != '':
                if allowed_file(file.filename):
                    # Use secure filename function to avoid potential security issues
                    secure_filename = werkzeug.utils.secure_filename(file.filename)
                    # Add timestamp to filename to avoid caching issues
                    timestamp = int(time.time())
                    logo_filename = f"{timestamp}_{secure_filename}"
                    file.save(os.path.join(app.config['UPLOAD_FOLDER'], logo_filename))
                    msg += "Logo uploaded successfully. "
                else:
                    msg += "Invalid file format. Please upload a .png, .jpg, .jpeg, or .gif file. "
    
    # Add logo_url to context if logo exists
    logo_url = None
    if logo_filename:
        logo_url = f"/static/{logo_filename}"
    
    try:
        df = pd.read_csv(current_csv_filename)
        total_registrations = len(df)
    except Exception:
        total_registrations = 0
    
    return render_template('admin.html',
                          device_name=DEVICE_NAME,
                          current_hostname=current_hostname,
                          splash_header=splash_header,
                          redirect_mode=REDIRECT_MODE,
                          fixed_redirect_url=FIXED_REDIRECT_URL,
                          total_registrations=total_registrations,
                          msg=msg,
                          logo_url=logo_url)

@app.route('/static/<filename>')
def serve_static(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/admin/revoke', methods=['POST'])
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

@app.route('/download_csv')
def download_csv():
    return send_file(current_csv_filename, as_attachment=True)

# Initialize CSV file on import so that current_csv_filename is not None.
init_csv()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=80)
EOF

  chmod +x /usr/local/bin/howzit.py
  echo "Default application written."
else
  echo "Using custom application script."
fi

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

# ==============================
# Section: Create Update Script
# ==============================
print_section_header "Create Update Script"
cat > /usr/local/bin/update_howzit.sh << 'EOF'
#!/bin/bash
# update_howzit.sh
# Version: 1.0.0
# This script checks for updated versions of splash.html, admin.html, and howzit.py
# in the current directory and copies them to the appropriate locations

# ==============================
# ASCII Header
# ==============================
ascii_header=" _                       _ _   _ 
| |__   _____      _____(_) |_| |
| '_ \ / _ \ \ /\ / /_  / | __| |
| | | | (_) \ V  V / / /| | |_|_|
|_| |_|\___/ \_/\_/ /___|_|\__(_)"
echo "$ascii_header"
echo -e "\n\033[32mHowzit Local Files Update Script - Version: 1.0.0\033[0m\n"

# ==============================
# Constants
# ==============================
TEMPLATE_DIR="/usr/local/bin/templates"
APP_DIR="/usr/local/bin"
STATIC_DIR="/usr/local/bin/static"

# ==============================
# Utility Functions
# ==============================
check_root() {
  if [ "$(id -u)" -ne 0 ]; then
    echo -e "\033[31mThis script must be run as root\033[0m"
    exit 1
  fi
}

restart_service() {
  if systemctl is-active --quiet howzit.service; then
    echo "Restarting Howzit service..."
    systemctl restart howzit.service
    echo "Service restarted."
  else
    echo "Howzit service is not running. No restart needed."
  fi
}

# ==============================
# Main Functions
# ==============================
update_templates() {
  # Create template directory if it doesn't exist
  mkdir -p "$TEMPLATE_DIR"

  local updated=false

  # Check for splash.html
  if [ -f "splash.html" ]; then
    echo "Found splash.html in current directory. Copying to $TEMPLATE_DIR"
    cp "splash.html" "$TEMPLATE_DIR/"
    updated=true
  fi

  # Check for admin.html
  if [ -f "admin.html" ]; then
    echo "Found admin.html in current directory. Copying to $TEMPLATE_DIR"
    cp "admin.html" "$TEMPLATE_DIR/"
    updated=true
  fi

  if [ "$updated" = true ]; then
    echo -e "\033[32mTemplates updated successfully.\033[0m"
  else
    echo "No template files found in current directory."
  fi
}

update_application() {
  # Check for howzit.py
  if [ -f "howzit.py" ]; then
    echo "Found howzit.py in current directory. Comparing with installed version..."
    
    if [ -f "$APP_DIR/howzit.py" ]; then
      # Get version from files
      local current_version=$(grep -o "Version: [0-9]\+\.[0-9]\+\.[0-9]\+" "$APP_DIR/howzit.py" | cut -d' ' -f2)
      local new_version=$(grep -o "Version: [0-9]\+\.[0-9]\+\.[0-9]\+" "howzit.py" | cut -d' ' -f2)
      
      if [ -z "$current_version" ] || [ -z "$new_version" ]; then
        echo "Could not determine versions. Copying anyway."
        cp "howzit.py" "$APP_DIR/"
        chmod +x "$APP_DIR/howzit.py"
        echo -e "\033[32mhowzit.py updated.\033[0m"
        return 0
      fi
      
      if [ "$(printf '%s\n' "$current_version" "$new_version" | sort -V | head -n1)" != "$new_version" ]; then
        # New version is greater than current version
        echo "Newer version found ($new_version > $current_version). Updating..."
        cp "howzit.py" "$APP_DIR/"
        chmod +x "$APP_DIR/howzit.py"
        echo -e "\033[32mhowzit.py updated to version $new_version.\033[0m"
      else
        echo "Current version ($current_version) is the same or newer than the local file ($new_version). No update needed."
      fi
    else
      echo "No existing howzit.py found. Installing..."
      cp "howzit.py" "$APP_DIR/"
      chmod +x "$APP_DIR/howzit.py"
      echo -e "\033[32mhowzit.py installed.\033[0m"
    fi
  else
    echo "No howzit.py found in current directory."
  fi
}

# ==============================
# Main Execution
# ==============================
main() {
  check_root
  
  # Ensure directories exist
  mkdir -p "$TEMPLATE_DIR"
  mkdir -p "$STATIC_DIR"
  chmod 755 "$STATIC_DIR"
  
  # Update templates and application
  update_templates
  update_application
  
  # Restart service if needed
  if [ -f "$APP_DIR/howzit.py" ]; then
    restart_service
  fi
  
  echo -e "\n\033[32mUpdate process completed.\033[0m"
}

main "$@"
EOF

chmod +x /usr/local/bin/update_howzit.sh
echo "Created update script at /usr/local/bin/update_howzit.sh"
update_status $CURRENT_STEP $TOTAL_STEPS "Update script created."
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
echo "  CSV will be emailed to:   $CSV_EMAIL"
echo "  DHCP Pool:                10.69.0.10 - 10.69.0.254 (/24)"
echo "  Lease Time:               15 minutes"
echo "  DNS for DHCP Clients:     8.8.8.8 (primary), 10.69.0.1 (secondary)"
echo "  Redirect Mode:            $REDIRECT_MODE"
[ "$REDIRECT_MODE" == "fixed" ] && echo "  Fixed Redirect URL:       $FIXED_REDIRECT_URL"
echo -e "\033[32m-----------------------------------------\033[0m"
echo ""
echo "To update local files in the future, place updated versions of splash.html,"
echo "admin.html, or howzit.py in the current directory and run:"
echo -e "\033[1msudo /usr/local/bin/update_howzit.sh\033[0m"
