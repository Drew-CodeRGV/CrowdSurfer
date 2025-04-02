#!/bin/bash
# install_howzit.sh
# Version: 1.5.1

cat << "HEADER"
 _                       _ _   _ 
| |__   _____      _____(_) |_| |
| '_ \ / _ \ \ /\ / /_  / | __| |
| | | | (_) \ V  V / / /| | |_|_|
|_| |_|\___/ \_/\_/ /___|_|\__(_)
HEADER

echo -e "\n\033[32mHowzit Captive Portal Installation Script - 1.5.1\033[0m\n"

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

# --- Check for Script Updates (optional) ---
REMOTE_URL="https://raw.githubusercontent.com/Drew-CodeRGV/CrowdSurfer/main/install_howzit.sh"
SCRIPT_VERSION="1.5.1"
check_for_update() {
  if ! command -v curl >/dev/null 2>&1; then
    apt-get update && apt-get install -y curl
  fi
  REMOTE_SCRIPT=$(curl -fsSL "$REMOTE_URL")
  REMOTE_VERSION=$(echo "$REMOTE_SCRIPT" | grep '^SCRIPT_VERSION=' | head -n 1 | cut -d'=' -f2 | tr -d '"')
  if [ -n "$REMOTE_VERSION" ] && [ "$REMOTE_VERSION" != "$SCRIPT_VERSION" ]; then
    echo "New version available ($REMOTE_VERSION). Please update manually."
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

def schedule_exemption_removal(mac, key, duration=600):
  def remove_rule():
    subprocess.call(f"/sbin/iptables -t nat -D PREROUTING -i {CP_INTERFACE} -m mac --mac-source {mac} -p tcp --dport 80 -j RETURN", shell=True)
    subprocess.call(f"/sbin/iptables -t nat -D PREROUTING -i {CP_INTERFACE} -m mac --mac-source {mac} -p tcp --dport 443 -j RETURN", shell=True)
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
  email_timer = threading.Timer(CSV_TIMEOUT, send_csv_via_email)
  email_timer.start()

def send_csv_via_email():
  global current_csv_filename
  with csv_lock, open(current_csv_filename, 'rb') as f:
    content = f.read()
  msg = MIMEMultipart()
  msg['Subject'] = "Howzit CSV Submission"
  msg['From'] = "no-reply@example.com"
  msg['To'] = CSV_EMAIL
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
    append_to_csv([request.form.get('first_name'),
                   request.form.get('last_name'),
                   request.form.get('birthday'),
                   request.form.get('zip_code'),
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
      redirect_script = "<p>You now have 10 minutes access. Enjoy your browsing!</p>"
    return f"""
        <html>
          <head>
            <title>Registration Complete</title>
            {redirect_script}
            <style>
              body {{ font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; background: #f7f7f7; text-align: center; padding-top: 50px; }}
            </style>
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
          <head>
            <title>{splash_header}</title>
            <style>
              body {{ font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; background: #f7f7f7; text-align: center; padding-top: 50px; }}
              form {{ display: inline-block; background: #fff; padding: 20px; border-radius: 10px; box-shadow: 0 2px 5px rgba(0,0,0,0.2); }}
              input[type="text"], input[type="email"], input[type="date"], select {{ width: 300px; padding: 10px; margin: 10px 0; border: 1px solid #ccc; border-radius: 5px; }}
              input[type="submit"] {{ background: #007bff; color: #fff; padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; font-size: 16px; }}
              input[type="submit"]:hover {{ background: #0056b3; }}
            </style>
          </head>
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
        msg += "Header updated successfully. "
    if 'redirect_mode' in request.form:
      REDIRECT_MODE = request.form.get('redirect_mode')
      if REDIRECT_MODE == "fixed":
        FIXED_REDIRECT_URL = request.form.get('fixed_url', '')
      else:
        FIXED_REDIRECT_URL = ""
      msg += "Redirect settings updated."
  try:
    df = pd.read_csv(current_csv_filename)
  except Exception:
    df = pd.DataFrame(columns=["First Name", "Last Name", "Birthday", "Zip Code", "Email", "MAC", "Date Registered", "Time Registered"])
  total_registrations = len(df)
  return f"""
    <html>
      <head>
        <title>{DEVICE_NAME} - Admin</title>
        <style>
          body {{ font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; background: #f7f7f7; text-align: center; padding-top: 50px; }}
          form {{ display: inline-block; background: #fff; padding: 20px; border-radius: 10px; box-shadow: 0 2px 5px rgba(0,0,0,0.2); }}
          input[type="text"] {{ width: 300px; padding: 10px; margin: 10px 0; border: 1px solid #ccc; border-radius: 5px; }}
          input[type="submit"] {{ background: #007bff; color: #fff; padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; font-size: 16px; }}
          input[type="submit"]:hover {{ background: #0056b3; }}
          select {{ width: 320px; padding: 10px; margin: 10px 0; border: 1px solid #ccc; border-radius: 5px; }}
        </style>
      </head>
      <body>
        <h1>{DEVICE_NAME} Admin Management</h1>
        <p>{msg}</p>
        <form method="post">
          Change Splash Header: <input type="text" name="header"
