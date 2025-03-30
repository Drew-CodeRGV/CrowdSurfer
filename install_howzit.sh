#!/bin/bash
# install_howzit.sh
# This installation script sets up the Howzit Captive Portal Service on a fresh Raspberry Pi.
# It installs all required dependencies, configures network settings, writes the captive portal
# Python code, creates a systemd service so that Howzit starts automatically at boot, and starts it.
#
# NOTE:
#   - This script is intended for Debian‑based systems (like Raspberry Pi OS).
#   - Postfix is installed in non-interactive mode for basic local SMTP (for emailing CSV files).
#   - Adjust configurations as needed for your environment.

# Check for root privileges.
if [ "$EUID" -ne 0 ]; then 
  echo "Please run as root."
  exit 1
fi

# Set non-interactive mode for apt.
export DEBIAN_FRONTEND=noninteractive

echo "Updating package lists and upgrading packages..."
apt-get update && apt-get -y upgrade

echo "Installing required packages..."
apt-get install -y \
  python3 python3-flask python3-pandas python3-matplotlib \
  dnsmasq net-tools iptables postfix

# Configure dnsmasq for DHCP on eth0.
# (Append configuration to /etc/dnsmasq.conf if not already present.)
echo "Configuring dnsmasq..."
if ! grep -q "^interface=eth0" /etc/dnsmasq.conf; then
  echo "interface=eth0" >> /etc/dnsmasq.conf
fi
if ! grep -q "^dhcp-range=192.168.4.10,192.168.4.250,255.255.255.0,12h" /etc/dnsmasq.conf; then
  echo "dhcp-range=192.168.4.10,192.168.4.250,255.255.255.0,12h" >> /etc/dnsmasq.conf
fi
systemctl restart dnsmasq

# Determine outbound interface: prefer eth1 over wlan0.
if ifconfig eth1 &>/dev/null; then
   OUT_IF="eth1"
else
   OUT_IF="wlan0"
fi
echo "Using outbound interface: $OUT_IF"

# Write the captive portal Python code to /usr/local/bin/howzit.py.
cat << 'EOF' > /usr/local/bin/howzit.py
#!/usr/bin/env python3
import os, time, random, threading, smtplib, csv, io, base64
from datetime import datetime, date
from flask import Flask, request, send_file
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import pandas as pd

app = Flask("Howzit")

# Global variables for CSV management and splash page header.
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
        writer = csv.writer(f)
        # CSV header includes Gender.
        writer.writerow(["First Name", "Last Name", "Birthday", "Zip Code", "Email", "Gender"])
    last_submission_time = time.time()
    if email_timer is not None:
        email_timer.cancel()

def append_to_csv(data):
    global last_submission_time, email_timer
    with csv_lock:
        with open(current_csv_filename, 'a', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(data)
        last_submission_time = time.time()
        # Reset timer: if no new entry in 5 minutes (300 sec), send the CSV.
        if email_timer is not None:
            email_timer.cancel()
        email_timer = threading.Timer(300, send_csv_via_email)
        email_timer.start()

def send_csv_via_email():
    global current_csv_filename
    with csv_lock:
        with open(current_csv_filename, 'rb') as f:
            content = f.read()
    # Compose email with attachment.
    msg = MIMEMultipart()
    msg['Subject'] = "Howzit CSV Submission"
    msg['From'] = "no-reply@example.com"
    msg['To'] = "cs@drewlentz.com"
    body = MIMEText("Attached is the CSV file for the session.")
    msg.attach(body)
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
    # Start a new CSV file after sending.
    init_csv()

@app.route('/', methods=['GET', 'POST'])
def splash():
    global splash_header
    if request.method == 'POST':
        # Get form values.
        first = request.form.get('first_name')
        last = request.form.get('last_name')
        birthday = request.form.get('birthday')  # Expected as YYYY-MM-DD.
        zipcode = request.form.get('zip_code')
        email_addr = request.form.get('email')
        gender = request.form.get('gender')
        append_to_csv([first, last, birthday, zipcode, email_addr, gender])
        return "Thank you for registering!"
    # Build splash page HTML using the current header.
    splash_html = f"""
    <html>
      <head>
        <title>Howzit Captive Portal</title>
      </head>
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
    return splash_html

@app.route('/admin', methods=['GET', 'POST'])
def admin():
    global splash_header
    msg = ""
    if request.method == 'POST':
        # Allow admin to update the splash header.
        new_header = request.form.get('header')
        if new_header:
            splash_header = new_header
            msg = "Header updated successfully."
    # Load current CSV data.
    try:
        df = pd.read_csv(current_csv_filename)
    except Exception:
        df = pd.DataFrame(columns=["First Name", "Last Name", "Birthday", "Zip Code", "Email", "Gender"])
    total_registrations = len(df)
    
    # Gender breakdown pie chart.
    gender_counts = df['Gender'].value_counts() if 'Gender' in df.columns else pd.Series()
    plt.figure()
    if not gender_counts.empty:
        gender_counts.plot.pie(autopct='%1.1f%%')
    else:
        plt.text(0.5, 0.5, 'No Data', horizontalalignment='center')
    plt.title('Gender Breakdown')
    gender_chart = io.BytesIO()
    plt.savefig(gender_chart, format='png')
    plt.close()
    gender_chart.seek(0)
    gender_chart_data = base64.b64encode(gender_chart.getvalue()).decode('utf-8')
    
    # Zip Code distribution bar chart.
    zipcode_counts = df['Zip Code'].value_counts() if 'Zip Code' in df.columns else pd.Series()
    plt.figure()
    if not zipcode_counts.empty:
        zipcode_counts.plot.bar()
    else:
        plt.text(0.5, 0.5, 'No Data', horizontalalignment='center')
    plt.title('Zip Code Distribution')
    zipcode_chart = io.BytesIO()
    plt.savefig(zipcode_chart, format='png')
    plt.close()
    zipcode_chart.seek(0)
    zipcode_chart_data = base64.b64encode(zipcode_chart.getvalue()).decode('utf-8')
    
    # Age groups bar chart (compute age from birthday).
    def calculate_age(bday_str):
        try:
            bday = datetime.strptime(bday_str, "%Y-%m-%d").date()
            today = date.today()
            return today.year - bday.year - ((today.month, today.day) < (bday.month, bday.day))
        except:
            return None
    if not df.empty and 'Birthday' in df.columns:
        df['Age'] = df['Birthday'].apply(calculate_age)
        age_bins = {"18-24": 0, "25-40": 0, "41-55": 0, "56-65": 0, "65+": 0}
        for age in df['Age'].dropna():
            if 18 <= age <= 24:
                age_bins["18-24"] += 1
            elif 25 <= age <= 40:
                age_bins["25-40"] += 1
            elif 41 <= age <= 55:
                age_bins["41-55"] += 1
            elif 56 <= age <= 65:
                age_bins["56-65"] += 1
            elif age > 65:
                age_bins["65+"] += 1
        age_series = pd.Series(age_bins)
    else:
        age_series = pd.Series()
    plt.figure()
    if not age_series.empty:
        age_series.plot.bar()
    else:
        plt.text(0.5, 0.5, 'No Data', horizontalalignment='center')
    plt.title('Age Groups')
    age_chart = io.BytesIO()
    plt.savefig(age_chart, format='png')
    plt.close()
    age_chart.seek(0)
    age_chart_data = base64.b64encode(age_chart.getvalue()).decode('utf-8')
    
    admin_html = f"""
    <html>
      <head>
        <title>Howzit - Admin Management</title>
      </head>
      <body>
        <h1>Howzit Admin Management</h1>
        <p>{msg}</p>
        <form method="post">
          Change Splash Header: <input type="text" name="header" value="{splash_header}">
          <input type="submit" value="Update">
        </form>
        <p>Total Registrations: {total_registrations}</p>
        <h2>Gender Breakdown</h2>
        <img src="data:image/png;base64,{gender_chart_data}" alt="Gender Chart"><br>
        <h2>Zip Code Distribution</h2>
        <img src="data:image/png;base64,{zipcode_chart_data}" alt="Zip Code Chart"><br>
        <h2>Age Groups</h2>
        <img src="data:image/png;base64,{age_chart_data}" alt="Age Chart"><br>
        <h2>Download CSV</h2>
        <a href="/download_csv">Download CSV</a>
      </body>
    </html>
    """
    return admin_html

@app.route('/download_csv')
def download_csv():
    return send_file(current_csv_filename, as_attachment=True)

if __name__ == '__main__':
    init_csv()
    # Run Flask on all interfaces (port 80).
    app.run(host='0.0.0.0', port=80)
EOF

# Make the Python script executable.
chmod +x /usr/local/bin/howzit.py

# Create a systemd service unit file for Howzit.
echo "Creating systemd service unit for Howzit..."
cat << EOF > /etc/systemd/system/howzit.service
[Unit]
Description=Howzit Captive Portal Service
After=network.target

[Service]
Type=simple
# Pre-start commands to set up network configuration and NAT rules.
ExecStartPre=/sbin/ifconfig eth0 192.168.4.1 netmask 255.255.255.0 up
ExecStartPre=/bin/sh -c "echo 1 > /proc/sys/net/ipv4/ip_forward"
# Flush any existing NAT rules and set up new ones.
ExecStartPre=/sbin/iptables -t nat -F
ExecStartPre=/sbin/iptables -t nat -A POSTROUTING -o ${OUT_IF} -j MASQUERADE
ExecStartPre=/sbin/iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 80 -j DNAT --to-destination 192.168.4.1:80
# Ensure dnsmasq is running for DHCP on eth0.
ExecStartPre=/usr/bin/killall dnsmasq || true
ExecStartPre=/usr/sbin/dnsmasq --interface=eth0 --no-daemon --dhcp-range=192.168.4.10,192.168.4.250,255.255.255.0,12h
# Start the Howzit captive portal.
ExecStart=/usr/bin/python3 /usr/local/bin/howzit.py
Restart=always
User=root
WorkingDirectory=/

[Install]
WantedBy=multi-user.target
EOF

# Reload systemd configuration, enable and start the Howzit service.
echo "Reloading systemd and enabling Howzit service..."
systemctl daemon-reload
systemctl enable howzit.service
systemctl start howzit.service

echo "Howzit Captive Portal Service has been installed and started."
echo "It will automatically run on boot. The captive portal is available on eth0 (IP: 192.168.4.1)."
