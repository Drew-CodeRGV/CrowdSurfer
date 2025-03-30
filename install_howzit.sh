#!/bin/bash
# install_howzit.sh
# SCRIPT_VERSION must be updated on each new release.
SCRIPT_VERSION="1.0.0"
REMOTE_URL="https://raw.githubusercontent.com/Drew-CodeRGV/CrowdSurfer/main/install_howzit.sh"

# Function: Check for script update
function check_for_update {
    # Ensure curl is available.
    if ! command -v curl >/dev/null 2>&1; then
        echo "curl not found. Installing curl..."
        apt-get update && apt-get install -y curl
    fi

    echo "Checking for script updates..."
    REMOTE_SCRIPT=$(curl -fsSL "$REMOTE_URL")
    if [ $? -ne 0 ] || [ -z "$REMOTE_SCRIPT" ]; then
        echo "Unable to retrieve remote script. Skipping update check."
        return
    fi

    # Extract the remote version (assumes a line like: SCRIPT_VERSION="1.0.1")
    REMOTE_VERSION=$(echo "$REMOTE_SCRIPT" | grep '^SCRIPT_VERSION=' | head -n 1 | cut -d'=' -f2 | tr -d '"')
    if [ -z "$REMOTE_VERSION" ]; then
        echo "Unable to determine remote version. Skipping update."
        return
    fi

    if [ "$REMOTE_VERSION" != "$SCRIPT_VERSION" ]; then
        echo "New version available ($REMOTE_VERSION). Updating..."
        NEW_SCRIPT="/tmp/install_howzit.sh.new"
        curl -fsSL "$REMOTE_URL" -o "$NEW_SCRIPT"
        if [ $? -eq 0 ]; then
            chmod +x "$NEW_SCRIPT"
            echo "Update downloaded. Replacing current script and restarting..."
            mv "$NEW_SCRIPT" "$0"
            exec "$0" "$@"
        else
            echo "Failed to download the new version. Continuing with the current version."
        fi
    else
        echo "Script is up-to-date (version $SCRIPT_VERSION)."
    fi
}

# Run update check first.
check_for_update

# --- Main Installation Script Below ---
# This script installs and configures the Howzit Captive Portal Service on a fresh Raspberry Pi.
# It displays an ASCII art header, prompts for key settings, and shows a concise progress status.
# It then verifies and installs required dependencies, writes the Python captive portal code,
# and creates a systemd service that starts Howzit automatically at boot.

# Check for root privileges.
if [ "$EUID" -ne 0 ]; then 
  echo "Please run as root."
  exit 1
fi

# Function to update a status bar.
function update_status {
    local step=$1
    local total=$2
    local message=$3
    echo -ne "\033[s\033[999;0H"  # Save cursor and move to bottom.
    printf "[%d/%d] %s\033[K\n" "$step" "$total" "$message"
    echo -ne "\033[u"             # Restore cursor.
}

TOTAL_STEPS=7
CURRENT_STEP=1

clear

# --- ASCII Art Header (Sub-Zero style) ---
cat << "EOF"
  ___    ___   ______   ______  ________   ______   ________  ______   ______  
 / _ \  / _ \ | ___ \  | ___ \ |  ___| \ | ___ \ |  ___| \| ___ \ | ___ \ | ___ \
/ /_\ \| /_\ \| |_/ /  | |_/ / | |__|  \| |_/ / | |__|  \| |_/ / | |_/ / | |_/ /
|  _  ||  _  ||    /   |  __/  |  __| . `  __/  |  __| . `  __/  |    /  |    / 
| | | || | | || |\ \   | |     | |__| |\  |     | |__| |\  |     | |\ \  | |\ \ 
\_| |_/\_| |_/\_| \_|  \_|     \____/\_| \_|     \____/\_| \_|     \_| \_| \_| \_|
                                                                                 
         ___   ___  _   _   _____  _____  ___  
        / _ \ |   \| | | | |_   _||  ___|/ _ \ 
       | | | || |\ | | | |   | |  | |_  | | | |
       | | | || | \| | | |   | |  |  _| | | | |
       | |_| || |  | | |_|   | |  | |   | |_| |
        \___/ |_|  |_|\___/  |_|  |_|    \___/ 
EOF

echo ""
echo "Welcome to the Howzit Captive Portal Setup Wizard!"
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
echo ""

update_status $CURRENT_STEP $TOTAL_STEPS "Step 2: Configuration complete."
sleep 0.5
CURRENT_STEP=$((CURRENT_STEP+1))

# --- Update System ---
echo "Updating package lists and upgrading packages..."
apt-get update && apt-get -y upgrade
update_status $CURRENT_STEP $TOTAL_STEPS "Step 3: System updated."
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
update_status $CURRENT_STEP $TOTAL_STEPS "Step 4: Dependencies verified."
sleep 0.5
CURRENT_STEP=$((CURRENT_STEP+1))

# --- Configure dnsmasq for DHCP on CP_INTERFACE ---
echo "Configuring dnsmasq for DHCP on interface ${CP_INTERFACE}..."
grep -q "^interface=${CP_INTERFACE}" /etc/dnsmasq.conf || echo "interface=${CP_INTERFACE}" >> /etc/dnsmasq.conf
grep -q "^dhcp-range=192.168.4.10,192.168.4.250,255.255.255.0,12h" /etc/dnsmasq.conf || echo "dhcp-range=192.168.4.10,192.168.4.250,255.255.255.0,12h" >> /etc/dnsmasq.conf
systemctl restart dnsmasq
update_status $CURRENT_STEP $TOTAL_STEPS "Step 5: dnsmasq configured."
sleep 0.5
CURRENT_STEP=$((CURRENT_STEP+1))

# --- Write the Captive Portal Python Application ---
echo "Writing captive portal application to /usr/local/bin/howzit.py..."
cat << EOF > /usr/local/bin/howzit.py
#!/usr/bin/env python3
import os
os.environ['MPLCONFIGDIR'] = '/tmp/matplotlib'  # Avoid font cache delays.
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

app = Flask("${DEVICE_NAME}")

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
    if email_timer:
        email_timer.cancel()

def append_to_csv(data):
    global last_submission_time, email_timer
    with csv_lock:
        with open(current_csv_filename, 'a', newline='') as f:
            csv.writer(f).writerow(data)
        last_submission_time = time.time()
        if email_timer:
            email_timer.cancel()
        email_timer = threading.Timer(${CSV_TIMEOUT}, send_csv_via_email)
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
    if request.method == 'POST':
        new_header = request.form.get('header')
        if new_header:
            splash_header = new_header
            msg = "Header updated successfully."
    try:
        df = pd.read_csv(current_csv_filename)
    except Exception:
        df = pd.DataFrame(columns=["First Name", "Last Name", "Birthday", "Zip Code", "Email", "Gender"])
    total_registrations = len(df)
    gender_counts = df['Gender'].value_counts() if 'Gender' in df.columns else pd.Series()
    plt.figure()
    (gender_counts.plot.pie(autopct='%1.1f%%') if not gender_counts.empty else plt.text(0.5,0.5,'No Data', ha='center'))
    plt.title('Gender Breakdown')
    buf1 = io.BytesIO(); plt.savefig(buf1, format='png'); plt.close(); buf1.seek(0)
    gender_chart = base64.b64encode(buf1.getvalue()).decode('utf-8')
    zipcode_counts = df['Zip Code'].value_counts() if 'Zip Code' in df.columns else pd.Series()
    plt.figure()
    (zipcode_counts.plot.bar() if not zipcode_counts.empty else plt.text(0.5,0.5,'No Data', ha='center'))
    plt.title('Zip Code Distribution')
    buf2 = io.BytesIO(); plt.savefig(buf2, format='png'); plt.close(); buf2.seek(0)
    zipcode_chart = base64.b64encode(buf2.getvalue()).decode('utf-8')
    def calc_age(bday_str):
        try:
            b = datetime.strptime(bday_str, "%Y-%m-%d").date()
            today = date.today()
            return today.year - b.year - ((today.month, today.day) < (b.month, b.day))
        except:
            return None
    if not df.empty and 'Birthday' in df.columns:
        df['Age'] = df['Birthday'].apply(calc_age)
        bins = {"18-24":0,"25-40":0,"41-55":0,"56-65":0,"65+":0}
        for a in df['Age'].dropna():
            if 18<=a<=24: bins["18-24"]+=1
            elif 25<=a<=40: bins["25-40"]+=1
            elif 41<=a<=55: bins["41-55"]+=1
            elif 56<=a<=65: bins["56-65"]+=1
            elif a>65: bins["65+"]+=1
        age_series = pd.Series(bins)
    else:
        age_series = pd.Series()
    plt.figure()
    (age_series.plot.bar() if not age_series.empty else plt.text(0.5,0.5,'No Data', ha='center'))
    plt.title('Age Groups')
    buf3 = io.BytesIO(); plt.savefig(buf3, format='png'); plt.close(); buf3.seek(0)
    age_chart = base64.b64encode(buf3.getvalue()).decode('utf-8')
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
        <h2>Gender Breakdown</h2>
        <img src="data:image/png;base64,{gender_chart}" alt="Gender Chart"><br>
        <h2>Zip Code Distribution</h2>
        <img src="data:image/png;base64,{zipcode_chart}" alt="Zip Chart"><br>
        <h2>Age Groups</h2>
        <img src="data:image/png;base64,{age_chart}" alt="Age Chart"><br>
        <h2>Download CSV</h2>
        <a href="/download_csv">Download CSV</a>
      </body>
    </html>
    """

@app.route('/download_csv')
def download_csv():
    return send_file(current_csv_filename, as_attachment=True)

if __name__ == '__main__':
    init_csv()
    app.run(host='0.0.0.0', port=80)
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
ExecStartPre=/sbin/ifconfig ${CP_INTERFACE} 192.168.4.1 netmask 255.255.255.0 up
ExecStartPre=/bin/sh -c "echo 1 > /proc/sys/net/ipv4/ip_forward"
ExecStartPre=/sbin/iptables -t nat -F
ExecStartPre=/sbin/iptables -t nat -A POSTROUTING -o ${INTERNET_INTERFACE} -j MASQUERADE
ExecStartPre=/sbin/iptables -t nat -A PREROUTING -i ${CP_INTERFACE} -p tcp --dport 80 -j DNAT --to-destination 192.168.4.1:80
ExecStartPre=/usr/bin/killall dnsmasq || true
ExecStartPre=/usr/sbin/dnsmasq --interface=${CP_INTERFACE} --no-daemon --dhcp-range=192.168.4.10,192.168.4.250,255.255.255.0,12h
ExecStart=/usr/bin/python3 /usr/local/bin/howzit.py
Restart=always
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
systemctl start howzit.service

update_status $TOTAL_STEPS $TOTAL_STEPS "Installation complete. Howzit is now running."
echo ""
echo "-----------------------------------------"
echo "Installation Summary:"
echo "  Device Name:              $DEVICE_NAME"
echo "  Captive Portal Interface: $CP_INTERFACE (IP: 192.168.4.1)"
echo "  Internet Interface:       $INTERNET_INTERFACE"
echo "  CSV Timeout (sec):        $CSV_TIMEOUT"
echo "  CSV will be emailed to:    $CSV_EMAIL"
echo "-----------------------------------------"
