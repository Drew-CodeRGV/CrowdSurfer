#!/usr/bin/env python3
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
