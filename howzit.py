#!/usr/bin/env python3
from flask import Flask, request, render_template_string, redirect, send_from_directory
from datetime import datetime, timedelta
from threading import Timer, Lock
import pandas as pd
import os, csv, random, string, shutil, smtplib
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

HTML_ADMIN = '''
<html><head><title>Admin Panel</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<style>
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #fff; margin: 0; padding: 40px; }
h1, h2 { margin-bottom: 20px; }
canvas { max-width: 600px; margin: 20px auto; display: block; }
form { margin-bottom: 30px; }
input[type="file"] { margin-bottom: 10px; }
button { background: #007aff; color: white; border: none; padding: 10px 20px; border-radius: 8px; font-weight: bold; cursor: pointer; }
ul { list-style: none; padding: 0; }
li { margin-bottom: 10px; }
a { color: #007aff; text-decoration: none; }
a:hover { text-decoration: underline; }
</style></head><body>
<h1>Admin Panel</h1>
<form method='post' enctype='multipart/form-data'>
<input type='file' name='splash' accept='image/*'>
<button type='submit'>Upload Splash Image</button>
</form>
{% if uploaded_image %}<p>Current splash image: <a href='/uploads/{{ uploaded_image }}' target='_blank'>{{ uploaded_image }}</a></p>{% endif %}
<h2>CSV Downloads</h2>
<ul>{% for f in files %}<li><a href='/data/{{ f }}'>{{ f }}</a></li>{% endfor %}</ul>

<h2>Charts</h2>
<canvas id="ageChart"></canvas>
<canvas id="zipChart"></canvas>
<script>
var ctxAge = document.getElementById('ageChart').getContext('2d');
var ctxZip = document.getElementById('zipChart').getContext('2d');
var ageData = {{ age_data | safe }};
var zipData = {{ zip_data | safe }};
new Chart(ctxAge, {type:'bar',data: {labels: ageData.labels,datasets:[{label:'Age Groups',data:ageData.values,backgroundColor:'#007aff'}]}});
new Chart(ctxZip, {type:'bar',data: {labels: zipData.labels,datasets:[{label:'ZIP Codes',data:zipData.values,backgroundColor:'#34c759'}]}});
</script>
</body></html>'''

@app.route("/admin", methods=["GET", "POST"])
def admin():
    files = os.listdir(data_folder)
    uploads = os.listdir(upload_folder)
    uploaded_image = next((f for f in uploads if f.lower().endswith(('.png', '.jpg', '.jpeg'))), None)
    if request.method == "POST" and 'splash' in request.files:
        f = request.files['splash']
        if f.filename.lower().endswith(('png', 'jpg', 'jpeg')):
            for old in uploads:
                os.remove(os.path.join(upload_folder, old))
            f.save(os.path.join(upload_folder, f.filename))
            return redirect("/admin")

    all_entries = []
    for f in files:
        try:
            df = pd.read_csv(os.path.join(data_folder, f))
            all_entries.append(df)
        except Exception:
            continue

    combined = pd.concat(all_entries) if all_entries else pd.DataFrame()
    now = datetime.now()
    def age_group(birth_str):
        try:
            dob = datetime.strptime(birth_str, "%m/%d/%Y")
            age = (now - dob).days // 365
            if age < 18: return "<18"
            elif age <= 24: return "18-24"
            elif age <= 40: return "25-40"
            elif age <= 55: return "41-55"
            elif age <= 65: return "56-65"
            else: return "65+"
        except: return "Unknown"

    age_counts = combined['DOB'].map(age_group).value_counts().to_dict() if not combined.empty else {}
    zip_counts = combined['ZIP'].value_counts().to_dict() if not combined.empty else {}

    age_data = {"labels": list(age_counts.keys()), "values": list(age_counts.values())}
    zip_data = {"labels": list(zip_counts.keys()), "values": list(zip_counts.values())}

    return render_template_string(HTML_ADMIN, uploaded_image=uploaded_image, files=files, age_data=age_data, zip_data=zip_data)

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
    print(f"[Howzit] Saved CSV: {csv_filename}")
    send_csv_email(path)
