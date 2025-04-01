cat << 'EOF' > /usr/local/bin/howzit.py
#!/usr/bin/env python3
from flask import Flask, request, render_template_string, redirect, send_from_directory
from datetime import datetime
from threading import Timer, Lock
import pandas as pd
import os, csv, random, string, smtplib
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

HTML_SPLASH = '''
<html><head><title>Howzit Portal</title>
<style>
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f0f2f5; margin: 0; padding: 40px; }
.container { max-width: 400px; margin: auto; background: white; padding: 30px; border-radius: 16px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); text-align: center; }
input, button { width: 100%; padding: 12px; margin-top: 12px; border-radius: 8px; border: 1px solid #ccc; font-size: 16px; }
button { background: #007aff; color: white; border: none; cursor: pointer; font-weight: 600; }
button:hover { background: #0051c7; }
img { max-width: 100%; border-radius: 12px; margin-bottom: 20px; }
h1 { margin-bottom: 24px; }
</style>
</head><body>
<div class="container">
<h1>Welcome to the event!</h1>
{% if image_url %}<img src="{{ image_url }}" />{% endif %}
<form action="/register" method="post">
<input name="first" placeholder="First Name" required>
<input name="last" placeholder="Last Name" required>
<input name="dob" placeholder="Birthday (MM/DD/YYYY)" required>
<input name="zip" placeholder="ZIP Code" required>
<input name="email" placeholder="Email Address" required>
<button type="submit">Register</button>
</form></div></body></html>'''

HTML_THANKYOU = '''
<html><head><title>Registered</title>
<style>
body { text-align: center; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f9f9f9; padding-top: 80px; }
h2 { font-size: 28px; margin-bottom: 20px; }
p { font-size: 18px; }
</style>
</head>
<body>
<h2>Thank you for registering!</h2>
<p>You’ll be redirected in <span id="countdown">10</span> seconds...</p>
<script>
var seconds = 10;
var countdown = document.getElementById("countdown");
setInterval(function() {
  seconds--; countdown.textContent = seconds;
  if (seconds === 0) { window.location.href = "{{ redirect_url }}"; }
}, 1000);
</script>
</body></html>'''

HTML_CLOSE = '''
<html><head><title>Complete</title>
<style>body { text-align:center; font-family:-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin-top:100px; font-size:24px; }</style>
</head><body>
<p>Ok, good luck!</p>
<script>setTimeout(()=>{window.close()},2000)</script>
</body></html>'''

@app.route("/")
def index():
    files = os.listdir(upload_folder)
    image_url = next((f"/uploads/{f}" for f in files if f.lower().endswith(('.png', '.jpg', '.jpeg', '.gif'))), None)
    return render_template_string(HTML_SPLASH, image_url=image_url)

@app.route("/uploads/<filename>")
def uploads(filename):
    return send_from_directory(upload_folder, filename)

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

@app.route("/register", methods=["POST"])
def register():
    global entries, timer
    info = request.form.to_dict()
    info["MAC"] = request.remote_addr
    now = datetime.now()
    info["Date"] = now.strftime("%Y-%m-%d")
    info["Time"] = now.strftime("%H:%M:%S")
    with csv_lock:
        entries.append(info)
        if timer:
            timer.cancel()
        timer = Timer(timeout_secs, save_csv)
        timer.start()

    if redirect_mode == "fixed":
        return render_template_string(HTML_THANKYOU, redirect_url=fixed_url)
    elif redirect_mode == "none":
        return render_template_string(HTML_CLOSE)
    else:
        return render_template_string(HTML_THANKYOU, redirect_url="http://example.com")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=80)
EOF
