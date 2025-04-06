#!/bin/bash
# install_howzit.sh
# Version: 3.4.0
# Complete captive portal solution with WiFi QR code support

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
echo -e "\n\033[32mHowzit Captive Portal Installation Script - Version: 3.4.0\033[0m\n"

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
  
  # Check for qrc.html
  if [ -f "qrc.html" ]; then
    echo "Found qrc.html in current directory. Will use this instead of default."
    cp "qrc.html" "$tpl_dir/"
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
# Create Default Templates Function
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
    <!-- Auto-updated by Howzit Heartbeat -->
    <meta name="generator" content="Howzit Captive Portal">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ splash_header }}</title>
    <style>
      body { font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; background: #f7f7f7; text-align: center; padding-top: 50px; }
      form { display: inline-block; background: #fff; padding: 20px; border-radius: 10px; box-shadow: 0 2px 5px rgba(0,0,0,0.2); }
      input[type='text'], input[type='email'], input[type='date'], select { width: 300px; padding: 10px; margin: 10px 0; border: 1px solid #ccc; border-radius: 5px; }
      input[type='submit'] { background: #007bff; color: #fff; padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; font-size: 16px; }
      input[type='submit']:hover { background: #0056b3; }
      img.logo { max-width: 200px; margin-bottom: 20px; }
      .success-message { background-color: #d4edda; color: #155724; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
      .template-footer { font-size: 10px; color: #999; margin-top: 20px; }
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
    
    <div class="template-footer">
        Howzit Captive Portal | CrowdSurfer
    </div>
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
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
      body { font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; background: #f7f7f7; text-align: center; padding-top: 50px; }
      form { display: inline-block; background: #fff; padding: 20px; border-radius: 10px; box-shadow: 0 2px 5px rgba(0,0,0,0.2); margin-bottom: 20px; }
      input[type='text'], input[type='submit'], input[type='file'], input[type='password'] { width: 300px; padding: 10px; margin: 10px 0; border: 1px solid #ccc; border-radius: 5px; }
      input[type='submit'] { background: #007bff; color: #fff; padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; font-size: 16px; }
      input[type='submit']:hover { background: #0056b3; }
      select { width: 320px; padding: 10px; margin: 10px 0; border: 1px solid #ccc; border-radius: 5px; }
      img.logo-preview { max-width: 200px; margin-bottom: 20px; display: block; margin-left: auto; margin-right: auto; }
      .message { background-color: #d4edda; color: #155724; padding: 10px; border-radius: 5px; margin-bottom: 20px; }
      .error { background-color: #f8d7da; color: #721c24; }
      .tabs { display: flex; justify-content: center; margin-bottom: 20px; }
      .tab { padding: 10px 20px; margin: 0 5px; background: #e9ecef; border-radius: 5px 5px 0 0; cursor: pointer; }
      .tab.active { background: #fff; font-weight: bold; }
      .tab-content { display: none; }
      .tab-content.active { display: block; }
      .button-row { margin-top: 20px; }
      .button-row a { 
          display: inline-block; 
          margin: 0 10px; 
          padding: 10px 20px; 
          background: #28a745; 
          color: white; 
          text-decoration: none; 
          border-radius: 5px;
      }
      .button-row a:hover { background: #218838; }
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
    
    <div class="tabs">
        <div class="tab active" onclick="openTab(event, 'general')">General Settings</div>
        <div class="tab" onclick="openTab(event, 'wifi')">WiFi Settings</div>
        <div class="tab" onclick="openTab(event, 'tools')">Tools</div>
    </div>

    <div id="general" class="tab-content active">
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
    </div>
    
    <div id="wifi" class="tab-content">
        <form method="post" enctype="multipart/form-data">
          WiFi SSID: <input type="text" name="wifi_ssid" value="{{ wifi_ssid }}" required><br>
          WiFi Password: <input type="text" name="wifi_password" value="{{ wifi_password }}" required><br>
          <input type="submit" value="Update WiFi Settings">
        </form>
        
        <div class="button-row">
            <a href="/qrc" target="_blank">View WiFi QR Code Page</a>
        </div>
        
        <div style="margin-top: 20px;">
            <img src="/static/wifi_qr.png" alt="WiFi QR Code" style="max-width: 200px;">
        </div>
    </div>
    
    <div id="tools" class="tab-content">
        <p>Total Registrations: {{ total_registrations }}</p>
        <form method="post" action="/admin/revoke">
          <input type="submit" value="Revoke All Exemptions">
        </form>
        
        <h2>Download CSV</h2>
        <a href="/download_csv">Download CSV</a>
    </div>
    
    <script>
        function openTab(evt, tabName) {
            // Hide all tab content
            var tabcontent = document.getElementsByClassName("tab-content");
            for (var i = 0; i < tabcontent.length; i++) {
                tabcontent[i].classList.remove("active");
            }
            
            // Remove active class
            var tabs = document.getElementsByClassName("tab");
            for (var i = 0; i < tabs.length; i++) {
                tabs[i].classList.remove("active");
            }
            
            // Show the current tab and add an "active" class
            document.getElementById(tabName).classList.add("active");
            evt.currentTarget.classList.add("active");
        }
    </script>
</body>
</html>
EOF
  fi
  
  # Create qrc.html if it doesn't exist
  if [ ! -f "$tpl_dir/qrc.html" ]; then
    cat > "$tpl_dir/qrc.html" << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>{{ splash_header }} - WiFi QR Code</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body {
            font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif;
            background: #f7f7f7;
            text-align: center;
            margin: 0;
            padding: 0;
            display: flex;
            flex-direction: column;
            min-height: 100vh;
            justify-content: center;
        }
        .container {
            padding: 20px;
        }
        h1 {
            margin-bottom: 30px;
        }
        .qr-code {
            margin: 20px auto;
            max-width: 100%;
            height: auto;
        }
        .qr-code img {
            max-width: 100%;
            height: auto;
            max-height: 70vh;
        }
        .instructions {
            margin-top: 30px;
            background: #fff;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.2);
            max-width: 600px;
            margin-left: auto;
            margin-right: auto;
        }
        .instructions p {
            text-align: left;
        }
        .instructions ul {
            text-align: left;
            margin-left: 20px;
        }
        @media (max-width: 768px) {
            .qr-code img {
                max-height: 50vh;
            }
        }
        .fullscreen-button {
            background: #007bff;
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 5px;
            cursor: pointer;
            margin-top: 20px;
        }
        .fullscreen-button:hover {
            background: #0056b3;
        }
        .fullscreen-container {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: white;
            z-index: 1000;
            justify-content: center;
            align-items: center;
            flex-direction: column;
        }
        .fullscreen-container img {
            max-width: 80%;
            max-height: 80vh;
        }
        .exit-fullscreen {
            position: absolute;
            top: 20px;
            right: 20px;
            background: #dc3545;
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 5px;
            cursor: pointer;
        }
        .wifi-details {
            margin-top: 20px;
            font-size: 24px;
            font-weight: bold;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>{{ splash_header }}</h1>
        <div class="qr-code">
            <img src="/static/wifi_qr.png" alt="WiFi QR Code">
        </div>
        
        <button class="fullscreen-button" onclick="showFullscreen()">Show Fullscreen QR Code</button>
        
        <div class="instructions">
            <h2>Connect to {{ wifi_ssid }}</h2>
            <p>Scan this QR code with your phone's camera to automatically connect to our WiFi network.</p>
            <h3>Instructions:</h3>
            <ul>
                <li><strong>iPhone users:</strong> Open your Camera app and point it at the QR code</li>
                <li><strong>Android users:</strong> Use your Camera app or QR code scanner</li>
                <li>Tap the notification that appears to connect</li>
                <li>If prompted, confirm you want to join the network</li>
            </ul>
            <p>Network: <strong>{{ wifi_ssid }}</strong></p>
            <p>Password: <strong>{{ wifi_password }}</strong></p>
        </div>
    </div>
    
    <div id="fullscreenContainer" class="fullscreen-container">
        <button class="exit-fullscreen" onclick="hideFullscreen()">Exit Fullscreen</button>
        <img src="/static/wifi_qr.png" alt="WiFi QR Code">
        <div class="wifi-details">
            {{ wifi_ssid }}<br>
            Password: {{ wifi_password }}
        </div>
    </div>
    
    <script>
        function showFullscreen() {
            document.getElementById('fullscreenContainer').style.display = 'flex';
            
            // Request fullscreen if supported
            var elem = document.getElementById('fullscreenContainer');
            if (elem.requestFullscreen) {
                elem.requestFullscreen();
            } else if (elem.mozRequestFullScreen) { /* Firefox */
                elem.mozRequestFullScreen();
            } else if (elem.webkitRequestFullscreen) { /* Chrome, Safari & Opera */
                elem.webkitRequestFullscreen();
            } else if (elem.msRequestFullscreen) { /* IE/Edge */
                elem.msRequestFullscreen();
            }
        }
        
        function hideFullscreen() {
            document.getElementById('fullscreenContainer').style.display = 'none';
            
            // Exit fullscreen if active
            if (document.exitFullscreen) {
                document.exitFullscreen();
            } else if (document.mozCancelFullScreen) { /* Firefox */
                document.mozCancelFullScreen();
            } else if (document.webkitExitFullscreen) { /* Chrome, Safari & Opera */
                document.webkitExitFullscreen();
            } else if (document.msExitFullscreen) { /* IE/Edge */
                document.msExitFullscreen();
            }
        }
    </script>
</body>
</html>
EOF
  fi

  echo "Template files created in $tpl_dir"
}

# ==============================
# Create Heartbeat Update Script
# ==============================
create_heartbeat_script() {
  cat > /usr/local/bin/howzit_heartbeat.sh << 'EOF'
#!/bin/bash
# howzit_heartbeat.sh
# Version: 1.0.0
# This script checks GitHub for updated template files and installs them automatically

# ==============================
# Configuration
# ==============================
GITHUB_RAW_URL="https://raw.githubusercontent.com/Drew-CodeRGV/CrowdSurfer/main"
TEMPLATE_DIR="/usr/local/bin/templates"
STATIC_DIR="/usr/local/bin/static"
LOG_FILE="/var/log/howzit_heartbeat.log"
LAST_CHECK_FILE="/tmp/howzit_last_check"
CHECK_INTERVAL=360  # 6 minutes (360 seconds)

# ==============================
# Logging Function
# ==============================
log_message() {
  local timestamp
  timestamp=$(date "+%Y-%m-%d %H:%M:%S")
  echo "[$timestamp] $1" >> "$LOG_FILE"
  echo "[$timestamp] $1"
}

# ==============================
# File Hash Function
# ==============================
get_file_hash() {
  if [ -f "$1" ]; then
    md5sum "$1" | cut -d' ' -f1
  else
    echo "file_not_found"
  fi
}

# ==============================
# Check Time Interval
# ==============================
check_time_interval() {
  if [ -f "$LAST_CHECK_FILE" ]; then
    local last_check
    last_check=$(cat "$LAST_CHECK_FILE")
    local current_time
    current_time=$(date +%s)
    local time_diff=$((current_time - last_check))
    
    if [ "$time_diff" -lt "$CHECK_INTERVAL" ]; then
      log_message "Last check was only $time_diff seconds ago. Minimum interval is $CHECK_INTERVAL seconds."
      return 1
    fi
  fi
  
  # Update the last check time
  date +%s > "$LAST_CHECK_FILE"
  # Also create a copy in the static directory for the admin panel
  cp "$LAST_CHECK_FILE" "$STATIC_DIR/last_check.txt" 2>/dev/null || true
  return 0
}

# ==============================
# Check for Updates
# ==============================
check_for_updates() {
  log_message "Checking for template updates from GitHub..."
  
  # Check time interval
  if ! check_time_interval; then
    return 0
  fi
  
  local temp_dir
  temp_dir=$(mktemp -d)
  local updated=false
  
  # Function to check and update a specific file
  check_file() {
    local filename=$1
    local remote_url="$GITHUB_RAW_URL/$filename"
    local local_path="$TEMPLATE_DIR/$filename"
    local temp_path="$temp_dir/$filename"
    
    # Download the file from GitHub
    if curl -s -o "$temp_path" "$remote_url"; then
      # Check if file exists and has changed
      if [ ! -f "$local_path" ] || [ "$(get_file_hash "$temp_path")" != "$(get_file_hash "$local_path")" ]; then
        log_message "New or updated $filename detected. Installing..."
        cp "$temp_path" "$local_path"
        updated=true
      else
        log_message "$filename is up to date."
      fi
    else
      log_message "Failed to download $filename from GitHub."
    fi
  }
  
  # Check splash.html, admin.html, and qrc.html
  check_file "splash.html"
  check_file "admin.html"
  check_file "qrc.html"
  
  # Clean up temp directory
  rm -rf "$temp_dir"
  
  # Restart service if files were updated
  if [ "$updated" = true ]; then
    log_message "Templates updated. Restarting Howzit service..."
    systemctl restart howzit.service
    log_message "Service restarted."
  fi
  
  return 0
}

# ==============================
# Install as Service
# ==============================
install_as_service() {
  if [ -f "/etc/systemd/system/howzit-heartbeat.service" ]; then
    log_message "Heartbeat service already installed."
    return 0
  fi
  
  log_message "Installing heartbeat as systemd service..."
  
  # Create systemd service file
  cat > /etc/systemd/system/howzit-heartbeat.service << EOF
[Unit]
Description=Howzit Template Auto-Update Service
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/howzit_heartbeat.sh --daemon
Restart=always
RestartSec=300
User=root

[Install]
WantedBy=multi-user.target
EOF
  
  # Create systemd timer for periodic execution
  cat > /etc/systemd/system/howzit-heartbeat.timer << EOF
[Unit]
Description=Run Howzit heartbeat check periodically

[Timer]
OnBootSec=60
OnUnitActiveSec=360
RandomizedDelaySec=60
AccuracySec=1

[Install]
WantedBy=timers.target
EOF
  
  # Enable and start the service/timer
  systemctl daemon-reload
  systemctl enable howzit-heartbeat.timer
  systemctl start howzit-heartbeat.timer
  
  log_message "Heartbeat service and timer installed and started."
  return 0
}

# ==============================
# Daemon Mode
# ==============================
run_daemon_mode() {
  log_message "Starting heartbeat in daemon mode..."
  
  # Run initial check
  check_for_updates
  
  # No need for a loop - systemd timer will handle the periodic execution
  log_message "Daemon execution complete. Next check will be triggered by systemd timer."
  exit 0
}

# ==============================
# Main Function
# ==============================
main() {
  # Ensure we're running as root
  if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root"
    exit 1
  fi
  
  # Create log directory if it doesn't exist
  mkdir -p "$(dirname "$LOG_FILE")"
  touch "$LOG_FILE"
  
  # Ensure template directories exist
  mkdir -p "$TEMPLATE_DIR"
  mkdir -p "$STATIC_DIR"
  chmod 755 "$STATIC_DIR"
  
  # Check if we're running in daemon mode
  if [ "$1" = "--daemon" ]; then
    run_daemon_mode
    exit 0
  fi
  
  # Run update check
  check_for_updates
  
  # Install as service if not already installed
  install_as_service
  
  log_message "Heartbeat check completed successfully."
}

# Execute main function
main "$@"
EOF
  chmod +x /usr/local/bin/howzit_heartbeat.sh
  echo "Created heartbeat script at /usr/local/bin/howzit_heartbeat.sh"
}

# ==============================
# Create Local Update Script
# ==============================
create_update_script() {
  cat > /usr/local/bin/update_howzit.sh << 'EOF'
#!/bin/bash
# update_howzit.sh
# Version: 1.0.0
# This script checks for updated versions of splash.html, admin.html, qrc.html and howzit.py
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
  
  # Check for qrc.html
  if [ -f "qrc.html" ]; then
    echo "Found qrc.html in current directory. Copying to $TEMPLATE_DIR"
    cp "qrc.html" "$TEMPLATE_DIR/"
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
}

# ==============================
# Total Steps
# ==============================
TOTAL_STEPS=13
CURRENT_STEP=1

# ==============================
# Section: Rollback Routine
# ==============================
print_section_header "Rollback Routine"
if [ -f /usr/local/bin/howzit.py ]; then
  echo -e "\033[33mExisting Howzit installation detected. Rolling back...\033[0m"
  systemctl stop howzit.service 2>/dev/null
  systemctl disable howzit.service 2>/dev/null
  systemctl stop howzit-heartbeat.timer 2>/dev/null
  systemctl disable howzit-heartbeat.timer 2>/dev/null
  rm -f /etc/systemd/system/howzit.service /usr/local/bin/howzit.py
  rm -f /etc/systemd/system/howzit-heartbeat.service /etc/systemd/system/howzit-heartbeat.timer
  rm -f /usr/local/bin/howzit_heartbeat.sh /usr/local/bin/update_howzit.sh
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
SCRIPT_VERSION="3.4.0"
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

# WiFi Settings for QR code
read -p "Enter WiFi SSID [CrowdSurfer WiFi]: " WIFI_SSID
WIFI_SSID=${WIFI_SSID:-"CrowdSurfer WiFi"}
read -p "Enter WiFi Password [crowdsurfer2024]: " WIFI_PASSWORD
WIFI_PASSWORD=${WIFI_PASSWORD:-"crowdsurfer2024"}

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
echo "  WiFi SSID:                $WIFI_SSID"
echo "  WiFi Password:            $WIFI_PASSWORD"
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
install_packages "python3" "python3-flask" "python3-pandas" "python3-matplotlib" "dnsmasq" "net-tools" "iptables" "python3-pip" "python3-werkzeug" "qrencode" "python3-qrcode" "python3-pil"
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
# Section: Configure dnsmasq
# ==============================
print_section_header "Configure dnsmasq"
configure_dnsmasq
update_status $CURRENT_STEP $TOTAL_STEPS "dnsmasq configured."
sleep 0.5
CURRENT_STEP=$((CURRENT_STEP+1))

# ==============================
# Section: Create Directories and Templates
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
# Section: Create Heartbeat and Update Scripts
# ==============================
print_section_header "Create Utility Scripts"
create_heartbeat_script
create_update_script
update_status $CURRENT_STEP $TOTAL_STEPS "Utility scripts created."
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
# Version: 3.4.0
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
WIFI_PASSWORD = os.environ.get("WIFI_PASSWORD", "crowdsurfer2024")
WIFI_SSID = os.environ.get("WIFI_SSID", "CrowdSurfer WiFi")

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

def generate_qr_code():
    """Generate a QR code for WiFi connection"""
    # Format the WiFi information in the standard format for QR WiFi connection
    wifi_data = f"WIFI:S:{WIFI_SSID};T:WPA;P:{WIFI_PASSWORD};;"
    
    # QR code file path
    qr_file_path = os.path.join(UPLOAD_FOLDER, "wifi_qr.png")
    
    try:
        # First try using qrencode command-line tool if available
        subprocess.run(['which', 'qrencode'], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        subprocess.run(['qrencode', '-o', qr_file_path, wifi_data], check=True)
        return True
    except (subprocess.SubprocessError, subprocess.CalledProcessError):
        try:
            # If qrencode command fails, try Python qrcode library
            import qrcode
            qr = qrcode.QRCode(
                version=1,
                error_correction=qrcode.constants.ERROR_CORRECTION_L,
                box_size=10,
                border=4,
            )
            qr.add_data(wifi_data)
            qr.make(fit=True)
            img = qr.make_image(fill_color="black", back_color="white")
            img.save(qr_file_path)
            return True
        except ImportError:
            # If qrcode module is not available, try installing it
            try:
                subprocess.run(['pip3', 'install', 'qrcode[pil]'], check=True)
                import qrcode
                qr = qrcode.QRCode(
                    version=1,
                    error_correction=qrcode.constants.ERROR_CORRECTION_L,
                    box_size=10,
                    border=4,
                )
                qr.add_data(wifi_data)
                qr.make(fit=True)
                img = qr.make_image(fill_color="black", back_color="white")
                img.save(qr_file_path)
                return True
            except:
                return False

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
    global splash_header, REDIRECT_MODE, FIXED_REDIRECT_URL, logo_filename, WIFI_PASSWORD, WIFI_SSID
    
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
        
        # Handle WiFi settings updates
        if 'wifi_ssid' in request.form:
            new_ssid = request.form.get('wifi_ssid')
            if new_ssid:
                WIFI_SSID = new_ssid
                msg += "WiFi SSID updated. "
                
        if 'wifi_password' in request.form:
            new_password = request.form.get('wifi_password')
            if new_password:
                WIFI_PASSWORD = new_password
                msg += "WiFi password updated. "
                
        # Regenerate QR code if WiFi settings were updated
        if 'wifi_ssid' in request.form or 'wifi_password' in request.form:
            if generate_qr_code():
                msg += "QR code updated. "
            else:
                msg += "Failed to generate QR code. Please ensure qrencode is installed. "
    
    # Add logo_url to context if logo exists
    logo_url = None
    if logo_filename: logo_url = f"/static/{logo_filename}"
    
    try:
        df = pd.read_csv(current_csv_filename)
        total_registrations = len(df)
    except Exception:
        total_registrations = 0
    
    # Generate initial QR code if it doesn't exist
    qr_file_path = os.path.join(UPLOAD_FOLDER, "wifi_qr.png")
    if not os.path.exists(qr_file_path):
        generate_qr_code()
    
    return render_template('admin.html',
                          device_name=DEVICE_NAME,
                          current_hostname=current_hostname,
                          splash_header=splash_header,
                          redirect_mode=REDIRECT_MODE,
                          fixed_redirect_url=FIXED_REDIRECT_URL,
                          total_registrations=total_registrations,
                          wifi_ssid=WIFI_SSID,
                          wifi_password=WIFI_PASSWORD,
                          msg=msg,
                          logo_url=logo_url)

@app.route('/qrc')
def qr_code():
    global splash_header
    
    # Generate QR code for WiFi network if it doesn't exist
    qr_file_path = os.path.join(UPLOAD_FOLDER, "wifi_qr.png")
    if not os.path.exists(qr_file_path):
        if not generate_qr_code():
            return "QR code generation failed. Please ensure 'qrencode' or 'qrcode' Python package is installed."
    
    return render_template('qrc.html', 
                          splash_header=splash_header,
                          wifi_password=WIFI_PASSWORD,
                          wifi_ssid=WIFI_SSID)

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

# Generate initial QR code
generate_qr_code()

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
Environment=\"WIFI_SSID=${WIFI_SSID}\"
Environment=\"WIFI_PASSWORD=${WIFI_PASSWORD}\"
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
# Section: Start Services
# ==============================
print_section_header "Start Services"
echo "Starting Howzit service..."
systemctl daemon-reload
systemctl enable howzit.service
systemctl restart howzit.service

# Install and start heartbeat service
echo "Installing and starting the heartbeat update service..."
/usr/local/bin/howzit_heartbeat.sh

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
echo "  WiFi SSID:                $WIFI_SSID"
echo "  WiFi Password:            $WIFI_PASSWORD" 
echo "  DHCP Pool:                10.69.0.10 - 10.69.0.254 (/24)"
echo "  Lease Time:               15 minutes"
echo "  DNS for DHCP Clients:     8.8.8.8 (primary), 10.69.0.1 (secondary)"
echo "  Redirect Mode:            $REDIRECT_MODE"
[ "$REDIRECT_MODE" == "fixed" ] && echo "  Fixed Redirect URL:       $FIXED_REDIRECT_URL"
echo -e "\033[32m-----------------------------------------\033[0m"
echo ""
echo -e "\033[32mAccess Information:\033[0m"
echo "  Main Portal:              http://10.69.0.1/"
echo "  Admin Panel:              http://10.69.0.1/admin"
echo "  WiFi QR Code:             http://10.69.0.1/qrc"
echo ""
echo "To update local files in the future, place updated versions of splash.html,"
echo "admin.html, qrc.html, or howzit.py in the current directory and run:"
echo -e "\033[1msudo /usr/local/bin/update_howzit.sh\033[0m"
echo ""
echo "The system will automatically check for template updates every 6 minutes."
echo "Logs for the update service are in /var/log/howzit_heartbeat.log"
