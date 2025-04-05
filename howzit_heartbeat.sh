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
  
  # Check splash.html and admin.html
  check_file "splash.html"
  check_file "admin.html"
  
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
