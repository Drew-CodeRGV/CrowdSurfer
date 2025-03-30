#!/bin/bash
# install_howzit.sh
# SCRIPT_VERSION must be updated on each new release.
SCRIPT_VERSION="1.0.1"
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
# It displays an ASCII art header, prompts for key settings, and shows concise progress.
# It then verifies and installs required dependencies, writes the Python captive portal code,
# and creates a systemd service that starts Howzit automatically at boot.
#
# Note: This version removes RealVNC packages and forces the Flask app to bind to 192.168.4.1 (eth0).

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
 __  __     ______     __     __     ______     __     ______    
/\ \_\ \   /\  __ \   /\ \  _ \ \   /\___  \   /\ \   /\__  _\   
\ \  __ \  \ \ \/\ \  \ \ \/ ".\ \  \/_/  /__  \ \ \  \/_/\ \/   
 \ \_\ \_\  \ \_____\  \ \__/".~\_\   /\_____\  \ \_\    \ \_\   
  \/_/\/_/   \/_____/   \/_/   \/_/   \/_____/   \/_/     \/_/   
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

# --- Update System & Remove VNC Packages ---
echo "Updating package lists..."
apt-get update

echo "Removing RealVNC packages..."
apt-get purge -y realvnc-vnc-server realvnc-vnc-viewer
apt-get autoremove -y

echo "Upgrading packages..."
apt-get -y upgrade
update_status $CURRENT_STEP $TOTAL_STEPS "Step 3: System updated and VNC removed."
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
grep -q "^dhcp-range=192.168.4.10,192.168.4.250,255.255.255.0,12h" /etc/dnsmasq.conf || echo "dhcp-range=192.168.4.10,192.168.4.250,255.255.255.0,12h" >> /etc/d
