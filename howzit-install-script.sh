#!/bin/bash

#====================================================
# Howzit Captive Portal Complete Installation Script
# 
# This script performs a complete installation and setup of the
# Howzit captive portal on a fresh Raspberry Pi, optimized for efficiency.
#
# Usage: bash install-howzit.sh [options]
#
# Options:
#   --ssid NAME        Set WiFi SSID (default: CrowdSurfer-[random])
#   --password PASS    Set WiFi password (default: open network)
#   --admin-pass PASS  Set admin password (default: howzit)
#   --event NAME       Set event name (default: none)
#   --silent           Non-interactive installation
#   --help             Show this help
#====================================================

# Ensure the script is run as root
if [ "$(id -u)" -ne 0 ]; then
  echo "This script must be run as root" >&2
  echo "Please run: sudo bash $0 $@" >&2
  exit 1
fi

# Text colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
INSTALL_DIR="/opt/crowdsurfer/howzit"
LOG_DIR="/var/log/howzit"
WIFI_SSID="CrowdSurfer-$(cat /proc/sys/kernel/random/uuid | cut -c -8)"
WIFI_PASSWORD=""
ADMIN_USERNAME="admin"
ADMIN_PASSWORD="howzit"
EVENT_NAME="CrowdSurfer Event"
CAPTIVE_IP="10.0.0.1"
ETHERNET_INTERFACE="eth0"
WIFI_INTERFACE="wlan0"
SILENT=false
INTERACTIVE=true

# Parse command line arguments
while [[ $# -gt 0 ]]; do
  case $1 in
    --ssid)
      WIFI_SSID="$2"
      shift 2
      ;;
    --password)
      WIFI_PASSWORD="$2"
      shift 2
      ;;
    --admin-pass)
      ADMIN_PASSWORD="$2"
      shift 2
      ;;
    --event)
      EVENT_NAME="$2"
      shift 2
      ;;
    --silent)
      SILENT=true
      INTERACTIVE=false
      shift
      ;;
    --help)
      echo "Usage: bash $0 [options]"
      echo ""
      echo "Options:"
      echo "  --ssid NAME        Set WiFi SSID (default: CrowdSurfer-[random])"
      echo "  --password PASS    Set WiFi password (default: open network)"
      echo "  --admin-pass PASS  Set admin password (default: howzit)"
      echo "  --event NAME       Set event name (default: none)"
      echo "  --silent           Non-interactive installation"
      echo "  --help             Show this help"
      exit 0
      ;;
    *)
      echo "Unknown option: $1"
      echo "Use --help for usage information"
      exit 1
      ;;
  esac
done

# Create log directory
mkdir -p "$LOG_DIR"
LOG_FILE="$LOG_DIR/install.log"

# Log function
log() {
  echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

# Print section header
section() {
  echo -e "\n${BLUE}=== $1 ===${NC}"
  log "=== $1 ==="
}

# Check command success
check() {
  if [ $? -eq 0 ]; then
    echo -e "  ${GREEN}✓ $1${NC}"
    log "✓ $1"
  else
    echo -e "  ${RED}✗ $1${NC}"
    log "✗ $1"
    if [ "$2" = "critical" ]; then
      echo -e "${RED}Critical error: Installation cannot continue${NC}"
      log "Critical error: Installation cannot continue"
      exit 1
    fi
  fi
}

# Display banner
echo -e "${BLUE}=======================================${NC}"
echo -e "${BLUE}     Howzit Captive Portal Setup      ${NC}"
echo -e "${BLUE}=======================================${NC}"
echo -e "${YELLOW}This script will install and configure the complete${NC}"
echo -e "${YELLOW}Howzit captive portal system on this Raspberry Pi.${NC}"
echo -e ""
log "Starting Howzit installation"

# Interactive configuration if not in silent mode
if [ "$INTERACTIVE" = true ]; then
  echo -e "${YELLOW}WiFi Configuration${NC}"
  read -p "Enter WiFi SSID [$WIFI_SSID]: " input
  WIFI_SSID=${input:-$WIFI_SSID}
  
  read -p "Enter WiFi password (leave empty for open network): " input
  WIFI_PASSWORD=${input:-$WIFI_PASSWORD}
  
  echo -e "\n${YELLOW}Admin Configuration${NC}"
  read -p "Enter admin username [$ADMIN_USERNAME]: " input
  ADMIN_USERNAME=${input:-$ADMIN_USERNAME}
  
  read -s -p "Enter admin password [$ADMIN_PASSWORD]: " input
  echo
  ADMIN_PASSWORD=${input:-$ADMIN_PASSWORD}
  
  echo -e "\n${YELLOW}Event Configuration${NC}"
  read -p "Enter event name [$EVENT_NAME]: " input
  EVENT_NAME=${input:-$EVENT_NAME}
  
  echo
fi

# Setup starts here
section "System Update"
apt update -y
check "Update package lists"

# Install only essential packages and optimize installation time
section "Installing Dependencies"
apt install -y --no-install-recommends hostapd dnsmasq iptables iw git nodejs npm nginx sqlite3
check "Install essential packages" "critical"

# Install additional utilities in background for parallel installation
apt install -y curl python3-minimal build-essential ca-certificates &
BACKGROUND_INSTALL_PID=$!

section "Creating Directories"
mkdir -p "$INSTALL_DIR"/{config,public,src,data,scripts,logs,views}
mkdir -p "$INSTALL_DIR"/public/{css,js,images}
mkdir -p "$INSTALL_DIR"/data/{csv,backups}
check "Create directory structure"

# Clone repository if available, otherwise set up from scratch
section "Setting Up Howzit"
if [ -d "/tmp/howzit" ]; then
  rm -rf "/tmp/howzit"
fi

# Check if GitHub repository exists
if curl --output /dev/null --silent --head --fail "https://github.com/drewlentz/CrowdSurfer"; then
  log "Cloning from GitHub repository"
  git clone https://github.com/drewlentz/CrowdSurfer.git /tmp/crowdsurfer
  if [ -d "/tmp/crowdsurfer/howzit-raspi" ]; then
    cp -r /tmp/crowdsurfer/howzit-raspi/* "$INSTALL_DIR/"
    check "Copy files from GitHub repository"
  else
    log "Repository structure not as expected, creating files manually"
    # Files will be created below
  fi
else
  log "GitHub repository not available, creating files manually"
fi

# Create package.json
cat > "$INSTALL_DIR/package.json" << EOF
{
  "name": "howzit-captive-portal",
  "version": "1.0.0",
  "description": "CrowdSurfer Howzit Captive Portal",
  "main": "app.js",
  "scripts": {
    "start": "node app.js",
    "dev": "nodemon app.js"
  },
  "dependencies": {
    "bcryptjs": "^2.4.3",
    "body-parser": "^1.19.0",
    "cookie-parser": "^1.4.5",
    "ejs": "^3.1.6",
    "express": "^4.17.1",
    "express-session": "^1.17.2",
    "connect-sqlite3": "^0.9.13",
    "morgan": "^1.10.0",
    "sqlite3": "^5.0.2",
    "passport": "^0.5.0",
    "passport-facebook": "^3.0.0",
    "passport-google-oauth20": "^2.0.0",
    "passport-local": "^1.0.0",
    "googleapis": "^92.0.0",
    "fs-extra": "^10.0.0",
    "moment": "^2.29.1",
    "winston": "^3.3.3",
    "cron": "^1.8.2"
  },
  "devDependencies": {
    "nodemon": "^2.0.15"
  }
}
EOF

# Create default configuration
cat > "$INSTALL_DIR/config/default.json" << EOF
{
  "system": {
    "boxName": "$(hostname)",
    "adminUsername": "$ADMIN_USERNAME",
    "adminPassword": "$ADMIN_PASSWORD",
    "logLevel": "info"
  },
  "network": {
    "ssid": "$WIFI_SSID",
    "password": "$WIFI_PASSWORD",
    "apInterface": "$WIFI_INTERFACE",
    "internetInterface": "$ETHERNET_INTERFACE",
    "apIp": "$CAPTIVE_IP"
  },
  "captivePortal": {
    "title": "Sign in to win!",
    "eventName": "$EVENT_NAME",
    "primaryColor": "#3498db",
    "secondaryColor": "#2c3e50",
    "logoUrl": "/images/logo.png",
    "redirectUrl": "https://www.google.com",
    "redirectDelay": 10
  },
  "auth": {
    "google": {
      "enabled": true,
      "clientId": "",
      "clientSecret": ""
    },
    "facebook": {
      "enabled": true,
      "clientId": "",
      "clientSecret": ""
    },
    "twitter": {
      "enabled": false,
      "clientId": "",
      "clientSecret": ""
    },
    "apple": {
      "enabled": false,
      "clientId": "",
      "clientSecret": ""
    }
  },
  "googleSheets": {
    "enabled": true,
    "credentialsFile": "$INSTALL_DIR/config/google-credentials.json",
    "sheetNameTemplate": "${EVENT_NAME}_%DATE%_%RANDOM%"
  },
  "email": {
    "enabled": false,
    "service": "gmail",
    "user": "",
    "password": "",
    "adminEmail": ""
  },
  "sessionSecret": "$(cat /proc/sys/kernel/random/uuid)"
}
EOF

section "Installing Node.js Dependencies"
# Check if background installation is complete
if ps -p $BACKGROUND_INSTALL_PID > /dev/null; then
  log "Waiting for background installation to complete..."
  wait $BACKGROUND_INSTALL_PID
fi

# Install Node.js dependencies
cd "$INSTALL_DIR"
npm install --production
check "Install Node.js dependencies" "critical"

section "Creating Network Configuration Files"

# Create network configuration script
cat > "$INSTALL_DIR/scripts/setup-network.sh" << 'EOF'
#!/bin/bash

# Network Configuration Script for Howzit Captive Portal
# This script sets up the network configuration for the captive portal

# Source utility functions
SCRIPT_DIR="$(dirname "$0")"
if [ -f "$SCRIPT_DIR/utils.sh" ]; then
  source "$SCRIPT_DIR/utils.sh"
fi

# Configuration
ETHERNET_INTERFACE="eth0"
WIFI_INTERFACE="wlan0"
CAPTIVE_IP="10.0.0.1"
SUBNET_MASK="255.255.0.0"
CONFIG_FILE="$(dirname "$SCRIPT_DIR")/config/default.json"

# Load configuration from JSON file if it exists
if [ -f "$CONFIG_FILE" ]; then
  WIFI_SSID=$(grep -oP '"ssid": *"\K[^"]*' "$CONFIG_FILE")
  WIFI_PASSWORD=$(grep -oP '"password": *"\K[^"]*' "$CONFIG_FILE")
  ETHERNET_INTERFACE=$(grep -oP '"internetInterface": *"\K[^"]*' "$CONFIG_FILE")
  WIFI_INTERFACE=$(grep -oP '"apInterface": *"\K[^"]*' "$CONFIG_FILE")
  CAPTIVE_IP=$(grep -oP '"apIp": *"\K[^"]*' "$CONFIG_FILE")
fi

# Ensure script is run as root
if [ "$(id -u)" -ne 0 ]; then
  echo "This script must be run as root" >&2
  exit 1
fi

echo "Setting up network for Howzit captive portal..."

# 1. Detect network interfaces
echo "Detecting network interfaces..."

# Detect all network interfaces
ALL_INTERFACES=$(ip -o link show | grep -v lo | awk -F': ' '{print $2}')

# Identify USB interfaces (anything that's not eth0 or wlan0)
USB_INTERFACES=""
for interface in $ALL_INTERFACES; do
  if [[ "$interface" != "$WIFI_INTERFACE" && "$interface" != "$ETHERNET_INTERFACE" && "$interface" != "lo" ]]; then
    echo "Detected USB interface: $interface"
    USB_INTERFACES="$USB_INTERFACES $interface"
  fi
done

# 2. Enable IP forwarding
echo "Enabling IP forwarding..."
echo 1 > /proc/sys/net/ipv4/ip_forward
echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/90-ip-forward.conf
sysctl -p /etc/sysctl.d/90-ip-forward.conf

# 3. Configure iptables
echo "Configuring iptables rules..."

# Clear existing rules
iptables -F
iptables -t nat -F
iptables -t mangle -F

# Set default policies
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT

# Allow established and related connections
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Allow traffic on loopback interface
iptables -A INPUT -i lo -j ACCEPT

# Allow traffic to the captive portal web server
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT
iptables -A INPUT -p tcp --dport 3000 -j ACCEPT

# Allow DNS and DHCP
iptables -A INPUT -p udp --dport 53 -j ACCEPT
iptables -A INPUT -p tcp --dport 53 -j ACCEPT
iptables -A INPUT -p udp --dport 67 -j ACCEPT
iptables -A INPUT -p udp --dport 68 -j ACCEPT

# Set up NAT for Ethernet (for internet connectivity)
echo "Setting up NAT for internet connectivity..."
iptables -t nat -A POSTROUTING -o $ETHERNET_INTERFACE -j MASQUERADE

# Create a chain for authenticated clients
echo "Creating authentication chain..."
iptables -t mangle -N AUTHENTICATED
iptables -t mangle -A AUTHENTICATED -j MARK --set-mark 1
iptables -t mangle -A PREROUTING -j AUTHENTICATED

# Set up captive portal redirection for WiFi interface
echo "Setting up captive portal for WiFi interface ($WIFI_INTERFACE)..."
iptables -t nat -A PREROUTING -i $WIFI_INTERFACE -p tcp --dport 80 -m mark ! --mark 1 -j DNAT --to-destination $CAPTIVE_IP:3000
iptables -t nat -A PREROUTING -i $WIFI_INTERFACE -p tcp --dport 443 -m mark ! --mark 1 -j DNAT --to-destination $CAPTIVE_IP:3000

# Set up captive portal redirection for USB interfaces
for usb_if in $USB_INTERFACES; do
  if ip link show $usb_if &>/dev/null; then
    echo "Setting up captive portal for USB interface ($usb_if)..."
    iptables -t nat -A PREROUTING -i $usb_if -p tcp --dport 80 -m mark ! --mark 1 -j DNAT --to-destination $CAPTIVE_IP:3000
    iptables -t nat -A PREROUTING -i $usb_if -p tcp --dport 443 -m mark ! --mark 1 -j DNAT --to-destination $CAPTIVE_IP:3000
  fi
done

# Save iptables rules
echo "Saving iptables rules..."
mkdir -p /etc/iptables
iptables-save > /etc/iptables/rules.v4

# 4. Configure dnsmasq for captive portal
echo "Configuring dnsmasq..."

# Build interface list for dnsmasq
INTERFACE_LIST="$WIFI_INTERFACE"
for usb_if in $USB_INTERFACES; do
  if ip link show $usb_if &>/dev/null; then
    INTERFACE_LIST="$INTERFACE_LIST,$usb_if"
  fi
done

# Create dnsmasq configuration
cat > /etc/dnsmasq.conf << EOL
# Interface configuration
interface=$INTERFACE_LIST
# Explicitly exclude Ethernet
except-interface=$ETHERNET_INTERFACE
bind-interfaces

# DNS configuration
no-resolv
server=8.8.8.8
server=8.8.4.4
domain-needed
bogus-priv

# DHCP configuration - 24 subnets x 200 addresses = 4,800 IP addresses
dhcp-range=10.0.0.2,10.0.0.200,255.255.255.0,30m
dhcp-range=10.0.1.1,10.0.1.200,255.255.255.0,30m
dhcp-range=10.0.2.1,10.0.2.200,255.255.255.0,30m
dhcp-range=10.0.3.1,10.0.3.200,255.255.255.0,30m
dhcp-range=10.0.4.1,10.0.4.200,255.255.255.0,30m
dhcp-range=10.0.5.1,10.0.5.200,255.255.255.0,30m
dhcp-range=10.0.6.1,10.0.6.200,255.255.255.0,30m
dhcp-range=10.0.7.1,10.0.7.200,255.255.255.0,30m
dhcp-range=10.0.8.1,10.0.8.200,255.255.255.0,30m
dhcp-range=10.0.9.1,10.0.9.200,255.255.255.0,30m
dhcp-range=10.0.10.1,10.0.10.200,255.255.255.0,30m
dhcp-range=10.0.11.1,10.0.11.200,255.255.255.0,30m
dhcp-range=10.0.12.1,10.0.12.200,255.255.255.0,30m
dhcp-range=10.0.13.1,10.0.13.200,255.255.255.0,30m
dhcp-range=10.0.14.1,10.0.14.200,255.255.255.0,30m
dhcp-range=10.0.15.1,10.0.15.200,255.255.255.0,30m
dhcp-range=10.0.16.1,10.0.16.200,255.255.255.0,30m
dhcp-range=10.0.17.1,10.0.17.200,255.255.255.0,30m
dhcp-range=10.0.18.1,10.0.18.200,255.255.255.0,30m
dhcp-range=10.0.19.1,10.0.19.200,255.255.255.0,30m
dhcp-range=10.0.20.1,10.0.20.200,255.255.255.0,30m
dhcp-range=10.0.21.1,10.0.21.200,255.255.255.0,30m
dhcp-range=10.0.22.1,10.0.22.200,255.255.255.0,30m
dhcp-range=10.0.23.1,10.0.23.200,255.255.255.0,30m

# Set gateway and DNS server
dhcp-option=3,$CAPTIVE_IP
dhcp-option=6,$CAPTIVE_IP

# Redirect all DNS requests to our captive portal
address=/#/$CAPTIVE_IP

# Optimize performance
cache-size=10000
log-facility=/var/log/dnsmasq.log
EOL

# 5. Configure hostapd for WiFi access point
echo "Configuring hostapd..."

# Create hostapd configuration
cat > /etc/hostapd/hostapd.conf << EOL
# Interface configuration
interface=$WIFI_INTERFACE
driver=nl80211

# Basic settings
ssid=$WIFI_SSID
country_code=US
hw_mode=g
channel=7

# 802.11n settings
ieee80211n=1
wmm_enabled=1
ht_capab=[HT40+][SHORT-GI-40][DSSS_CCK-40]

# Authentication settings
auth_algs=1
macaddr_acl=0
ignore_broadcast_ssid=0
EOL

# Add password configuration if provided
if [ -n "$WIFI_PASSWORD" ]; then
  if [ ${#WIFI_PASSWORD} -lt 8 ]; then
    echo "WARNING: Password is less than 8 characters, this may not work with some clients"
  fi
  
  cat >> /etc/hostapd/hostapd.conf << EOL
# WPA/WPA2 configuration
wpa=2
wpa_passphrase=$WIFI_PASSWORD
wpa_key_mgmt=WPA-PSK
wpa_pairwise=TKIP
rsn_pairwise=CCMP
EOL
  echo "WiFi configured with password protection"
else
  echo "WiFi configured as an open network (no password)"
fi

# Configure hostapd to use this config file
sed -i 's|#DAEMON_CONF=.*|DAEMON_CONF="/etc/hostapd/hostapd.conf"|' /etc/default/hostapd

# 6. Configure network interfaces
echo "Configuring network interfaces..."

# Configure WiFi interface
cat > /etc/network/interfaces.d/wlan0 << EOL
# WiFi interface - Captive portal
allow-hotplug $WIFI_INTERFACE
iface $WIFI_INTERFACE inet static
    address $CAPTIVE_IP
    netmask $SUBNET_MASK
    post-up iptables-restore < /etc/iptables/rules.v4
EOL

# Configure Ethernet interface
cat > /etc/network/interfaces.d/eth0 << EOL
# Ethernet interface - Direct internet
allow-hotplug $ETHERNET_INTERFACE
iface $ETHERNET_INTERFACE inet dhcp
EOL

# Create helper scripts for managing authenticated clients
echo "Creating helper scripts..."

# Script to allow a client to bypass the captive portal
cat > "$INSTALL_DIR/scripts/allow-client.sh" << 'EOL'
#!/bin/bash
# This script adds a client to the authenticated list

if [ $# -ne 1 ]; then
  echo "Usage: $0 <mac_address>"
  exit 1
fi

MAC=$(echo "$1" | tr 'a-z' 'A-Z')
echo "Allowing client $MAC to bypass captive portal"
iptables -t mangle -A AUTHENTICATED -m mac --mac-source "$MAC" -j MARK --set-mark 1
echo "Client $MAC added successfully"
EOL
chmod +x "$INSTALL_DIR/scripts/allow-client.sh"

# Script to list authenticated clients
cat > "$INSTALL_DIR/scripts/list-clients.sh" << 'EOL'
#!/bin/bash
# This script lists all authenticated clients

echo "Authenticated clients:"
iptables-save -t mangle | grep "\-A AUTHENTICATED" | grep -oP "MAC \K([0-9A-F:]{17})" || echo "None found"
EOL
chmod +x "$INSTALL_DIR/scripts/list-clients.sh"

# Script to clear all authenticated clients
cat > "$INSTALL_DIR/scripts/clear-clients.sh" << 'EOL'
#!/bin/bash
# This script clears all authenticated clients

echo "Clearing all authenticated clients..."
iptables -t mangle -F AUTHENTICATED
iptables -t mangle -A AUTHENTICATED -j MARK --set-mark 1
echo "All clients cleared"
EOL
chmod +x "$INSTALL_DIR/scripts/clear-clients.sh"

# Create USB device detection script
echo "Creating USB device detection script..."

cat > "$INSTALL_DIR/scripts/detect-usb.sh" << 'EOL'
#!/bin/bash
# This script detects USB network interfaces and updates the captive portal configuration

LOG_FILE="/var/log/howzit/network.log"
CAPTIVE_IP="10.0.0.1"
ETHERNET_INTERFACE="eth0"
WIFI_INTERFACE="wlan0"

echo "$(date '+%Y-%m-%d %H:%M:%S') - Detecting USB network interfaces..." >> "$LOG_FILE"

# Get all interfaces except lo, eth0 and wlan0
USB_INTERFACES=$(ip -o link show | grep -v "lo\|$ETHERNET_INTERFACE\|$WIFI_INTERFACE" | awk -F': ' '{print $2}')

if [ -z "$USB_INTERFACES" ]; then
  echo "$(date '+%Y-%m-%d %H:%M:%S') - No USB network interfaces detected" >> "$LOG_FILE"
  exit 0
fi

# Update dnsmasq configuration
INTERFACE_LIST="$WIFI_INTERFACE"
for usb_if in $USB_INTERFACES; do
  echo "$(date '+%Y-%m-%d %H:%M:%S') - Found USB interface: $usb_if" >> "$LOG_FILE"
  INTERFACE_LIST="$INTERFACE_LIST,$usb_if"
  
  # Add iptables rules for this interface
  iptables -t nat -A PREROUTING -i $usb_if -p tcp --dport 80 -m mark ! --mark 1 -j DNAT --to-destination $CAPTIVE_IP:3000
  iptables -t nat -A PREROUTING -i $usb_if -p tcp --dport 443 -m mark ! --mark 1 -j DNAT --to-destination $CAPTIVE_IP:3000
done

# Update dnsmasq config
sed -i "s/^interface=.*/interface=$INTERFACE_LIST/" /etc/dnsmasq.conf

# Restart dnsmasq
systemctl restart dnsmasq

echo "$(date '+%Y-%m-%d %H:%M:%S') - Updated configuration for interfaces: $INTERFACE_LIST" >> "$LOG_FILE"
EOL
chmod +x "$INSTALL_DIR/scripts/detect-usb.sh"

# Create udev rule for USB network interfaces
echo "Creating udev rule for USB network interfaces..."

cat > /etc/udev/rules.d/99-howzit-usb-net.rules << EOL
ACTION=="add", SUBSYSTEM=="net", KERNEL!="lo|eth*|wlan*", RUN+="$INSTALL_DIR/scripts/detect-usb.sh"
EOL

echo "Network configuration completed successfully."
echo "WiFi SSID: $WIFI_SSID"
if [ -n "$WIFI_PASSWORD" ]; then
  echo "WiFi Password: $WIFI_PASSWORD"
else
  echo "WiFi is configured as an open network (no password)"
fi
EOF
chmod +x "$INSTALL_DIR/scripts/setup-network.sh"

# Create utility script
cat > "$INSTALL_DIR/scripts/utils.sh" << 'EOF'
#!/bin/bash

# Text colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Log function
log() {
  echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "/var/log/howzit/network.log"
}

# Check command success
check_command() {
  if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ $1${NC}"
    return 0
  else
    echo -e "${RED}✗ $1${NC}"
    return 1
  fi
}
EOF
chmod +x "$INSTALL_DIR/scripts/utils.sh"

section "Setting Up System Service"

# Create systemd service file
cat > /etc/systemd/system/howzit.service << EOF
[Unit]
Description=Howzit Captive Portal
After=network.target dnsmasq.service hostapd.service
Wants=network-online.target
Requires=dnsmasq.service hostapd.service

[Service]
Type=simple
ExecStart=/usr/bin/node $INSTALL_DIR/app.js
WorkingDirectory=$INSTALL_DIR
User=root
Group=root
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
Environment="NODE_ENV=production"
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

# Create service override for dnsmasq
mkdir -p /etc/systemd/system/dnsmasq.service.d/
cat > /etc/systemd/system/dnsmasq.service.d/override.conf << EOF
[Service]
LimitNOFILE=65536
EOF

# Create service override for hostapd
mkdir -p /etc/systemd/system/hostapd.service.d/
cat > /etc/systemd/system/hostapd.service.d/override.conf << EOF
[Service]
LimitNOFILE=65536
EOF

# Create a suitable app.js file optimized for performance
section "Creating Application Files"

# Create core application file
cat > "$INSTALL_DIR/app.js" << 'EOF'
/**
 * Howzit Captive Portal
 * Main application file
 */

const express = require('express');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const passport = require('passport');
const path = require('path');
const fs = require('fs-extra');
const morgan = require('morgan');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const cluster = require('cluster');
const numCPUs = require('os').cpus().length;
const config = require('./config/default.json');
const winston = require('winston');

// Set up logger
const logger = winston.createLogger({
  level: config.system?.logLevel || 