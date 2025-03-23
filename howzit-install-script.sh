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
npm install --omit=dev --no-fund --no-audit
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

# Create core application file
section "Creating Application Files"
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
  level: config.system?.logLevel || 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.printf(info => `${info.timestamp} ${info.level}: ${info.message}`)
  ),
  transports: [
    new winston.transports.File({ filename: './logs/error.log', level: 'error' }),
    new winston.transports.File({ filename: './logs/howzit.log' })
  ]
});

if (process.env.NODE_ENV !== 'production
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
  level: config.system?.logLevel || 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.printf(info => `${info.timestamp} ${info.level}: ${info.message}`)
  ),
  transports: [
    new winston.transports.File({ filename: './logs/error.log', level: 'error' }),
    new winston.transports.File({ filename: './logs/howzit.log' })
  ]
});

if (process.env.NODE_ENV !== 'production') {
  logger.add(new winston.transports.Console({
    format: winston.format.simple()
  }));
}

// Create basic Express app
const app = express();
const port = process.env.PORT || 3000;

// Set view engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Basic middleware
app.use(morgan('combined', { stream: { write: message => logger.info(message.trim()) } }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(cookieParser());

// Session configuration
app.use(session({
  store: new SQLiteStore({
    db: 'sessions.db',
    dir: './data'
  }),
  secret: config.sessionSecret || 'howzit-secret',
  resave: false,
  saveUninitialized: false,
  cookie: { 
    secure: process.env.NODE_ENV === 'production', 
    maxAge: 24 * 60 * 60 * 1000 
  }
}));

// Initialize Passport
app.use(passport.initialize());
app.use(passport.session());

// Create basic data directories
fs.ensureDirSync(path.join(__dirname, 'data/csv'));
fs.ensureDirSync(path.join(__dirname, 'data/backups'));

// Simplified captive portal middleware
app.use((req, res, next) => {
  // Skip for certain paths
  const skipPaths = ['/admin', '/api', '/css', '/js', '/images', '/login', '/register', '/verify', '/success'];
  for (const path of skipPaths) {
    if (req.path.startsWith(path)) {
      return next();
    }
  }
  
  // Handle special captive portal detection endpoints
  const captiveEndpoints = [
    '/generate_204',         // Android
    '/mobile/status.php',    // misc
    '/ncsi.txt',             // Windows
    '/hotspot-detect.html',  // iOS/MacOS
    '/library/test/success.html', // iOS/MacOS
    '/connectivity-check',   // Firefox
    '/fwlink/'               // Microsoft
  ];
  
  if (captiveEndpoints.some(endpoint => req.path.includes(endpoint))) {
    return res.redirect('/');
  }
  
  // Regular web requests (not targeting the splash page)
  if (req.path !== '/' && req.method === 'GET' && 
      req.headers.accept && req.headers.accept.includes('text/html')) {
    return res.redirect('/');
  }
  
  next();
});

// Sample routes (will be replaced later with proper implementation)
app.get('/', (req, res) => {
  res.render('splash', {
    title: 'Sign in to win!',
    eventName: config.captivePortal.eventName
  });
});

app.get('/register', (req, res) => {
  res.render('register', {
    title: 'Register',
    eventName: config.captivePortal.eventName
  });
});

app.post('/register', (req, res) => {
  // In the full implementation, this would store the data
  // For now, just redirect to success
  res.redirect('/success');
});

app.get('/success', (req, res) => {
  res.render('success', {
    title: 'Thank You!',
    eventName: config.captivePortal.eventName,
    redirectUrl: config.captivePortal.redirectUrl,
    countdown: config.captivePortal.redirectDelay
  });
});

// Admin routes
app.get('/admin', (req, res) => {
  // Basic admin authentication
  const username = req.query.username || '';
  const password = req.query.password || '';
  
  if (username === config.system.adminUsername && password === config.system.adminPassword) {
    res.render('admin', {
      title: 'Admin Dashboard',
      boxName: config.system.boxName,
      config: config
    });
  } else {
    res.render('login', {
      title: 'Admin Login',
      error: req.query.error ? 'Invalid credentials' : null
    });
  }
});

// Special captive portal endpoints
app.get('/generate_204', (req, res) => res.redirect('/'));
app.get('/hotspot-detect.html', (req, res) => res.redirect('/'));
app.get('/library/test/success.html', (req, res) => res.redirect('/'));
app.get('/ncsi.txt', (req, res) => res.redirect('/'));
app.get('/connecttest.txt', (req, res) => res.redirect('/'));
app.get('/fwlink', (req, res) => res.redirect('/'));

// Start the server
app.listen(port, () => {
  logger.info(`Howzit captive portal running on http://localhost:${port}`);
});

// Handle graceful shutdown
process.on('SIGINT', () => {
  logger.info('Shutting down gracefully...');
  process.exit(0);
});
EOF

# Create basic splash page template
mkdir -p "$INSTALL_DIR/views"
cat > "$INSTALL_DIR/views/splash.ejs" << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><%= title %> | <%= eventName %></title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #f5f5f5;
            margin: 0;
            padding: 0;
            display: flex;
            flex-direction: column;
            min-height: 100vh;
        }
        .container {
            max-width: 500px;
            margin: 20px auto;
            padding: 20px;
            background-color: #fff;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
            flex: 1;
        }
        .header {
            text-align: center;
            margin-bottom: 20px;
        }
        .logo {
            max-width: 200px;
            margin-bottom: 15px;
        }
        h1 {
            color: #333;
            font-size: 24px;
            margin: 0 0 10px;
        }
        .social-buttons {
            display: flex;
            flex-direction: column;
            gap: 10px;
            margin: 20px 0;
        }
        .social-button {
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 12px;
            border-radius: 4px;
            color: white;
            font-weight: bold;
            text-decoration: none;
            transition: opacity 0.2s;
        }
        .social-button:hover {
            opacity: 0.9;
        }
        .google {
            background-color: #DB4437;
        }
        .facebook {
            background-color: #4267B2;
        }
        .twitter {
            background-color: #1DA1F2;
        }
        .apple {
            background-color: #000;
        }
        .divider {
            display: flex;
            align-items: center;
            margin: 20px 0;
            color: #666;
        }
        .divider::before, .divider::after {
            content: "";
            flex: 1;
            border-bottom: 1px solid #ddd;
        }
        .divider span {
            padding: 0 10px;
        }
        .btn {
            display: block;
            width: 100%;
            padding: 12px;
            background-color: #3498db;
            color: white;
            border: none;
            border-radius: 4px;
            font-size: 16px;
            font-weight: bold;
            cursor: pointer;
            text-align: center;
            text-decoration: none;
        }
        .btn:hover {
            background-color: #2980b9;
        }
        .footer {
            text-align: center;
            margin-top: 20px;
            font-size: 12px;
            color: #666;
        }
        .terms {
            margin-top: 15px;
            text-align: center;
            font-size: 12px;
            color: #666;
        }
        .terms a {
            color: #3498db;
            text-decoration: none;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <img src="/images/logo.png" alt="<%= eventName %>" class="logo">
            <h1><%= title %></h1>
            <p>Connect to our WiFi and enter for a chance to win!</p>
        </div>

        <div class="social-buttons">
            <a href="/auth/google" class="social-button google">Sign in with Google</a>
            <a href="/auth/facebook" class="social-button facebook">Sign in with Facebook</a>
            <!-- <a href="/auth/twitter" class="social-button twitter">Sign in with Twitter</a> -->
            <!-- <a href="/auth/apple" class="social-button apple">Sign in with Apple</a> -->
        </div>

        <div class="divider"><span>or</span></div>

        <a href="/register" class="btn">Register with Email</a>

        <div class="terms">
            By connecting, you agree to our <a href="/terms">Terms of Service</a> and <a href="/privacy">Privacy Policy</a>
        </div>
    </div>

    <div class="footer">
        <p>Powered by CrowdSurfer</p>
    </div>
</body>
</html>
EOF

# Create register page template
cat > "$INSTALL_DIR/views/register.ejs" << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><%= title %> | <%= eventName %></title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #f5f5f5;
            margin: 0;
            padding: 0;
            display: flex;
            flex-direction: column;
            min-height: 100vh;
        }
        .container {
            max-width: 500px;
            margin: 20px auto;
            padding: 20px;
            background-color: #fff;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
            flex: 1;
        }
        .header {
            text-align: center;
            margin-bottom: 20px;
        }
        .logo {
            max-width: 200px;
            margin-bottom: 15px;
        }
        h1 {
            color: #333;
            font-size: 24px;
            margin: 0 0 10px;
        }
        .form-group {
            margin-bottom: 15px;
        }
        label {
            display: block;
            margin-bottom: 5px;
            font-weight: bold;
        }
        input, select {
            width: 100%;
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 4px;
            font-size: 16px;
        }
        .btn {
            display: block;
            width: 100%;
            padding: 12px;
            background-color: #3498db;
            color: white;
            border: none;
            border-radius: 4px;
            font-size: 16px;
            font-weight: bold;
            cursor: pointer;
            margin-top: 20px;
        }
        .btn:hover {
            background-color: #2980b9;
        }
        .footer {
            text-align: center;
            margin-top: 20px;
            font-size: 12px;
            color: #666;
        }
        .required {
            color: red;
        }
        .back-link {
            display: block;
            text-align: center;
            margin-top: 15px;
            color: #3498db;
            text-decoration: none;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <img src="/images/logo.png" alt="<%= eventName %>" class="logo">
            <h1>Register to Win</h1>
            <p>Please fill out the form below to enter.</p>
        </div>

        <form action="/register" method="post">
            <div class="form-group">
                <label for="firstName">First Name <span class="required">*</span></label>
                <input type="text" id="firstName" name="firstName" required>
            </div>

            <div class="form-group">
                <label for="lastName">Last Name <span class="required">*</span></label>
                <input type="text" id="lastName" name="lastName" required>
            </div>

            <div class="form-group">
                <label for="email">Email Address <span class="required">*</span></label>
                <input type="email" id="email" name="email" required>
            </div>

            <div class="form-group">
                <label for="zipCode">ZIP Code <span class="required">*</span></label>
                <input type="text" id="zipCode" name="zipCode" required>
            </div>

            <div class="form-group">
                <label for="gender">Gender</label>
                <select id="gender" name="gender">
                    <option value="">Select Gender</option>
                    <option value="Male">Male</option>
                    <option value="Female">Female</option>
                    <option value="Other">Other</option>
                    <option value="Prefer not to say">Prefer not to say</option>
                </select>
            </div>

            <div class="form-group">
                <label for="birthday">Birthday <span class="required">*</span></label>
                <input type="date" id="birthday" name="birthday" required>
            </div>

            <button type="submit" class="btn">Submit</button>
        </form>

        <a href="/" class="back-link">← Back to login options</a>
    </div>

    <div class="footer">
        <p>Powered by CrowdSurfer</p>
    </div>
</body>
</html>
EOF

# Create success page template
cat > "$INSTALL_DIR/views/success.ejs" << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><%= title %> | <%= eventName %></title>
    <meta http-equiv="refresh" content="<%= countdown %>;url=<%= redirectUrl %>">
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #f5f5f5;
            margin: 0;
            padding: 0;
            display: flex;
            flex-direction: column;
            min-height: 100vh;
        }
        .container {
            max-width: 500px;
            margin: 20px auto;
            padding: 20px;
            background-color: #fff;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
            flex: 1;
            text-align: center;
        }
        .success-icon {
            font-size: 80px;
            color: #2ecc71;
            margin-bottom: 20px;
        }
        h1 {
            color: #333;
            font-size: 28px;
            margin: 0 0 20px;
        }
        .message {
            font-size: 18px;
            color: #666;
            margin-bottom: 30px;
        }
        .countdown {
            margin-top: 30px;
            padding: 15px;
            background-color: #f8f9fa;
            border-radius: 8px;
        }
        .countdown p {
            margin: 0;
            color: #666;
        }
        .progress-bar {
            height: 10px;
            background-color: #e0e0e0;
            border-radius: 5px;
            margin-top: 10px;
            overflow: hidden;
        }
        .progress-fill {
            height: 100%;
            background-color: #3498db;
            border-radius: 5px;
            width: 0%;
            transition: width 1s linear;
        }
        .footer {
            text-align: center;
            margin-top: 20px;
            font-size: 12px;
            color: #666;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="success-icon">✓</div>
        <h1>Thank You!</h1>
        <div class="message">
            <p>You have been successfully entered to win!</p>
            <p>You can now enjoy free WiFi access.</p>
        </div>

        <div class="countdown">
            <p>You will be redirected in <span id="countdown"><%= countdown %></span> seconds...</p>
            <div class="progress-bar">
                <div class="progress-fill" id="progress"></div>
            </div>
        </div>
    </div>

    <div class="footer">
        <p>Powered by CrowdSurfer</p>
    </div>

    <script>
        // Countdown and progress bar
        const countdown = <%= countdown %>;
        let secondsLeft = countdown;
        const countdownElement = document.getElementById('countdown');
        const progressElement = document.getElementById('progress');
        
        // Set initial progress
        progressElement.style.width = '0%';
        
        // Update every second
        const interval = setInterval(() => {
            secondsLeft--;
            countdownElement.textContent = secondsLeft;
            
            // Update progress bar
            const progress = 100 - ((secondsLeft / countdown) * 100);
            progressElement.style.width = progress + '%';
            
            if (secondsLeft <= 0) {
                clearInterval(interval);
            }
        }, 1000);
    </script>
</body>
</html>
EOF

# Create admin login page template
cat > "$INSTALL_DIR/views/login.ejs" << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Login</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #f5f5f5;
            margin: 0;
            padding: 0;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
        }
        .login-container {
            background-color: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
            width: 350px;
        }
        h1 {
            margin-top: 0;
            text-align: center;
            color: #333;
        }
        .form-group {
            margin-bottom: 15px;
        }
        label {
            display: block;
            margin-bottom: 5px;
            font-weight: bold;
        }
        input {
            width: 100%;
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 4px;
            font-size: 16px;
            box-sizing: border-box;
        }
        .btn {
            width: 100%;
            padding: 12px;
            background-color: #3498db;
            color: white;
            border: none;
            border-radius: 4px;
            font-size: 16px;
            font-weight: bold;
            cursor: pointer;
        }
        .btn:hover {
            background-color: #2980b9;
        }
        .error {
            color: #e74c3c;
            margin-bottom: 15px;
            text-align: center;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <h1>Admin Login</h1>
        
        <% if (error) { %>
            <div class="error"><%= error %></div>
        <% } %>
        
        <form action="/admin" method="get">
            <div class="form-group">
                <label for="username">Username</label>
                <input type="text" id="username" name="username" required>
            </div>
            
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" required>
            </div>
            
            <button type="submit" class="btn">Login</button>
        </form>
    </div>
</body>
</html>
EOF

# Create basic admin dashboard template
cat > "$INSTALL_DIR/views/admin.ejs" << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><%= title %> - <%= boxName %></title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #f5f5f5;
            margin: 0;
            padding: 0;
        }
        .header {
            background-color: #2c3e50;
            color: white;
            padding: 15px 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .header h1 {
            margin: 0;
            font-size: 24px;
        }
        .container {
            max-width: 1200px;
            margin: 20px auto;
            padding: 0 20px;
        }
        .card {
            background-color: white;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
            padding: 20px;
            margin-bottom: 20px;
        }
        .card h2 {
            margin-top: 0;
            border-bottom: 1px solid #eee;
            padding-bottom: 10px;
            color: #333;
        }
        .stats-container {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(250px, 1fr));
            gap: 20px;
        }
        .stat-card {
            background-color: white;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
            padding: 20px;
            text-align: center;
        }
        .stat-card h3 {
            margin-top: 0;
            color: #666;
            font-size: 16px;
        }
        .stat-value {
            font-size: 36px;
            font-weight: bold;
            margin: 10px 0;
            color: #3498db;
        }
        .btn {
            display: inline-block;
            padding: 10px 20px;
            background-color: #3498db;
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            text-decoration: none;
            font-size: 14px;
        }
        .btn:hover {
            background-color: #2980b9;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }
        th, td {
            padding: 12px 15px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        th {
            background-color: #f8f9fa;
            font-weight: bold;
        }
        tr:hover {
            background-color: #f5f5f5;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>Howzit Admin Dashboard - <%= boxName %></h1>
        <div>
            <a href="/" class="btn" target="_blank">View Captive Portal</a>
        </div>
    </div>

    <div class="container">
        <div class="stats-container">
            <div class="stat-card">
                <h3>Registrations</h3>
                <div class="stat-value">0</div>
                <small>Total entries</small>
            </div>
            
            <div class="stat-card">
                <h3>Active Connections</h3>
                <div class="stat-value">0</div>
                <small>Current users</small>
            </div>
            
            <div class="stat-card">
                <h3>WiFi SSID</h3>
                <div class="stat-value" style="font-size: 24px;"><%= config.network.ssid %></div>
                <small><%= config.network.password ? 'Password Protected' : 'Open Network' %></small>
            </div>
            
            <div class="stat-card">
                <h3>System Status</h3>
                <div class="stat-value" style="color: #2ecc71;">Online</div>
                <small>All services running</small>
            </div>
        </div>

        <div class="card">
            <h2>Quick Actions</h2>
            <button class="btn">Download CSV Data</button>
            <button class="btn">Restart Services</button>
            <button class="btn">Clear All Data</button>
        </div>

        <div class="card">
            <h2>Recent Registrations</h2>
            <table>
                <thead>
                    <tr>
                        <th>Date/Time</th>
                        <th>Name</th>
                        <th>Email</th>
                        <th>Source</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td colspan="4">No registrations yet</td>
                    </tr>
                </tbody>
            </table>
        </div>
    </div>
</body>
</html>
EOF

# Create a demo logo
mkdir -p "$INSTALL_DIR/public/images"
cat > "$INSTALL_DIR/public/images/logo.png" << 'EOF'
iVBORw0KGgoAAAANSUhEUgAAAMgAAADICAYAAACtWK6eAAAACXBIWXMAAAsTAAALEwEAmpwYAAAF+mlUWHRYTUw6Y29tLmFkb2JlLnhtcAAAAAAAPD94cGFja2V0IGJlZ2luPSLvu78iIGlkPSJXNU0wTXBDZWhpSHpyZVN6TlRjemtjOWQiPz4gPHg6eG1wbWV0YSB4bWxuczp4PSJhZG9iZTpuczptZXRhLyIgeDp4bXB0az0iQWRvYmUgWE1QIENvcmUgNS42LWMxNDggNzkuMTY0MDM2LCAyMDE5LzA4LzEzLTAxOjA2OjU3ICAgICAgICAiPiA8cmRmOlJERiB4bWxuczpyZGY9Imh0dHA6Ly93d3cudzMub3JnLzE5OTkvMDIvMjItcmRmLXN5bnRheC1ucyMiPiA8cmRmOkRlc2NyaXB0aW9uIHJkZjphYm91dD0iIiB4bWxuczp4bXA9Imh0dHA6Ly9ucy5hZG9iZS5jb20veGFwLzEuMC8iIHhtbG5zOmRjPSJodHRwOi8vcHVybC5vcmcvZGMvZWxlbWVudHMvMS4xLyIgeG1sbnM6cGhvdG9zaG9wPSJodHRwOi8vbnMuYWRvYmUuY29tL3Bob3Rvc2hvcC8xLjAvIiB4bWxuczp4bXBNTT0iaHR0cDovL25zLmFkb2JlLmNvbS94YXAvMS4wL21tLyIgeG1sbnM6c3RFdnQ9Imh0dHA6Ly9ucy5hZG9iZS5jb20veGFwLzEuMC9zVHlwZS9SZXNvdXJjZUV2ZW50IyIgeG1wOkNyZWF0b3JUb29sPSJBZG9iZSBQaG90b3Nob3AgQ0MgMjAxOSAoTWFjaW50b3NoKSIgeG1wOkNyZWF0ZURhdGU9IjIwMjItMDQtMTJUMTU6MjQ6MTcrMDI6MDA
section "Running Network Configuration"
"$INSTALL_DIR/scripts/setup-network.sh"
check "Configure network" "critical"

# Enable and start services
section "Starting Services"
systemctl daemon-reload
systemctl enable hostapd dnsmasq
systemctl start hostapd
check "Start hostapd service"
systemctl start dnsmasq
check "Start dnsmasq service"

systemctl enable howzit.service
systemctl start howzit.service
check "Start Howzit service"

# Configure Nginx as reverse proxy
section "Setting Up Nginx Reverse Proxy"
cat > /etc/nginx/sites-available/howzit << EOF
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    
    server_name _;
    
    location / {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_cache_bypass \$http_upgrade;
    }
}
EOF

ln -sf /etc/nginx/sites-available/howzit /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default
systemctl restart nginx
check "Configure and start Nginx"

section "Optimizing System Performance"
# Increase file limits
cat > /etc/security/limits.d/howzit.conf << EOF
*               soft    nofile          65535
*               hard    nofile          65535
EOF

# Optimize kernel parameters
cat > /etc/sysctl.d/99-howzit-performance.conf << EOF
# Increase maximum open files
fs.file-max = 500000

# Increase TCP connection settings
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 65535
net.ipv4.tcp_max_syn_backlog = 65535

# Increase TCP buffer sizes
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216

# Optimize TCP connection timeouts
net.ipv4.tcp_fin_timeout = 10
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_keepalive_intvl = 15
net.ipv4.tcp_tw_reuse = 1
EOF

sysctl -p /etc/sysctl.d/99-howzit-performance.conf
check "Optimize system performance"

# Create cron job for daily log rotation
cat > /etc/cron.daily/howzit-logs << EOF
#!/bin/bash
find /var/log/howzit -type f -name "*.log" -mtime +7 -delete
find $INSTALL_DIR/logs -type f -name "*.log" -mtime +7 -delete
EOF
chmod +x /etc/cron.daily/howzit-logs

# Installation complete
section "Installation Complete"
echo -e "${GREEN}Howzit captive portal has been successfully installed and configured!${NC}"
echo
echo -e "WiFi SSID: ${YELLOW}$WIFI_SSID${NC}"

if [ -n "$WIFI_PASSWORD" ]; then
    echo -e "WiFi Password: ${YELLOW}$WIFI_PASSWORD${NC}"
else
    echo -e "WiFi configured as an ${YELLOW}open network${NC} (no password)"
fi

echo
echo -e "Admin URL: ${YELLOW}http://10.0.0.1/admin${NC}"
echo -e "Admin Username: ${YELLOW}$ADMIN_USERNAME${NC}"
echo -e "Admin Password: ${YELLOW}$ADMIN_PASSWORD${NC}"
echo
echo -e "Event Name: ${YELLOW}$EVENT_NAME${NC}"
echo
echo -e "${BLUE}To customize social login, visit the admin dashboard.${NC}"
echo -e "${BLUE}Your WiFi network should now be broadcasting.${NC}"
echo

log "Installation completed successfully"
