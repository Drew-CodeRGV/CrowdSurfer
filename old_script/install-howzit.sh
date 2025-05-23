#!/bin/bash

###############################################################
# Howzit Captive Portal Installation Script for Raspberry Pi
# 
# This script installs and configures the Howzit captive portal
# system on a fresh Raspberry Pi installation.
# Traffic from ethernet (eth0) is forwarded to WiFi (wlan0) after authentication.
#
# Usage: sudo bash install-howzit.sh
###############################################################

# Ensure script is run as root
if [ "$(id -u)" -ne 0 ]; then
  echo "This script must be run as root" >&2
  echo "Please run: sudo bash $0" >&2
  exit 1
fi

# Text formatting
BOLD='\033[1m'
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Constants
INSTALL_DIR="/opt/crowdsurfer/howzit"
LOG_DIR="/var/log/howzit"
CONFIG_DIR="/etc/howzit"
DEFAULT_ADMIN_USER="admin"
DEFAULT_ADMIN_PASSWORD="howzit"
ETH_INTERFACE="eth0"
WLAN_INTERFACE="wlan0"

# Function to print section headers
print_section() {
  echo -e "\n${BLUE}${BOLD}$1${NC}"
  echo -e "${BLUE}--------------------------------------------------${NC}"
}

# Function to print status
print_status() {
  if [ $1 -eq 0 ]; then
    echo -e "[ ${GREEN}OK${NC} ] $2"
  else
    echo -e "[${RED}FAIL${NC}] $2"
    if [ "$3" == "critical" ]; then
      echo -e "${RED}Critical error: Installation cannot continue.${NC}"
      exit 1
    fi
  fi
}

# Function to create log message
log_message() {
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_DIR/install.log"
  echo "$1"
}

# Create log directory
mkdir -p "$LOG_DIR"
touch "$LOG_DIR/install.log"

# Display banner
clear
echo -e "${BLUE}${BOLD}"
echo " _   _     ___     _    _    _____   _   _____"
echo "| | | |   / _ \\   | |  | |  |__  /  | | |_   _|"
echo "| |_| |  | | | |  | |  | |    / /   | |   | |"
echo "|  _  |  | | | |  | |/\\| |   / /_   | |   | |"
echo "| | | |  | |_| |  \\  /\\  /  |____| | |   | |"
echo "|_| |_|   \\___/    \\/  \\/          |_|   |_|"
echo -e "${NC}"
echo -e "${BOLD}Captive Portal Installation Script${NC}"
echo -e "This script will install and configure the Howzit captive portal on your Raspberry Pi.\n"
echo -e "This setup will bridge traffic from Ethernet (${ETH_INTERFACE}) to WiFi (${WLAN_INTERFACE}) for Internet access.\n"

# Prompt for user input
read -p "Admin username [${DEFAULT_ADMIN_USER}]: " ADMIN_USER
ADMIN_USER=${ADMIN_USER:-$DEFAULT_ADMIN_USER}

read -s -p "Admin password [${DEFAULT_ADMIN_PASSWORD}]: " ADMIN_PASSWORD
ADMIN_PASSWORD=${ADMIN_PASSWORD:-$DEFAULT_ADMIN_PASSWORD}
echo ""

# Detect network interfaces
if ip link show ${ETH_INTERFACE} >/dev/null 2>&1; then
  echo -e "${GREEN}Ethernet interface ${ETH_INTERFACE} found.${NC}"
else
  echo -e "${YELLOW}Warning: Ethernet interface ${ETH_INTERFACE} not found. Please check your network configuration.${NC}"
  echo -e "Available interfaces:"
  ip -o link show | grep -v "lo:" | awk -F': ' '{print $2}'
  read -p "Enter ethernet interface name: " ETH_INTERFACE
fi

if ip link show ${WLAN_INTERFACE} >/dev/null 2>&1; then
  echo -e "${GREEN}WiFi interface ${WLAN_INTERFACE} found.${NC}"
else
  echo -e "${YELLOW}Warning: WiFi interface ${WLAN_INTERFACE} not found. Please check your network configuration.${NC}"
  echo -e "Available interfaces:"
  ip -o link show | grep -v "lo:" | awk -F': ' '{print $2}'
  read -p "Enter WiFi interface name: " WLAN_INTERFACE
fi

# Confirm installation
echo -e "\n${YELLOW}${BOLD}Installation Summary:${NC}"
echo -e "  - Captive Portal Interface: ${ETH_INTERFACE}"
echo -e "  - Internet Source Interface: ${WLAN_INTERFACE}"
echo -e "  - Admin username: ${ADMIN_USER}"
echo -e "  - Installation directory: ${INSTALL_DIR}"

read -p "Continue with installation? (y/n): " CONFIRM
if [[ ! $CONFIRM =~ ^[Yy]$ ]]; then
  echo "Installation cancelled by user."
  exit 0
fi

# Start installation
print_section "System Update"
log_message "Starting system update..."

apt update
print_status $? "Update package lists"

# Prioritize essential packages first
apt install -y dnsmasq iptables
print_status $? "Install networking packages" "critical"

# Install additional packages
print_section "Installing Dependencies"
log_message "Installing system dependencies..."

apt install -y --no-install-recommends nodejs npm nginx sqlite3 git curl build-essential ca-certificates
print_status $? "Install system dependencies" "critical"

# Check NodeJS version (we need at least v14)
NODE_VERSION=$(node -v 2>/dev/null | cut -d 'v' -f 2 | cut -d '.' -f 1)
if [ -z "$NODE_VERSION" ] || [ "$NODE_VERSION" -lt 14 ]; then
  log_message "NodeJS version is too old or not installed. Installing Node.js 16..."
  curl -fsSL https://deb.nodesource.com/setup_16.x | bash -
  apt install -y nodejs
  print_status $? "Install Node.js 16" "critical"
fi

print_section "Creating Directories"
mkdir -p "$INSTALL_DIR"/{config,data,logs,public/{css,js,images},src,views,scripts}
mkdir -p "$CONFIG_DIR"
print_status $? "Create directory structure"

# Create main application files
print_section "Creating Application Files"

# Create package.json
cat > "$INSTALL_DIR/package.json" << EOL
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
    "express": "^4.17.1",
    "express-session": "^1.17.2",
    "body-parser": "^1.19.0",
    "ejs": "^3.1.6",
    "sqlite3": "^5.0.2",
    "winston": "^3.3.3",
    "moment": "^2.29.1",
    "fs-extra": "^10.0.0",
    "morgan": "^1.10.0",
    "connect-sqlite3": "^0.9.13",
    "cookie-parser": "^1.4.5",
    "uuid": "^8.3.2",
    "helmet": "^4.6.0"
  },
  "devDependencies": {
    "nodemon": "^2.0.15"
  }
}
EOL
print_status $? "Create package.json"

# Create app.js
cat > "$INSTALL_DIR/app.js" << 'EOL'
/**
 * Howzit Captive Portal
 * Main application file
 */

const express = require('express');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const path = require('path');
const fs = require('fs-extra');
const morgan = require('morgan');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const winston = require('winston');
const helmet = require('helmet');
const { v4: uuidv4 } = require('uuid');

// Load configuration
const config = require('./config/config.json');

// Set up logger
const logger = winston.createLogger({
  level: config.logging?.level || 'info',
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

// Create Express app
const app = express();
const port = process.env.PORT || 3000;

// Set view engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Middleware
app.use(helmet({ contentSecurityPolicy: false }));
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

// Create data directory if it doesn't exist
fs.ensureDirSync(path.join(__dirname, 'data'));

// Simplified database module
const db = require('./src/database');
db.init();

// Simplified captive portal middleware
app.use((req, res, next) => {
  // Skip for static assets and certain paths
  const skipPaths = ['/admin', '/api', '/css', '/js', '/images', '/login', '/register', '/profile', '/success'];
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
  
  // Regular web requests not targeting the splash page
  if (req.path !== '/' && req.method === 'GET' && 
      req.headers.accept && req.headers.accept.includes('text/html')) {
    return res.redirect('/');
  }
  
  next();
});

// Basic routes
app.get('/', (req, res) => {
  res.render('splash', {
    config: config.captivePortal
  });
});

app.get('/login', (req, res) => {
  res.render('login', {
    config: config.captivePortal,
    error: null
  });
});

app.post('/login', (req, res) => {
  const { email } = req.body;
  
  if (!email) {
    return res.render('login', { 
      config: config.captivePortal, 
      error: 'Email is required' 
    });
  }
  
  // Create a simple session
  req.session.user = {
    id: uuidv4(),
    email: email,
    loginTime: new Date()
  };
  
  // Redirect to profile page
  res.redirect('/profile');
});

app.get('/profile', (req, res) => {
  if (!req.session.user) {
    return res.redirect('/');
  }
  
  res.render('profile', {
    config: config.captivePortal,
    user: req.session.user,
    error: null
  });
});

app.post('/profile', (req, res) => {
  if (!req.session.user) {
    return res.redirect('/');
  }
  
  const { firstName, lastName, zipCode } = req.body;
  
  if (!firstName || !lastName) {
    return res.render('profile', {
      config: config.captivePortal,
      user: req.session.user,
      error: 'Please fill in required fields'
    });
  }
  
  // Update user data
  req.session.user = {
    ...req.session.user,
    firstName,
    lastName,
    zipCode,
    registrationComplete: true
  };
  
  // Save user to database
  db.saveUser(req.session.user);
  
  // Run the script to allow this device through the captive portal
  const clientIP = req.ip.replace(/^::ffff:/, ''); // Remove IPv6 prefix if present
  require('./src/allow-client')(clientIP);
  
  // Redirect to success page
  res.redirect('/success');
});

app.get('/success', (req, res) => {
  if (!req.session.user || !req.session.user.registrationComplete) {
    return res.redirect('/');
  }
  
  res.render('success', {
    config: config.captivePortal,
    user: req.session.user
  });
});

// Admin routes (simplified)
app.get('/admin', (req, res) => {
  res.render('admin-login');
});

app.post('/admin/login', (req, res) => {
  const { username, password } = req.body;
  
  if (username === config.admin.username && password === config.admin.password) {
    req.session.admin = true;
    res.redirect('/admin/dashboard');
  } else {
    res.render('admin-login', { error: 'Invalid credentials' });
  }
});

app.get('/admin/dashboard', (req, res) => {
  if (!req.session.admin) {
    return res.redirect('/admin');
  }
  
  // Get user data from database
  const users = db.getUsers();
  
  res.render('admin-dashboard', {
    config: config,
    users: users
  });
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
  console.log(`Howzit captive portal running on http://localhost:${port}`);
});
EOL
print_status $? "Create app.js"

# Create database module
mkdir -p "$INSTALL_DIR/src"
cat > "$INSTALL_DIR/src/database.js" << 'EOL'
/**
 * Simple database module for Howzit
 */
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const fs = require('fs');

let db;

function init() {
  const dbDir = path.join(__dirname, '../data');
  if (!fs.existsSync(dbDir)) {
    fs.mkdirSync(dbDir, { recursive: true });
  }
  
  db = new sqlite3.Database(path.join(dbDir, 'howzit.db'));
  
  // Create tables if they don't exist
  db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      email TEXT,
      firstName TEXT,
      lastName TEXT,
      zipCode TEXT,
      macAddress TEXT,
      ipAddress TEXT,
      loginTime TEXT,
      registrationTime TEXT,
      lastSeen TEXT
    )`);
  });
  
  return db;
}

function saveUser(user) {
  if (!db) init();
  
  const now = new Date().toISOString();
  
  db.run(
    `INSERT OR REPLACE INTO users 
    (id, email, firstName, lastName, zipCode, ipAddress, loginTime, registrationTime, lastSeen) 
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      user.id,
      user.email,
      user.firstName,
      user.lastName,
      user.zipCode,
      user.ipAddress,
      user.loginTime ? new Date(user.loginTime).toISOString() : null,
      now,
      now
    ]
  );
}

function getUsers() {
  if (!db) init();
  
  return new Promise((resolve, reject) => {
    db.all('SELECT * FROM users ORDER BY registrationTime DESC', (err, rows) => {
      if (err) {
        reject(err);
        return;
      }
      resolve(rows);
    });
  });
}

function getUserById(id) {
  if (!db) init();
  
  return new Promise((resolve, reject) => {
    db.get('SELECT * FROM users WHERE id = ?', [id], (err, row) => {
      if (err) {
        reject(err);
        return;
      }
      resolve(row);
    });
  });
}

module.exports = {
  init,
  saveUser,
  getUsers,
  getUserById
};
EOL
print_status $? "Create database module"

# Create helper script to allow clients
cat > "$INSTALL_DIR/src/allow-client.js" << 'EOL'
/**
 * Helper script to allow a client through the captive portal
 */
const { exec } = require('child_process');
const path = require('path');

module.exports = function allowClient(ip) {
  // Get MAC address from IP
  exec(`arp -n ${ip} | grep -v Address | awk '{print $3}'`, (error, stdout, stderr) => {
    if (error) {
      console.error(`Error getting MAC address: ${error}`);
      return;
    }
    
    const mac = stdout.trim();
    if (!mac) {
      console.error(`Could not find MAC address for IP: ${ip}`);
      return;
    }
    
    // Call the script to allow the client
    const scriptPath = path.join(__dirname, '../scripts/allow-client.sh');
    exec(`bash ${scriptPath} ${mac}`, (error, stdout, stderr) => {
      if (error) {
        console.error(`Error allowing client: ${error}`);
        return;
      }
      console.log(`Client allowed: ${ip} (${mac})`);
    });
  });
};
EOL
print_status $? "Create allow-client module"

# Create configuration file
mkdir -p "$INSTALL_DIR/config"
cat > "$INSTALL_DIR/config/config.json" << EOL
{
  "admin": {
    "username": "${ADMIN_USER}",
    "password": "${ADMIN_PASSWORD}"
  },
  "captivePortal": {
    "title": "Connect to Network",
    "subtitle": "Sign up to access the internet",
    "eventName": "CrowdSurfer Event",
    "redirectUrl": "https://www.google.com",
    "redirectDelay": 10,
    "logoPath": "/images/logo.png",
    "primaryColor": "#3498db",
    "secondaryColor": "#e74c3c",
    "termsUrl": "/terms.html",
    "privacyUrl": "/privacy.html"
  },
  "network": {
    "ethernetInterface": "${ETH_INTERFACE}",
    "wifiInterface": "${WLAN_INTERFACE}",
    "ipAddress": "10.0.0.1",
    "subnetMask": "255.255.255.0",
    "dhcpRange": "10.0.0.2,10.0.0.254,30m"
  },
  "logging": {
    "level": "info",
    "console": true
  },
  "sessionSecret": "$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1)"
}
EOL
print_status $? "Create configuration file"

# Create network configuration script - UPDATED VERSION with fixes for manual IP and internet bridge
mkdir -p "$INSTALL_DIR/scripts"
cat > "$INSTALL_DIR/scripts/setup-network.sh" << EOL
#!/bin/bash

# Network configuration script for Howzit captive portal
# Internet bridge from Ethernet to WiFi

# Exit on error
set -e

# Configuration values
ETH_INTERFACE="${ETH_INTERFACE}"
WLAN_INTERFACE="${WLAN_INTERFACE}"
AP_IP="10.0.0.1"

# Basic echo function that doesn't rely on any other functions
echo "Starting network configuration..."

# Function to log messages - defined at the very beginning
echo_log() {
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] \$1"
}

echo_log "Initializing network configuration"
echo_log "Ethernet interface: \${ETH_INTERFACE}, WiFi interface: \${WLAN_INTERFACE}"

# Stop services before reconfiguring
echo_log "Stopping network services before reconfiguration..."
systemctl stop dnsmasq || true

# Check if interfaces exist
if ! ip link show \${ETH_INTERFACE} >/dev/null 2>&1; then
  echo_log "ERROR: Ethernet interface \${ETH_INTERFACE} not found! Please check your network configuration."
  exit 1
fi

if ! ip link show \${WLAN_INTERFACE} >/dev/null 2>&1; then
  echo_log "WARNING: WiFi interface \${WLAN_INTERFACE} not found. Internet forwarding won't work."
fi

# Configure IPv4 forwarding
echo_log "Enabling IPv4 forwarding..."
echo 1 > /proc/sys/net/ipv4/ip_forward
echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/99-ipforward.conf
sysctl -p /etc/sysctl.d/99-ipforward.conf

# Set up the ethernet interface with a static IP
echo_log "Setting up ethernet interface with static IP..."
ip addr flush dev \${ETH_INTERFACE}
ip addr add \${AP_IP}/24 dev \${ETH_INTERFACE}
ip link set \${ETH_INTERFACE} up

# Configure dnsmasq for DHCP and DNS
echo_log "Configuring dnsmasq..."
cat > /etc/dnsmasq.conf << EOF
# Configure dnsmasq to listen on specific interface
interface=\${ETH_INTERFACE}
# Explicitly disable listening on WiFi interface
except-interface=\${WLAN_INTERFACE}
# Don't use /etc/resolv.conf
no-resolv
# Use Google DNS server
server=8.8.8.8
server=8.8.4.4
# Set domain for local network
domain=lan
# DHCP range and lease time - simple format with just start and end address
dhcp-range=10.0.0.2,10.0.0.254,30m
# Redirect all domains to captive portal
address=/#/\${AP_IP}
# Set the gateway and DNS server to be the Pi
dhcp-option=3,\${AP_IP}
dhcp-option=6,\${AP_IP}
# Log DHCP transactions
log-dhcp
# Logging
log-queries
# Log to specific file
log-facility=/var/log/dnsmasq.log
# Don't forward short names
domain-needed
# Don't forward addresses in non-routed address spaces
bogus-priv
EOF

# Create persistent interface configuration
echo_log "Creating persistent network configuration..."

if [ -d "/etc/network/interfaces.d" ]; then
    # Debian-style networking with interfaces.d directory
    echo_log "Using Debian-style network configuration..."
    
    mkdir -p /etc/network/interfaces.d
    
    # Configure ethernet interface (static IP)
    cat > /etc/network/interfaces.d/\${ETH_INTERFACE} << EOF
allow-hotplug \${ETH_INTERFACE}
iface \${ETH_INTERFACE} inet static
    address \${AP_IP}
    netmask 255.255.255.0
    network 10.0.0.0
    broadcast 10.0.0.255
EOF

elif [ -f "/etc/dhcpcd.conf" ]; then
    # Newer Raspberry Pi OS uses dhcpcd for network configuration
    echo_log "Using dhcpcd for network configuration..."
    
    # Back up the original config
    cp /etc/dhcpcd.conf /etc/dhcpcd.conf.backup
    
    # Configure static IP for ethernet interface
    cat >> /etc/dhcpcd.conf << EOF
# Configuration added by Howzit installer
# Static IP configuration for ethernet interface
interface \${ETH_INTERFACE}
    static ip_address=\${AP_IP}/24
    nohook wpa_supplicant
EOF

else
    echo_log "Warning: Could not detect network configuration method. Manual configuration may be required."
fi

# Reset all iptables rules to start fresh
echo_log "Resetting iptables chains and rules..."
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X
iptables -t mangle -F
iptables -t mangle -X
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT

# Configure iptables for captive portal and internet forwarding
echo_log "Configuring iptables for captive portal and internet forwarding..."

# Allow established connections
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Allow traffic on loopback
iptables -A INPUT -i lo -j ACCEPT

# Allow SSH (port 22) for remote administration
iptables -A INPUT -p tcp --dport 22 -j ACCEPT

# Allow HTTP (port 80) and HTTPS (port 443) for captive portal
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT

# Allow DNS (port 53) for name resolution
iptables -A INPUT -p udp --dport 53 -j ACCEPT
iptables -A INPUT -p tcp --dport 53 -j ACCEPT

# Allow DHCP (port 67 and 68) for network configuration
iptables -A INPUT -p udp --dport 67:68 -j ACCEPT

# Create captive portal chains
iptables -t nat -N CAPTIVE_PORTAL
iptables -t nat -N AUTHENTICATED

# Redirect HTTP and HTTPS traffic to captive portal
iptables -t nat -A PREROUTING -i \${ETH_INTERFACE} -p tcp --dport 80 -j CAPTIVE_PORTAL
iptables -t nat -A PREROUTING -i \${ETH_INTERFACE} -p tcp --dport 443 -j CAPTIVE_PORTAL

# Configure the CAPTIVE_PORTAL chain to redirect to the portal server
iptables -t nat -A CAPTIVE_PORTAL -p tcp -j DNAT --to-destination \${AP_IP}:3000

# Add the AUTHENTICATED chain - authenticated devices will bypass the captive portal
iptables -t nat -A CAPTIVE_PORTAL -j AUTHENTICATED
iptables -t nat -A AUTHENTICATED -j RETURN

# Set up NAT for forwarding internet from Ethernet to WiFi
if ip link show \${WLAN_INTERFACE} >/dev/null 2>&1; then
    echo_log "Setting up internet forwarding from \${ETH_INTERFACE} to \${WLAN_INTERFACE}..."
    
    # Enable NAT (masquerading) for internet forwarding - THIS IS THE KEY PART
    iptables -t nat -A POSTROUTING -o \${WLAN_INTERFACE} -j MASQUERADE
    
    # Allow forwarded traffic from ethernet to WiFi
    iptables -A FORWARD -i \${ETH_INTERFACE} -o \${WLAN_INTERFACE} -j ACCEPT
    
    # Allow established and related connections back from WiFi to ethernet
    iptables -A FORWARD -i \${WLAN_INTERFACE} -o \${ETH_INTERFACE} -m state --state RELATED,ESTABLISHED -j ACCEPT
    
    echo_log "Internet forwarding set up successfully"
else
    echo_log "Skipping internet forwarding setup - WiFi interface not available"
fi

# Save iptables rules
mkdir -p /etc/iptables
iptables-save > /etc/iptables/rules.v4

# Create script to restore iptables rules on boot
cat > /etc/network/if-up.d/iptables << EOF
#!/bin/sh
iptables-restore < /etc/iptables/rules.v4
exit 0
EOF
chmod +x /etc/network/if-up.d/iptables

# Make sure the ethernet interface is up
echo_log "Ensuring ethernet interface is up..."
ip link set \${ETH_INTERFACE} up

# Enable and start dnsmasq
echo_log "Enabling and starting dnsmasq..."
systemctl enable dnsmasq
systemctl restart dnsmasq || true

# Check if dnsmasq started properly
if systemctl is-active --quiet dnsmasq; then
    echo_log "dnsmasq service started successfully"
else
    echo_log "Warning: dnsmasq service failed to start"
    echo_log "Trying to start dnsmasq manually..."
    
    # Try to start dnsmasq manually with debugging
    killall dnsmasq || true
    sleep 2
    dnsmasq
    
    if pgrep dnsmasq > /dev/null; then
        echo_log "dnsmasq started manually"
    else
        echo_log "Failed to start dnsmasq manually. Check configuration."
    fi
fi

echo_log "Network configuration completed."
exit 0
EOL
chmod +x "$INSTALL_DIR/scripts/setup-network.sh"
print_status $? "Create network setup script"

## Create client authentication script
cat > "$INSTALL_DIR/scripts/allow-client.sh" << 'EOL'
#!/bin/bash

# Script to allow a client to bypass the captive portal

if [ $# -ne 1 ]; then
  echo "Usage: $0 <mac_address>"
  exit 1
fi

MAC=$(echo "$1" | tr 'a-z' 'A-Z')
echo "Adding client $MAC to authenticated list..."

# Remove any existing rule for this MAC to avoid duplicates
iptables -t nat -D AUTHENTICATED -p tcp -m mac --mac-source "$MAC" -j RETURN 2>/dev/null || true

# Add client to the AUTHENTICATED chain
iptables -t nat -A AUTHENTICATED -p tcp -m mac --mac-source "$MAC" -j RETURN

# Save iptables rules
iptables-save > /etc/iptables/rules.v4

echo "Client $MAC has been authenticated."
EOL
chmod +x "$INSTALL_DIR/scripts/allow-client.sh"
print_status $? "Create client authentication script"

# Create service file
cat > "/etc/systemd/system/howzit.service" << EOL
[Unit]
Description=Howzit Captive Portal
After=network.target dnsmasq.service
Wants=dnsmasq.service

[Service]
Type=simple
User=root
WorkingDirectory=${INSTALL_DIR}
ExecStart=/usr/bin/node ${INSTALL_DIR}/app.js
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=howzit

[Install]
WantedBy=multi-user.target
EOL
print_status $? "Create systemd service file"

# Create view templates
print_section "Creating View Templates"

# Create splash page
mkdir -p "$INSTALL_DIR/views"
cat > "$INSTALL_DIR/views/splash.ejs" << 'EOL'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><%= config.title %></title>
    <link rel="stylesheet" href="/css/styles.css">
</head>
<body>
    <div class="container">
        <div class="card">
            <div class="header">
                <img src="<%= config.logoPath %>" alt="Logo" class="logo">
                <h1><%= config.title %></h1>
                <p><%= config.subtitle %></p>
            </div>
            
            <div class="content">
                <p>Welcome to <strong><%= config.eventName %></strong></p>
                <p>Connect to our network by signing in below.</p>
                
                <div class="buttons">
                    <a href="/login" class="button primary">Continue with Email</a>
                </div>
                
                <p class="terms">
                    By connecting, you agree to our <a href="<%= config.termsUrl %>">Terms</a> and <a href="<%= config.privacyUrl %>">Privacy Policy</a>
                </p>
            </div>
        </div>
        
        <div class="footer">
            Powered by <strong>CrowdSurfer</strong>
        </div>
    </div>
</body>
</html>
EOL
print_status $? "Create splash page template"

# Create login page
cat > "$INSTALL_DIR/views/login.ejs" << 'EOL'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - <%= config.title %></title>
    <link rel="stylesheet" href="/css/styles.css">
</head>
<body>
    <div class="container">
        <div class="card">
            <div class="header">
                <img src="<%= config.logoPath %>" alt="Logo" class="logo">
                <h1>Sign In</h1>
                <p>Enter your email to continue</p>
            </div>
            
            <div class="content">
                <% if (error) { %>
                    <div class="error-message"><%= error %></div>
                <% } %>
                
                <form action="/login" method="post">
                    <div class="form-group">
                        <label for="email">Email Address</label>
                        <input type="email" id="email" name="email" required>
                    </div>
                    
                    <button type="submit" class="button primary">Continue</button>
                </form>
                
                <div class="back-link">
                    <a href="/">&larr; Back</a>
                </div>
            </div>
        </div>
        
        <div class="footer">
            Powered by <strong>CrowdSurfer</strong>
        </div>
    </div>
</body>
</html>
EOL
print_status $? "Create login page template"

# Create profile page
cat > "$INSTALL_DIR/views/profile.ejs" << 'EOL'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Complete Profile - <%= config.title %></title>
    <link rel="stylesheet" href="/css/styles.css">
</head>
<body>
    <div class="container">
        <div class="card">
            <div class="header">
                <img src="<%= config.logoPath %>" alt="Logo" class="logo">
                <h1>Complete Your Profile</h1>
                <p>Just a few more details and you'll be connected!</p>
            </div>
            
            <div class="content">
                <% if (error) { %>
                    <div class="error-message"><%= error %></div>
                <% } %>
                
                <form action="/profile" method="post">
                    <div class="form-group">
                        <label for="firstName">First Name <span class="required">*</span></label>
                        <input type="text" id="firstName" name="firstName" required value="<%= user.firstName || '' %>">
                    </div>
                    
                    <div class="form-group">
                        <label for="lastName">Last Name <span class="required">*</span></label>
                        <input type="text" id="lastName" name="lastName" required value="<%= user.lastName || '' %>">
                    </div>
                    
                    <div class="form-group">
                        <label for="zipCode">Zip Code</label>
                        <input type="text" id="zipCode" name="zipCode" value="<%= user.zipCode || '' %>">
                    </div>
                    
                    <div class="checkbox-group">
                        <input type="checkbox" id="termsAgreed" name="termsAgreed" required>
                        <label for="termsAgreed">I agree to the <a href="<%= config.termsUrl %>">Terms of Service</a> and <a href="<%= config.privacyUrl %>">Privacy Policy</a> <span class="required">*</span></label>
                    </div>
                    
                    <button type="submit" class="button primary">Connect</button>
                </form>
            </div>
        </div>
        
        <div class="footer">
            Powered by <strong>CrowdSurfer</strong>
        </div>
    </div>
</body>
</html>
EOL
print_status $? "Create profile page template"

# Create success page
cat > "$INSTALL_DIR/views/success.ejs" << 'EOL'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Connected - <%= config.title %></title>
    <link rel="stylesheet" href="/css/styles.css">
    <meta http-equiv="refresh" content="<%= config.redirectDelay %>; url=<%= config.redirectUrl %>">
</head>
<body>
    <div class="container">
        <div class="card success-card">
            <div class="success-icon">✓</div>
            
            <h1>You're Connected!</h1>
            
            <div class="success-message">
                <p>Thanks, <%= user.firstName %>!</p>
                <p>You are now connected to the internet.</p>
                
                <div class="redirect-message">
                    <p>You will be redirected in <span id="countdown"><%= config.redirectDelay %></span> seconds...</p>
                    
                    <div class="progress-bar">
                        <div class="progress-fill" id="progress-fill"></div>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="footer">
            Powered by <strong>CrowdSurfer</strong>
        </div>
    </div>
    
    <script>
        // Countdown timer
        let seconds = <%= config.redirectDelay %>;
        const countdownElement = document.getElementById('countdown');
        const progressFill = document.getElementById('progress-fill');
        
        const interval = setInterval(() => {
            seconds--;
            if (seconds <= 0) {
                clearInterval(interval);
            } else {
                countdownElement.textContent = seconds;
                const progressWidth = (seconds / <%= config.redirectDelay %>) * 100;
                progressFill.style.width = (100 - progressWidth) + '%';
            }
        }, 1000);
    </script>
</body>
</html>
EOL
print_status $? "Create success page template"

# Create admin login page
cat > "$INSTALL_DIR/views/admin-login.ejs" << 'EOL'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Login</title>
    <link rel="stylesheet" href="/css/styles.css">
</head>
<body>
    <div class="container">
        <div class="card">
            <div class="header">
                <h1>Admin Login</h1>
                <p>Enter your credentials to access the admin dashboard</p>
            </div>
            
            <div class="content">
                <% if (typeof error !== 'undefined' && error) { %>
                    <div class="error-message"><%= error %></div>
                <% } %>
                
                <form action="/admin/login" method="post">
                    <div class="form-group">
                        <label for="username">Username</label>
                        <input type="text" id="username" name="username" required>
                    </div>
                    
                    <div class="form-group">
                        <label for="password">Password</label>
                        <input type="password" id="password" name="password" required>
                    </div>
                    
                    <button type="submit" class="button primary">Login</button>
                </form>
                
                <div class="back-link">
                    <a href="/">&larr; Back to Captive Portal</a>
                </div>
            </div>
        </div>
    </div>
</body>
</html>
EOL
print_status $? "Create admin login page template"

# Create admin dashboard page
cat > "$INSTALL_DIR/views/admin-dashboard.ejs" << 'EOL'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Dashboard</title>
    <link rel="stylesheet" href="/css/admin.css">
</head>
<body>
    <div class="admin-container">
        <header class="admin-header">
            <h1>Howzit Admin Dashboard</h1>
            <div class="admin-actions">
                <a href="/" class="button secondary" target="_blank">View Portal</a>
                <a href="/admin/logout" class="button danger">Logout</a>
            </div>
        </header>
        
        <div class="admin-content">
            <div class="stats-panel">
                <div class="stat-card">
                    <h3>Total Users</h3>
                    <div class="stat-value"><%= users.length %></div>
                </div>
                
                <div class="stat-card">
                    <h3>Ethernet Interface</h3>
                    <div class="stat-value"><%= config.network.ethernetInterface %></div>
                </div>
                
                <div class="stat-card">
                    <h3>WiFi Interface</h3>
                    <div class="stat-value"><%= config.network.wifiInterface %></div>
                </div>
            </div>
            
            <div class="admin-panel">
                <h2>Registered Users</h2>
                
                <table class="data-table">
                    <thead>
                        <tr>
                            <th>Name</th>
                            <th>Email</th>
                            <th>Zip Code</th>
                            <th>Registration Time</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <% if (users.length === 0) { %>
                            <tr>
                                <td colspan="5" class="no-data">No registered users yet</td>
                            </tr>
                        <% } else { %>
                            <% users.forEach(user => { %>
                                <tr>
                                    <td><%= user.firstName %> <%= user.lastName %></td>
                                    <td><%= user.email %></td>
                                    <td><%= user.zipCode || 'N/A' %></td>
                                    <td><%= new Date(user.registrationTime).toLocaleString() %></td>
                                    <td>
                                        <a href="/admin/users/<%= user.id %>" class="button small">View</a>
                                    </td>
                                </tr>
                            <% }) %>
                        <% } %>
                    </tbody>
                </table>
            </div>
            
            <div class="admin-panel">
                <h2>Export Data</h2>
                <p>Download user registration data in CSV format.</p>
                <a href="/admin/export/csv" class="button primary">Export to CSV</a>
            </div>
        </div>
    </div>
</body>
</html>
EOL
print_status $? "Create admin dashboard template"

# Create CSS files
mkdir -p "$INSTALL_DIR/public/css"
cat > "$INSTALL_DIR/public/css/styles.css" << 'EOL'
/* Main CSS for Howzit Captive Portal */
* {
    box-sizing: border-box;
    margin: 0;
    padding: 0;
}

body {
    font-family: 'Arial', sans-serif;
    line-height: 1.6;
    color: #333;
    background-color: #f5f7fa;
    min-height: 100vh;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
}

.container {
    width: 90%;
    max-width: 500px;
    margin: 20px auto;
    display: flex;
    flex-direction: column;
    min-height: 80vh;
}

.card {
    background-color: #fff;
    border-radius: 8px;
    box-shadow: 0 4px 16px rgba(0, 0, 0, 0.1);
    padding: 30px;
    margin-bottom: 20px;
    flex: 1;
}

.header {
    text-align: center;
    margin-bottom: 30px;
}

.logo {
    max-width: 150px;
    margin-bottom: 20px;
}

h1 {
    color: #2c3e50;
    margin-bottom: 10px;
    font-size: 24px;
}

.content {
    margin-bottom: 20px;
}

.form-group {
    margin-bottom: 20px;
}

label {
    display: block;
    margin-bottom: 8px;
    font-weight: bold;
}

input[type="text"],
input[type="email"],
input[type="password"] {
    width: 100%;
    padding: 12px;
    border: 1px solid #ddd;
    border-radius: 4px;
    font-size: 16px;
}

.button {
    display: inline-block;
    padding: 12px 24px;
    background-color: #3498db;
    color: white;
    text-decoration: none;
    border: none;
    border-radius: 4px;
    cursor: pointer;
    font-size: 16px;
    transition: background-color 0.2s;
    text-align: center;
}

.button.primary {
    background-color: #3498db;
    width: 100%;
}

.button.primary:hover {
    background-color: #2980b9;
}

.button.secondary {
    background-color: #95a5a6;
}

.button.danger {
    background-color: #e74c3c;
}

.buttons {
    display: flex;
    flex-direction: column;
    gap: 10px;
    margin: 20px 0;
}

.terms {
    font-size: 12px;
    text-align: center;
    margin-top: 20px;
    color: #7f8c8d;
}

.terms a {
    color: #3498db;
    text-decoration: none;
}

.footer {
    text-align: center;
    color: #7f8c8d;
    padding: 10px;
    font-size: 14px;
}

.error-message {
    color: #e74c3c;
    background-color: #fadbd8;
    padding: 10px;
    border-radius: 4px;
    margin-bottom: 20px;
}

.back-link {
    text-align: center;
    margin-top: 20px;
}

.back-link a {
    color: #3498db;
    text-decoration: none;
}

.checkbox-group {
    margin-bottom: 20px;
}

.checkbox-group label {
    display: inline;
    margin-left: 8px;
}

.required {
    color: #e74c3c;
}

/* Success page styles */
.success-card {
    text-align: center;
}

.success-icon {
    font-size: 60px;
    color: #2ecc71;
    margin-bottom: 20px;
}

.success-message {
    margin: 20px 0;
}

.redirect-message {
    margin-top: 30px;
    padding: 15px;
    background-color: #f8f9fa;
    border-radius: 8px;
}

.progress-bar {
    height: 10px;
    background-color: #ecf0f1;
    border-radius: 5px;
    margin-top: 10px;
    overflow: hidden;
}

.progress-fill {
    height: 100%;
    background-color: #3498db;
    width: 0%;
    transition: width 1s linear;
}

@media (max-width: 768px) {
    .container {
        width: 95%;
    }
    
    .card {
        padding: 20px;
    }
}
EOL
print_status $? "Create main CSS file"

# Create admin CSS file
cat > "$INSTALL_DIR/public/css/admin.css" << 'EOL'
/* Admin Dashboard CSS */
* {
    box-sizing: border-box;
    margin: 0;
    padding: 0;
}

body {
    font-family: 'Arial', sans-serif;
    line-height: 1.6;
    color: #333;
    background-color: #f5f7fa;
}

.admin-container {
    max-width: 1200px;
    margin: 0 auto;
    padding: 20px;
}

.admin-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 20px 0;
    border-bottom: 1px solid #e5e5e5;
    margin-bottom: 30px;
}

.admin-header h1 {
    color: #2c3e50;
    font-size: 24px;
}

.admin-actions {
    display: flex;
    gap: 10px;
}

.button {
    display: inline-block;
    padding: 10px 20px;
    background-color: #3498db;
    color: white;
    text-decoration: none;
    border: none;
    border-radius: 4px;
    cursor: pointer;
    font-size: 14px;
    transition: background-color 0.2s;
}

.button.primary {
    background-color: #3498db;
}

.button.secondary {
    background-color: #95a5a6;
}

.button.danger {
    background-color: #e74c3c;
}

.button.small {
    padding: 6px 12px;
    font-size: 12px;
}

.stats-panel {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(250px, 1fr));
    gap: 20px;
    margin-bottom: 30px;
}

.stat-card {
    background-color: #fff;
    border-radius: 8px;
    box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
    padding: 20px;
    text-align: center;
}

.stat-card h3 {
    color: #7f8c8d;
    font-size: 16px;
    margin-bottom: 10px;
}

.stat-value {
    font-size: 28px;
    font-weight: bold;
    color: #2c3e50;
}

.admin-panel {
    background-color: #fff;
    border-radius: 8px;
    box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
    padding: 20px;
    margin-bottom: 30px;
}

.admin-panel h2 {
    color: #2c3e50;
    margin-bottom: 20px;
    font-size: 20px;
    border-bottom: 1px solid #e5e5e5;
    padding-bottom: 10px;
}

.data-table {
    width: 100%;
    border-collapse: collapse;
}

.data-table th, 
.data-table td {
    padding: 12px 15px;
    text-align: left;
    border-bottom: 1px solid #e5e5e5;
}

.data-table th {
    background-color: #f8f9fa;
    font-weight: bold;
}

.data-table tr:hover {
    background-color: #f8f9fa;
}

.no-data {
    text-align: center;
    color: #7f8c8d;
    padding: 20px;
}

@media (max-width: 768px) {
    .admin-header {
        flex-direction: column;
        gap: 15px;
    }
    
    .stats-panel {
        grid-template-columns: 1fr;
    }
    
    .data-table {
        display: block;
        overflow-x: auto;
    }
}
EOL
print_status $? "Create admin CSS file"

# Create network management utility script
cat > "$INSTALL_DIR/scripts/network-manager.sh" << 'EOL'
#!/bin/bash
#
# Network management utility for Howzit
#

# Source the configuration file
CONFIG_FILE="/opt/crowdsurfer/howzit/config/config.json"
ETH_INTERFACE=$(grep -o '"ethernetInterface": *"[^"]*"' "$CONFIG_FILE" | cut -d'"' -f4)
WLAN_INTERFACE=$(grep -o '"wifiInterface": *"[^"]*"' "$CONFIG_FILE" | cut -d'"' -f4)

# Function to display usage information
show_usage() {
    echo "Howzit Network Management Utility"
    echo "Usage: $0 [command]"
    echo
    echo "Commands:"
    echo "  status              Display network status"
    echo "  restart             Restart network services"
    echo "  fix-eth             Set IP address on ethernet interface"
    echo "  fix-nat             Fix NAT forwarding rules"
    echo "  debug               Run diagnostics and troubleshooting"
    echo
}

# Function to display network status
show_status() {
    echo "=== Network Interface Status ==="
    echo "Ethernet Interface ($ETH_INTERFACE):"
    ip addr show dev $ETH_INTERFACE 2>/dev/null || echo "  Interface not found!"
    echo
    echo "WiFi Interface ($WLAN_INTERFACE):"
    ip addr show dev $WLAN_INTERFACE 2>/dev/null || echo "  Interface not found!"
    echo
    echo "=== Routing Table ==="
    ip route show
    echo
    echo "=== DHCP Server Status ==="
    systemctl status dnsmasq | grep Active
    echo
    echo "=== NAT Forwarding Rules ==="
    iptables -t nat -L POSTROUTING -v -n
    echo
    iptables -L FORWARD -v -n
    echo
    echo "=== Captive Portal Rules ==="
    iptables -t nat -L CAPTIVE_PORTAL -v -n 2>/dev/null || echo "CAPTIVE_PORTAL chain not found"
    echo
    iptables -t nat -L AUTHENTICATED -v -n 2>/dev/null || echo "AUTHENTICATED chain not found"
    echo
}

# Function to restart network services
restart_network() {
    echo "Restarting network services..."
    systemctl restart dnsmasq
    
    # Restart network interface
    echo "Restarting ethernet interface..."
    ip link set $ETH_INTERFACE down
    sleep 2
    ip link set $ETH_INTERFACE up
    
    # Restore iptables rules
    echo "Restoring iptables rules..."
    if [ -f /etc/iptables/rules.v4 ]; then
        iptables-restore < /etc/iptables/rules.v4
    else
        echo "No saved iptables rules found."
    fi
    
    echo "Network services restarted."
}

# Function to fix ethernet IP address
fix_ethernet() {
    echo "Setting static IP on ethernet interface..."
    ip addr flush dev $ETH_INTERFACE
    ip addr add 10.0.0.1/24 dev $ETH_INTERFACE
    ip link set $ETH_INTERFACE up
    echo "IP address set to 10.0.0.1/24 on $ETH_INTERFACE."
    
    echo "Checking DHCP server..."
    systemctl restart dnsmasq
    if systemctl is-active --quiet dnsmasq; then
        echo "DHCP server (dnsmasq) is running."
    else
        echo "Starting DHCP server manually..."
        killall dnsmasq 2>/dev/null || true
        sleep 2
        dnsmasq
        if pgrep dnsmasq > /dev/null; then
            echo "DHCP server started manually."
        else
            echo "Failed to start DHCP server!"
        fi
    fi
}

# Function to fix NAT forwarding rules
fix_nat() {
    echo "Fixing NAT forwarding rules for traffic from Ethernet to WiFi..."
    
    # Enable IP forwarding
    echo 1 > /proc/sys/net/ipv4/ip_forward
    
    # Set up NAT for forwarding from Ethernet to WiFi
    iptables -t nat -F POSTROUTING
    iptables -t nat -A POSTROUTING -o $WLAN_INTERFACE -j MASQUERADE
    
    # Allow forwarded traffic between interfaces
    iptables -F FORWARD
    iptables -A FORWARD -i $ETH_INTERFACE -o $WLAN_INTERFACE -j ACCEPT
    iptables -A FORWARD -i $WLAN_INTERFACE -o $ETH_INTERFACE -m state --state RELATED,ESTABLISHED -j ACCEPT
    
    # Save the rules
    iptables-save > /etc/iptables/rules.v4
    
    echo "NAT forwarding rules have been updated to forward traffic from $ETH_INTERFACE to $WLAN_INTERFACE."
}

# Function to run diagnostics
run_diagnostics() {
    echo "=== Running Howzit Network Diagnostics ==="
    
    echo "1. Checking interfaces..."
    if ip link show $ETH_INTERFACE > /dev/null 2>&1; then
        echo "  Ethernet interface $ETH_INTERFACE exists."
    else
        echo "  ERROR: Ethernet interface $ETH_INTERFACE does not exist!"
        echo "  Available interfaces:"
        ip -o link show | grep -v lo: | awk -F': ' '{print "  - " $2}'
    fi
    
    if ip link show $WLAN_INTERFACE > /dev/null 2>&1; then
        echo "  WiFi interface $WLAN_INTERFACE exists."
    else
        echo "  WARNING: WiFi interface $WLAN_INTERFACE does not exist!"
        echo "  Internet forwarding won't work without WiFi interface."
    fi
    
    echo "2. Checking IP configuration..."
    ETH_IP=$(ip -4 addr show dev $ETH_INTERFACE 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}')
    if [ "$ETH_IP" = "10.0.0.1" ]; then
        echo "  Ethernet IP is correctly set to 10.0.0.1"
    else
        echo "  ERROR: Ethernet IP is $ETH_IP (should be 10.0.0.1)"
        echo "  Run 'sudo howzit network fix-eth' to fix this."
    fi
    
    echo "3. Checking DHCP server..."
    if pgrep dnsmasq > /dev/null; then
        echo "  DHCP server (dnsmasq) is running."
    else
        echo "  ERROR: DHCP server (dnsmasq) is not running!"
        echo "  Run 'sudo systemctl restart dnsmasq' to start it."
    fi
    
    echo "4. Testing dnsmasq configuration..."
    dnsmasq --test 2>&1 | grep -i error && {
        echo "  ERRORS found in dnsmasq configuration!"
    } || echo "  dnsmasq configuration seems valid."
    
    echo "5. Checking IP forwarding..."
    IP_FORWARD=$(cat /proc/sys/net/ipv4/ip_forward)
    if [ "$IP_FORWARD" = "1" ]; then
        echo "  IP forwarding is enabled."
    else
        echo "  ERROR: IP forwarding is disabled!"
        echo "  Run 'sudo echo 1 > /proc/sys/net/ipv4/ip_forward' to enable it."
    fi
    
    echo "6. Checking NAT configuration..."
    NAT_RULES=$(iptables -t nat -L POSTROUTING -n | grep MASQUERADE)
    if [[ $NAT_RULES == *"$WLAN_INTERFACE"* ]]; then
        echo "  NAT is properly configured for forwarding to $WLAN_INTERFACE."
    else
        echo "  WARNING: NAT does not appear to be properly configured for forwarding to WiFi!"
        echo "  Run 'sudo howzit network fix-nat' to fix this."
    fi
    
    echo "7. Checking captive portal chains..."
    if iptables -t nat -L CAPTIVE_PORTAL -n > /dev/null 2>&1; then
        echo "  CAPTIVE_PORTAL chain exists."
    else
        echo "  ERROR: CAPTIVE_PORTAL chain is missing!"
    fi
    
    if iptables -t nat -L AUTHENTICATED -n > /dev/null 2>&1; then
        echo "  AUTHENTICATED chain exists."
    else
        echo "  ERROR: AUTHENTICATED chain is missing!"
    fi
    
    echo "8. Checking network connectivity..."
    if ip link show $WLAN_INTERFACE > /dev/null 2>&1; then
        echo "  Testing WiFi interface connectivity..."
        if ping -c 1 -I $WLAN_INTERFACE 8.8.8.8 > /dev/null 2>&1; then
            echo "  WiFi interface has internet connectivity."
        else
            echo "  WARNING: WiFi interface doesn't have internet connectivity!"
            echo "  Make sure $WLAN_INTERFACE is connected to the internet."
        fi
    fi
    
    echo
    echo "Diagnostics completed."
    echo "For detailed network status, run: sudo howzit network status"
}

# Main execution
case "$1" in
    status)
        show_status
        ;;
    restart)
        restart_network
        ;;
    fix-eth)
        fix_ethernet
        ;;
    fix-nat)
        fix_nat
        ;;
    debug)
        run_diagnostics
        ;;
    *)
        show_usage
        ;;
esac
EOL
chmod +x "$INSTALL_DIR/scripts/network-manager.sh"
print_status $? "Create network management utility"

# Create helper script to set up eth0 IP and forwarding on boot
cat > "$INSTALL_DIR/scripts/network-setup.sh" << EOL
#!/bin/bash

# This script ensures eth0 has the correct IP and forwarding is enabled
# It should be run at boot time

# Set up static IP on ethernet
ip addr flush dev ${ETH_INTERFACE}
ip addr add 10.0.0.1/24 dev ${ETH_INTERFACE}
ip link set ${ETH_INTERFACE} up

# Enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

# Restore iptables rules
if [ -f /etc/iptables/rules.v4 ]; then
    iptables-restore < /etc/iptables/rules.v4
fi

# Restart dnsmasq to ensure it binds to the correct interface
systemctl restart dnsmasq

exit 0
EOL
chmod +x "$INSTALL_DIR/scripts/network-setup.sh"
print_status $? "Create network setup boot script"

# Set up the network boot script to run at startup
cat > "/etc/systemd/system/howzit-network.service" << EOL
[Unit]
Description=Howzit Network Setup
After=network.target
Before=howzit.service dnsmasq.service

[Service]
Type=oneshot
ExecStart=${INSTALL_DIR}/scripts/network-setup.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOL
systemctl daemon-reload
systemctl enable howzit-network.service
print_status $? "Create network boot service"

# Create a simple logo
mkdir -p "$INSTALL_DIR/public/images"
# Simple placeholder logo - this is base64 encoded small image
echo "iVBORw0KGgoAAAANSUhEUgAAAGQAAABkCAYAAABw4pVUAAAABmJLR0QA/wD/AP+gvaeTAAAFEklEQVR4nO2dW2gdRRjHf23UmkRTRaFWsP0hikJVUCu1XkCrIj4JXkAFkRRvKD74oKiIWFAULz4ooiKiVq1K0Ye2JfXWVrSYNlFrvaA1GkuTSJM0bZr8fZiJbJbdc/bM7O45M+f8YEjOzuzMfv+zO9/Mzn4HFEVRFEVRFEVRFEVRlMLSAEwHZgHNWRcmZ0wCrgZmA7MzyHkIeBtoBT4C9mWgITUagc3AQeAv4DTwLfAI0JhhufLAdOA54FfMb3EY2AXcCxRSKMtHwAk8tWRdjoy5nPJGqGxfA5dlJcg3yNrgdWVVgIxoBL5AfqPnDVABuIV4UpaJLJAyG4jfIKVRGLX4G/A7sCcrITlgBvASMJB1QapxJfCnp+CvgcuzEpMTGoEPkf8mxzC9tFwxSj4Bbge+EcqeBG7HdCnVQzYB1yjlLQTeF+Qpeg9NvIPkBeDRiPXrhWrgWSS/yXbgmqTFvEO14HXAyoj1641G4HnCf5PjwF1JiZkKHPcIuQ94HRgbZ6V1wBhgLXAA+W+0BXNLi8VlwF5J4CZgahwV1TFTge3If6vXgItdyN8sKTQI3OGiEsXDHOB3wr/dL8BVUYo+HCiwB5gXpQKlKnOBvwn/ho/4LvRSIFAXMM9nsaVCHxgabQnCvuUj5uJ+e4X/QbTPR511mB6p/Ju+GCbYrAqB8/CfHSnxWEj1b3u/JNBST2CJtO6sC+CB1prEWoLsqCbc/FDg3L9AW4iAkQiF1YCxNYltk8SaESLgiEDY1Dp5qSlwS5AdiYSdCQlc5FhUHmgNnOvKuiBVEGlKJGxvSODekMAsECczgIeAN2wOOh2lUKPNQT2ScDshgbV68lbDdOCbOAr+QRJ7U0jgKyGBLmkA7sMM4u3DPBNpA14C7owp1ybXBdwoib1OENijA2+nMdPSvgN6Kz4/BWwDHsdMPXRBqyshtdRDKplO+b2P4Mc/wDLH5bzTZeFeBhpeC5x/MGR9O06LbFjhqkCvIx+wryH8lrXYUZmbXRXodcTTxohhbm11VOa1rgq0gupTsL2PcQ+7KrNk+LjDW6A/JeETMRNlBsN2Vcd3Cq6aITRDJKGTgN8C5zZUBJU8Xpf4btTZ+D6TY1bG3HovbpDO/JZ0p2SuRX5PWxkQ7KJcAD8DJwlvkPUxlWctsjIvxj8pZizZTeJZgfya7GCaI4ZHZQxd9WGnzHSRrQrS15DQtQn9wFLJ9pGIPaGLjhA7XT0JPYM8gWYxsEtBfjXagYUS//FCQJz7UN2CHGt5HEFwMfAzYXq+oTwH+U9HWpoQj5HmLMbsWhhF5RRHBZkzKeBxKuvXOYW8RH5myjrlcwnnmOG9ZCPA8k7wY0LdngfuRz5bskg9pJT7EL4T2kpKMkJYhpwbsRfxXNIiT9aJwg6EM1N3pqrIJe0I9dlJ+q+SjcJ0xEk1A8DslHW5pBk5Uc3elHX5sAI5L2IbyWdgJsU45CfOva+qiqrIJe8h15Oc9ViGnBuxL1VVrngXub5lT5OLIr6IHIecIDlCek9cikK2i/wPFAaZgvyx93+pqooZ25CfOX+UrioP20J+3Cz/mj+AySJfyfFEyUCnzZMY/2XkkhQzImaE6BgEllN+m6JQTELOkAP4CTMGKxQ3UX4ULnkOkM7/3HTGVOSHiX4uAveigg7M+62LgDcoUu9JURRFURRFURRFURRFUZScch57hBH+M0c1CAAAAABJRU5ErkJggg==" | base64 -d > "$INSTALL_DIR/public/images/logo.png"
print_status $? "Create placeholder logo"

# Create terms and privacy pages
cat > "$INSTALL_DIR/public/terms.html" << 'EOL'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Terms of Service</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 800px;
            margin: 0 auto;
            padding: 20px;
        }
        h1 {
            color: #2c3e50;
        }
        h2 {
            color: #3498db;
            margin-top: 30px;
        }
        a {
            color: #3498db;
        }
        .back-button {
            display: inline-block;
            margin-top: 30px;
            padding: 10px 20px;
            background-color: #3498db;
            color: white;
            text-decoration: none;
            border-radius: 4px;
        }
    </style>
</head>
<body>
    <h1>Terms of Service</h1>
    
    <p>Last Updated: <%= new Date().toLocaleDateString() %></p>
    
    <p>Welcome to our network. By accessing or using our network, you agree to be bound by these Terms of Service.</p>
    
    <h2>1. Acceptance of Terms</h2>
    <p>By using our network service, you agree to these terms. If you do not agree, please do not use the service.</p>
    
    <h2>2. Service Description</h2>
    <p>We provide internet access as a courtesy to our visitors. We do not guarantee availability or speed of the service.</p>
    
    <h2>3. User Conduct</h2>
    <p>When using our service, you agree not to:</p>
    <ul>
        <li>Violate any applicable laws or regulations</li>
        <li>Infringe on intellectual property rights</li>
        <li>Transmit harmful code or malware</li>
        <li>Engage in spamming or other abusive behaviors</li>
        <li>Access unauthorized areas of the network</li>
        <li>Use excessive bandwidth that may negatively impact other users</li>
    </ul>
    
    <h2>4. Data Collection</h2>
    <p>By using our service, you acknowledge that we may collect certain information as outlined in our Privacy Policy.</p>
    
    <h2>5. Limitation of Liability</h2>
    <p>We provide this service "as is" without warranties of any kind. We are not liable for any damages arising from your use of the service.</p>
    
    <h2>6. Termination</h2>
    <p>We reserve the right to terminate your access to the service at any time, for any reason, without notice.</p>
    
    <h2>7. Changes to Terms</h2>
    <p>We may modify these terms at any time. Continued use of the service constitutes acceptance of the modified terms.</p>
    
    <a href="/" class="back-button">Back to Login</a>
</body>
</html>
EOL
print_status $? "Create terms page"

cat > "$INSTALL_DIR/public/privacy.html" << 'EOL'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Privacy Policy</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 800px;
            margin: 0 auto;
            padding: 20px;
        }
        h1 {
            color: #2c3e50;
        }
        h2 {
            color: #3498db;
            margin-top: 30px;
        }
        a {
            color: #3498db;
        }
        .back-button {
            display: inline-block;
            margin-top: 30px;
            padding: 10px 20px;
            background-color: #3498db;
            color: white;
            text-decoration: none;
            border-radius: 4px;
        }
    </style>
</head>
<body>
    <h1>Privacy Policy</h1>
    
    <p>Last Updated: <%= new Date().toLocaleDateString() %></p>
    
    <p>This Privacy Policy describes how we collect, use, and disclose information when you use our network service.</p>
    
    <h2>1. Information We Collect</h2>
    <p>When you use our network service, we may collect:</p>
    <ul>
        <li>Personal information you provide (e.g., name, email)</li>
        <li>Device information (e.g., MAC address, device type)</li>
        <li>Usage information (e.g., connection time, data usage)</li>
        <li>Location data (based on connection point)</li>
    </ul>
    
    <h2>2. How We Use Information</h2>
    <p>We may use the collected information to:</p>
    <ul>
        <li>Provide and maintain the network service</li>
        <li>Improve our service and user experience</li>
        <li>Analyze usage patterns and traffic flow</li>
        <li>Communicate with you about our services</li>
        <li>Comply with legal obligations</li>
    </ul>
    
    <h2>3. Information Sharing</h2>
    <p>We may share information with:</p>
    <ul>
        <li>Service providers who help operate our network</li>
        <li>Law enforcement when required by law</li>
        <li>Business partners (in aggregated, anonymized form)</li>
    </ul>
    
    <h2>4. Data Security</h2>
    <p>We implement reasonable security measures to protect your information. However, no internet transmission is completely secure.</p>
    
    <h2>5. Your Choices</h2>
    <p>You can choose not to provide certain information, but this may limit your ability to use our service.</p>
    
    <h2>6. Changes to Policy</h2>
    <p>We may update this Privacy Policy from time to time. We will notify you of any changes by posting the new policy on this page.</p>
    
    <a href="/" class="back-button">Back to Login</a>
</body>
</html>
EOL
print_status $? "Create privacy page"

# Install Node.js dependencies
print_section "Installing Node.js Dependencies"
cd "$INSTALL_DIR"
npm install --omit=dev
print_status $? "Install Node.js packages" "critical"

# Set up nginx as reverse proxy
print_section "Setting Up Nginx Reverse Proxy"
cat > "/etc/nginx/sites-available/howzit" << EOL
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
EOL

# Enable the site and remove default site
ln -sf /etc/nginx/sites-available/howzit /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default
systemctl restart nginx
print_status $? "Configure Nginx"

# Set up initial network configuration
print_section "Initial Network Configuration"
# Ensure ethernet has the correct IP address
ip addr flush dev "$ETH_INTERFACE"
ip addr add 10.0.0.1/24 dev "$ETH_INTERFACE"
ip link set "$ETH_INTERFACE" up
print_status $? "Set up initial ethernet IP configuration"

# Set up and configure network
print_section "Configuring Network"
"$INSTALL_DIR/scripts/setup-network.sh"
print_status $? "Configure network" "critical"

# Create a simple control script for convenience
cat > "/usr/local/bin/howzit" << 'EOL'
#!/bin/bash

# Howzit Captive Portal Control Script

case "$1" in
    start)
        systemctl start dnsmasq howzit
        echo "Howzit captive portal started"
        ;;
    stop)
        systemctl stop howzit dnsmasq
        echo "Howzit captive portal stopped"
        ;;
    restart)
        systemctl restart dnsmasq howzit
        echo "Howzit captive portal restarted"
        ;;
    status)
        echo "Dnsmasq status:"
        systemctl status dnsmasq | grep Active
        echo "Howzit status:"
        systemctl status howzit | grep Active
        ;;
    logs)
        journalctl -u howzit -n 50
        ;;
    network)
        /opt/crowdsurfer/howzit/scripts/network-manager.sh ${@:2}
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|status|logs|network}"
        echo "For network management options: $0 network help"
        exit 1
        ;;
esac
exit 0
EOL
chmod +x "/usr/local/bin/howzit"
print_status $? "Create control script"

# Configure services to start on boot
print_section "Enabling Services"
systemctl daemon-reload
systemctl enable dnsmasq
systemctl restart dnsmasq
print_status $? "Enable dnsmasq"

systemctl enable howzit.service
systemctl enable howzit-network.service
systemctl start howzit-network.service
systemctl start howzit.service
print_status $? "Start Howzit captive portal"

# Set proper permissions
print_section "Setting Permissions"
chown -R root:root "$INSTALL_DIR"
chmod -R 755 "$INSTALL_DIR"
chmod +x "$INSTALL_DIR/scripts/"*.sh
print_status $? "Set proper permissions"

# System service optimization
print_section "Optimizing System"
# Add swap to improve performance on low-memory Raspberry Pi
if [ ! -f /swapfile ]; then
    echo "Creating swap file to improve performance..."
    dd if=/dev/zero of=/swapfile bs=1M count=512
    chmod 600 /swapfile
    mkswap /swapfile
    swapon /swapfile
    echo "/swapfile swap swap defaults 0 0" >> /etc/fstab
    print_status $? "Create swap file"
fi

# Disable unnecessary services to free up resources
echo "Disabling unnecessary services..."
systemctl disable bluetooth.service 2>/dev/null || true
systemctl disable avahi-daemon.service 2>/dev/null || true
systemctl disable triggerhappy.service 2>/dev/null || true
print_status $? "Disable unnecessary services"

# Installation complete
print_section "Installation Complete"
echo -e "${GREEN}Howzit captive portal has been successfully installed!${NC}"

echo -e "\nCaptive Portal Information:"
echo -e "  ${BOLD}Ethernet Interface:${NC} ${ETH_INTERFACE} (Captive Portal)"
echo -e "  ${BOLD}WiFi Interface:${NC} ${WLAN_INTERFACE} (Internet Source)"
echo -e "  ${BOLD}IP Address:${NC} 10.0.0.1"
echo -e "  ${BOLD}DHCP Range:${NC} 10.0.0.2 - 10.0.0.254"
echo -e "  ${BOLD}Lease Time:${NC} 30 minutes"

echo -e "\nAdmin Access:"
echo -e "  ${BOLD}URL:${NC} http://10.0.0.1/admin"
echo -e "  ${BOLD}Username:${NC} ${ADMIN_USER}"
echo -e "  ${BOLD}Password:${NC} ${ADMIN_PASSWORD}"

echo -e "\nControl Commands:"
echo -e "  ${BOLD}Start:${NC} howzit start"
echo -e "  ${BOLD}Stop:${NC} howzit stop"
echo -e "  ${BOLD}Restart:${NC} howzit restart"
echo -e "  ${BOLD}Status:${NC} howzit status"
echo -e "  ${BOLD}Logs:${NC} howzit logs"
echo -e "  ${BOLD}Network Management:${NC} howzit network"

echo -e "\nNetwork Troubleshooting:"
echo -e "  ${BOLD}Network Status:${NC} howzit network status"
echo -e "  ${BOLD}Fix Ethernet IP:${NC} howzit network fix-eth"
echo -e "  ${BOLD}Fix NAT Rules:${NC} howzit network fix-nat"
echo -e "  ${BOLD}Run Diagnostics:${NC} howzit network debug"

echo -e "\n${BOLD}Note:${NC} Your Raspberry Pi is now configured as a captive portal on the ethernet interface."
echo -e "Traffic from authenticated clients on the ethernet port will be forwarded to the internet through the WiFi connection."

# Optional reboot
echo -e "\n${YELLOW}It's recommended to reboot your Raspberry Pi to ensure all changes take effect.${NC}"
read -p "Would you like to reboot now? (y/n): " REBOOT
if [[ $REBOOT =~ ^[Yy]$ ]]; then
    echo "Rebooting system..."
    reboot
fi
