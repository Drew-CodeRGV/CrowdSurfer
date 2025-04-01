#!/bin/bash
# install_howzit.sh
# Version: 1.1.2

# --- ASCII Header ---
cat << "EOF"
 _   _  _____        __________ _____ _ 
| | | |/ _ \ \      / /__  /_ _|_   _| |
| |_| | | | \ \ /\ / /  / / | |  | | | |
|  _  | |_| |\ V  V /  / /_ | |  | | |_|
|_| |_|\___/  \_/\_/  /____|___| |_| (_)
EOF

echo -e "\n\033[32mHowzit Captive Portal Installation Script - v1.1.2\033[0m\n"

# --- GitHub Script Version Check ---
REMOTE_URL="https://raw.githubusercontent.com/Drew-CodeRGV/CrowdSurfer/main/install_howzit.sh"
SCRIPT_VERSION="1.1.2"
check_for_update() {
  echo "Checking for script updates from GitHub..."
  if ! command -v curl >/dev/null 2>&1; then
    apt-get update && apt-get install -y curl
  fi
  REMOTE_SCRIPT=$(curl -fsSL "$REMOTE_URL")
  REMOTE_VERSION=$(echo "$REMOTE_SCRIPT" | grep '^# Version:' | head -n 1 | awk '{print $3}')
  if [[ "$REMOTE_VERSION" != "$SCRIPT_VERSION" && ! -z "$REMOTE_VERSION" ]]; then
    echo "\033[33mNew version ($REMOTE_VERSION) available. Updating...\033[0m"
    echo "$REMOTE_SCRIPT" > "$0"
    chmod +x "$0"
    exec "$0" "$@"
  else
    echo "\033[32mScript is up-to-date.\033[0m"
  fi
}

check_for_update "$@"

# --- Function: Rollback If Already Installed ---
rollback_if_needed() {
  if [ -f /usr/local/bin/howzit.py ]; then
    echo "\033[33mPrevious Howzit installation detected. Rolling back...\033[0m"
    systemctl stop howzit.service 2>/dev/null
    systemctl disable howzit.service 2>/dev/null
    rm -f /etc/systemd/system/howzit.service
    rm -f /usr/local/bin/howzit.py
    sed -i '/howzit/d' /etc/dnsmasq.conf
    iptables -t nat -F
    echo "\033[32mRollback complete.\033[0m"
  fi
}

# --- Function: Update Status ---
update_status() {
  echo -e "\033[36m[$1/$2]\033[0m $3"
}

# --- Step 1: Rollback ---
TOTAL_STEPS=8
CURRENT_STEP=1
rollback_if_needed
update_status $CURRENT_STEP $TOTAL_STEPS "Rollback completed (if necessary)."
((CURRENT_STEP++))

# --- Step 2: Prompt for Config ---
echo "Configuration Setup:"
read -p "Device Name [Howzit01]: " DEVICE_NAME
DEVICE_NAME=${DEVICE_NAME:-Howzit01}
read -p "Captive Portal Interface [eth0]: " CP_INTERFACE
CP_INTERFACE=${CP_INTERFACE:-eth0}
read -p "Internet Interface [wlan0]: " INTERNET_INTERFACE
INTERNET_INTERFACE=${INTERNET_INTERFACE:-wlan0}
read -p "CSV Registration Timeout in seconds [300]: " CSV_TIMEOUT
CSV_TIMEOUT=${CSV_TIMEOUT:-300}
read -p "Email address to send CSV to [cs@drewlentz.com]: " CSV_EMAIL
CSV_EMAIL=${CSV_EMAIL:-cs@drewlentz.com}
echo "Redirect Options:\n 1) Original requested URL\n 2) Fixed URL\n 3) No Redirect"
read -p "Choose Redirect Mode [1]: " REDIRECT_CHOICE
if [[ "$REDIRECT_CHOICE" == "2" ]]; then
  REDIRECT_MODE="fixed"
  read -p "Enter fixed URL to redirect after registration: " FIXED_REDIRECT_URL
elif [[ "$REDIRECT_CHOICE" == "3" ]]; then
  REDIRECT_MODE="none"
  FIXED_REDIRECT_URL=""
else
  REDIRECT_MODE="original"
  FIXED_REDIRECT_URL=""
fi
update_status $CURRENT_STEP $TOTAL_STEPS "Configuration input captured."
((CURRENT_STEP++))

# --- Step 3: Install Dependencies ---
echo "Installing packages..."
apt-get update
apt-get install -y python3 python3-pip python3-flask python3-pandas python3-matplotlib dnsmasq net-tools iptables postfix
pip3 install adafruit-circuitpython-st7735r pillow
update_status $CURRENT_STEP $TOTAL_STEPS "Dependencies installed."
((CURRENT_STEP++))

# --- Step 4: Assign IP to CP Interface and Configure dnsmasq ---
echo "Assigning static IP to $CP_INTERFACE and configuring dnsmasq..."
ip addr flush dev $CP_INTERFACE
ip addr add 10.69.0.1/24 dev $CP_INTERFACE
ip link set $CP_INTERFACE up
echo "interface=$CP_INTERFACE" >> /etc/dnsmasq.conf
echo "dhcp-range=10.69.0.10,10.69.0.254,15m" >> /etc/dnsmasq.conf
echo "dhcp-option=option:dns-server,8.8.8.8,10.69.0.1" >> /etc/dnsmasq.conf
systemctl restart dnsmasq
update_status $CURRENT_STEP $TOTAL_STEPS "Interface configured and dnsmasq restarted."
((CURRENT_STEP++))

# --- Step 5: Write Howzit Application ---
echo "Writing Howzit Python app..."
mkdir -p /var/www/howzit/uploads
cat << PYTHON_EOF > /usr/local/bin/howzit.py
# Placeholder for full Python app
print("Starting Howzit Flask app...")
PYTHON_EOF
chmod +x /usr/local/bin/howzit.py
update_status $CURRENT_STEP $TOTAL_STEPS "Howzit Python app created."
((CURRENT_STEP++))

# --- Step 6: Create systemd Service ---
cat << EOF > /etc/systemd/system/howzit.service
[Unit]
Description=Howzit Captive Portal
After=network.target

[Service]
ExecStart=/usr/bin/python3 /usr/local/bin/howzit.py
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable howzit.service
update_status $CURRENT_STEP $TOTAL_STEPS "Systemd service created."
((CURRENT_STEP++))

# --- Step 7: Firewall + Routing ---
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -F
iptables -t nat -A POSTROUTING -o $INTERNET_INTERFACE -j MASQUERADE
iptables -t nat -A PREROUTING -i $CP_INTERFACE -p tcp --dport 80 -j DNAT --to-destination 10.69.0.1:80
iptables -t nat -A PREROUTING -i $CP_INTERFACE -p tcp --dport 443 -j DNAT --to-destination 10.69.0.1:80
update_status $CURRENT_STEP $TOTAL_STEPS "iptables and routing set."
((CURRENT_STEP++))

# --- Step 8: Launch Service ---
systemctl start howzit.service
update_status $CURRENT_STEP $TOTAL_STEPS "Howzit started and ready."
echo -e "\n\033[32mInstallation complete. Visit http://10.69.0.1 to test.\033[0m"
