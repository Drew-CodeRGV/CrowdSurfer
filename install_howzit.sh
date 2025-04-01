#!/bin/bash
# install_howzit.sh
# Version: 1.2.4

set -e

# ASCII Header
cat << "EOF"


██   ██  ██████  ██     ██ ███████ ██ ████████ 
██   ██ ██    ██ ██     ██    ███  ██    ██    
███████ ██    ██ ██  █  ██   ███   ██    ██    
██   ██ ██    ██ ██ ███ ██  ███    ██    ██    
██   ██  ██████   ███ ███  ███████ ██    ██    
                                               
                                               

EOF

echo -e "\n\033[32mHowzit Captive Portal Installation Script - v1.2.4\033[0m\n"

# --- Check for updates from GitHub ---
SCRIPT_URL="https://raw.githubusercontent.com/Drew-CodeRGV/CrowdSurfer/main/install_howzit.sh"
LOCAL_VERSION="1.2.4"

check_for_update() {
  echo "Checking for updates..."
  remote_script=$(curl -fsSL "$SCRIPT_URL" || true)
  remote_version=$(echo "$remote_script" | grep '^# Version:' | awk '{print $3}')
  if [[ "$remote_version" > "$LOCAL_VERSION" ]]; then
    echo -e "\033[33mA newer version ($remote_version) is available. Updating...\033[0m"
    echo "$remote_script" > "$0"
    chmod +x "$0"
    exec "$0" "$@"
  else
    echo "Up-to-date. Proceeding with installation."
  fi
}

check_for_update "$@"

# --- Rollback if previously installed ---
if systemctl is-active --quiet howzit.service; then
  echo -e "\n\033[33mExisting Howzit installation found. Rolling back...\033[0m"
  systemctl stop howzit.service || true
  systemctl disable howzit.service || true
  rm -f /etc/systemd/system/howzit.service
  rm -f /usr/local/bin/howzit.py
  rm -rf /var/www/howzit
  sed -i '/^interface=.*$/d' /etc/dnsmasq.conf || true
  sed -i '/^dhcp-range=.*$/d' /etc/dnsmasq.conf || true
  sed -i '/^dhcp-option=.*$/d' /etc/dnsmasq.conf || true
  iptables -t nat -F
  echo -e "\033[32mRollback complete.\033[0m"
fi

# Step 1: Set default values
DEVICE_NAME="Howzit01"
CP_INTERFACE="eth0"
INTERNET_INTERFACE="wlan0"
CSV_TIMEOUT="300"
CSV_EMAIL="cs@drewlentz.com"
REDIRECT_MODE="original"
FIXED_REDIRECT_URL=""

# Step 2: Prompt for Config
read -p "Device Name [Howzit01]: " input && DEVICE_NAME=${input:-$DEVICE_NAME}
read -p "Captive Portal Interface [eth0]: " input && CP_INTERFACE=${input:-$CP_INTERFACE}
read -p "Internet Interface [wlan0]: " input && INTERNET_INTERFACE=${input:-$INTERNET_INTERFACE}
read -p "CSV Registration Timeout (seconds) [300]: " input && CSV_TIMEOUT=${input:-$CSV_TIMEOUT}
read -p "Email to send CSV [cs@drewlentz.com]: " input && CSV_EMAIL=${input:-$CSV_EMAIL}
echo -e "Redirect Options:
 1) Original URL
 2) Fixed URL
 3) No Redirect"
read -p "Choose Redirect Mode [1]: " input
case $input in
  2)
    REDIRECT_MODE="fixed"
    read -p "Enter fixed redirect URL: " FIXED_REDIRECT_URL
    ;;
  3)
    REDIRECT_MODE="none"
    ;;
  *)
    REDIRECT_MODE="original"
    ;;
esac

# Step 3: Install required packages
apt-get update
apt-get install -y python3 python3-pip dnsmasq net-tools iptables postfix curl
python3 -m venv /opt/howzit-env
source /opt/howzit-env/bin/activate
pip install flask pandas

# Step 4: Setup directories
mkdir -p /var/www/howzit/uploads
mkdir -p /var/www/howzit/data

# Step 5: Write howzit.py
cat << 'EOF' > /usr/local/bin/howzit.py
#!/usr/bin/env python3
print("Starting Howzit Flask app...")
# Flask app code goes here...
EOF

chmod +x /usr/local/bin/howzit.py

# Step 6: Configure network interface
ip link set $CP_INTERFACE up
ip addr flush dev $CP_INTERFACE
ip addr add 10.69.0.1/24 dev $CP_INTERFACE

# Step 7: Configure dnsmasq
cat << EOF > /etc/dnsmasq.conf
interface=$CP_INTERFACE
dhcp-range=10.69.0.10,10.69.0.254,15m
dhcp-option=option:dns-server,8.8.8.8,10.69.0.1
EOF
systemctl restart dnsmasq

# Step 8: iptables forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -F
iptables -t nat -A POSTROUTING -o $INTERNET_INTERFACE -j MASQUERADE
iptables -t nat -A PREROUTING -i $CP_INTERFACE -p tcp --dport 80 -j DNAT --to-destination 10.69.0.1:80
iptables -t nat -A PREROUTING -i $CP_INTERFACE -p tcp --dport 443 -j DNAT --to-destination 10.69.0.1:80

# Step 9: Create systemd service
cat << EOF > /etc/systemd/system/howzit.service
[Unit]
Description=Howzit Captive Portal
After=network.target

[Service]
ExecStartPre=/bin/bash -c '
echo "[Howzit] Waiting for $CP_INTERFACE to come up..."
while true; do
  if ip addr show $CP_INTERFACE | grep -q "inet "; then
    echo "[Howzit] $CP_INTERFACE is ready. Proceeding."
    break
  fi
  echo "[Howzit] Still waiting for $CP_INTERFACE... retrying in 5 seconds."
  sleep 5
done'
ExecStart=/opt/howzit-env/bin/python /usr/local/bin/howzit.py
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reexec
systemctl daemon-reload
systemctl enable howzit.service
systemctl start howzit.service

clear
echo -e "\n\033[32m🎉 Congratulations! Howzit has been installed and started.\033[0m"
echo -e "Access the captive portal at: \033[1mhttp://10.69.0.1\033[0m"
#!/bin/bash
# install_howzit.sh
# Version: 1.2.4

set -e

# ASCII Header
cat << "EOF"
 _    _  ____  _     _ _     _      
| |  | |/ __ \| |   (_) |   | |     
| |__| | |  | | |__  _| |__ | | ___ 
|  __  | |  | | '_ \| | '_ \| |/ _ \
| |  | | |__| | |_) | | |_) | |  __/
|_|  |_|\____/|_.__/|_|_.__/|_|\___|
EOF

echo -e "\n\033[32mHowzit Captive Portal Installation Script - v1.2.4\033[0m\n"

# --- Check for updates from GitHub ---
SCRIPT_URL="https://raw.githubusercontent.com/Drew-CodeRGV/CrowdSurfer/main/install_howzit.sh"
LOCAL_VERSION="1.2.4"

check_for_update() {
  echo "Checking for updates..."
  remote_script=$(curl -fsSL "$SCRIPT_URL" || true)
  remote_version=$(echo "$remote_script" | grep '^# Version:' | awk '{print $3}')
  if [[ "$remote_version" > "$LOCAL_VERSION" ]]; then
    echo -e "\033[33mA newer version ($remote_version) is available. Updating...\033[0m"
    echo "$remote_script" > "$0"
    chmod +x "$0"
    exec "$0" "$@"
  else
    echo "Up-to-date. Proceeding with installation."
  fi
}

check_for_update "$@"

# --- Rollback if previously installed ---
if systemctl is-active --quiet howzit.service; then
  echo -e "\n\033[33mExisting Howzit installation found. Rolling back...\033[0m"
  systemctl stop howzit.service || true
  systemctl disable howzit.service || true
  rm -f /etc/systemd/system/howzit.service
  rm -f /usr/local/bin/howzit.py
  rm -rf /var/www/howzit
  sed -i '/^interface=.*$/d' /etc/dnsmasq.conf || true
  sed -i '/^dhcp-range=.*$/d' /etc/dnsmasq.conf || true
  sed -i '/^dhcp-option=.*$/d' /etc/dnsmasq.conf || true
  iptables -t nat -F
  echo -e "\033[32mRollback complete.\033[0m"
fi

# Step 1: Set default values
DEVICE_NAME="Howzit01"
CP_INTERFACE="eth0"
INTERNET_INTERFACE="wlan0"
CSV_TIMEOUT="300"
CSV_EMAIL="cs@drewlentz.com"
REDIRECT_MODE="original"
FIXED_REDIRECT_URL=""

# Step 2: Prompt for Config
read -p "Device Name [Howzit01]: " input && DEVICE_NAME=${input:-$DEVICE_NAME}
read -p "Captive Portal Interface [eth0]: " input && CP_INTERFACE=${input:-$CP_INTERFACE}
read -p "Internet Interface [wlan0]: " input && INTERNET_INTERFACE=${input:-$INTERNET_INTERFACE}
read -p "CSV Registration Timeout (seconds) [300]: " input && CSV_TIMEOUT=${input:-$CSV_TIMEOUT}
read -p "Email to send CSV [cs@drewlentz.com]: " input && CSV_EMAIL=${input:-$CSV_EMAIL}
echo -e "Redirect Options:
 1) Original URL
 2) Fixed URL
 3) No Redirect"
read -p "Choose Redirect Mode [1]: " input
case $input in
  2)
    REDIRECT_MODE="fixed"
    read -p "Enter fixed redirect URL: " FIXED_REDIRECT_URL
    ;;
  3)
    REDIRECT_MODE="none"
    ;;
  *)
    REDIRECT_MODE="original"
    ;;
esac

# Step 3: Install required packages
apt-get update
apt-get install -y python3 python3-pip dnsmasq net-tools iptables postfix curl
python3 -m venv /opt/howzit-env
source /opt/howzit-env/bin/activate
pip install flask pandas

# Step 4: Setup directories
mkdir -p /var/www/howzit/uploads
mkdir -p /var/www/howzit/data

# Step 5: Write howzit.py
cat << 'EOF' > /usr/local/bin/howzit.py
#!/usr/bin/env python3
print("Starting Howzit Flask app...")
# Flask app code goes here...
EOF

chmod +x /usr/local/bin/howzit.py

# Step 6: Configure network interface
ip link set $CP_INTERFACE up
ip addr flush dev $CP_INTERFACE
ip addr add 10.69.0.1/24 dev $CP_INTERFACE

# Step 7: Configure dnsmasq
cat << EOF > /etc/dnsmasq.conf
interface=$CP_INTERFACE
dhcp-range=10.69.0.10,10.69.0.254,15m
dhcp-option=option:dns-server,8.8.8.8,10.69.0.1
EOF
systemctl restart dnsmasq

# Step 8: iptables forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -F
iptables -t nat -A POSTROUTING -o $INTERNET_INTERFACE -j MASQUERADE
iptables -t nat -A PREROUTING -i $CP_INTERFACE -p tcp --dport 80 -j DNAT --to-destination 10.69.0.1:80
iptables -t nat -A PREROUTING -i $CP_INTERFACE -p tcp --dport 443 -j DNAT --to-destination 10.69.0.1:80

# Step 9: Create systemd service
cat << EOF > /etc/systemd/system/howzit.service
[Unit]
Description=Howzit Captive Portal
After=network.target

[Service]
ExecStartPre=/bin/bash -c '
echo "[Howzit] Waiting for $CP_INTERFACE to come up..."
while true; do
  if ip addr show $CP_INTERFACE | grep -q "inet "; then
    echo "[Howzit] $CP_INTERFACE is ready. Proceeding."
    break
  fi
  echo "[Howzit] Still waiting for $CP_INTERFACE... retrying in 5 seconds."
  sleep 5
done'
ExecStart=/opt/howzit-env/bin/python /usr/local/bin/howzit.py
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reexec
systemctl daemon-reload
systemctl enable howzit.service
systemctl start howzit.service

clear
echo -e "\n\033[32m🎉 Congratulations! Howzit has been installed and started.\033[0m"
echo -e "Access the captive portal at: \033[1mhttp://10.69.0.1\033[0m"
#!/bin/bash
# install_howzit.sh
# Version: 1.2.4

set -e

# ASCII Header
cat << "EOF"

██   ██  ██████  ██     ██ ███████ ██ ████████ 
██   ██ ██    ██ ██     ██    ███  ██    ██    
███████ ██    ██ ██  █  ██   ███   ██    ██    
██   ██ ██    ██ ██ ███ ██  ███    ██    ██    
██   ██  ██████   ███ ███  ███████ ██    ██    
                                               
EOF

echo -e "\n\033[32mHowzit Captive Portal Installation Script - v1.2.4\033[0m\n"

# --- Check for updates from GitHub ---
SCRIPT_URL="https://raw.githubusercontent.com/Drew-CodeRGV/CrowdSurfer/main/install_howzit.sh"
LOCAL_VERSION="1.2.4"

check_for_update() {
  echo "Checking for updates..."
  remote_script=$(curl -fsSL "$SCRIPT_URL" || true)
  remote_version=$(echo "$remote_script" | grep '^# Version:' | awk '{print $3}')
  if [[ "$remote_version" > "$LOCAL_VERSION" ]]; then
    echo -e "\033[33mA newer version ($remote_version) is available. Updating...\033[0m"
    echo "$remote_script" > "$0"
    chmod +x "$0"
    exec "$0" "$@"
  else
    echo "Up-to-date. Proceeding with installation."
  fi
}

check_for_update "$@"

# --- Rollback if previously installed ---
if systemctl is-active --quiet howzit.service; then
  echo -e "\n\033[33mExisting Howzit installation found. Rolling back...\033[0m"
  systemctl stop howzit.service || true
  systemctl disable howzit.service || true
  rm -f /etc/systemd/system/howzit.service
  rm -f /usr/local/bin/howzit.py
  rm -rf /var/www/howzit
  sed -i '/^interface=.*$/d' /etc/dnsmasq.conf || true
  sed -i '/^dhcp-range=.*$/d' /etc/dnsmasq.conf || true
  sed -i '/^dhcp-option=.*$/d' /etc/dnsmasq.conf || true
  iptables -t nat -F
  echo -e "\033[32mRollback complete.\033[0m"
fi

# Step 1: Set default values
DEVICE_NAME="Howzit01"
CP_INTERFACE="eth0"
INTERNET_INTERFACE="wlan0"
CSV_TIMEOUT="300"
CSV_EMAIL="cs@drewlentz.com"
REDIRECT_MODE="original"
FIXED_REDIRECT_URL=""

# Step 2: Prompt for Config
read -p "Device Name [Howzit01]: " input && DEVICE_NAME=${input:-$DEVICE_NAME}
read -p "Captive Portal Interface [eth0]: " input && CP_INTERFACE=${input:-$CP_INTERFACE}
read -p "Internet Interface [wlan0]: " input && INTERNET_INTERFACE=${input:-$INTERNET_INTERFACE}
read -p "CSV Registration Timeout (seconds) [300]: " input && CSV_TIMEOUT=${input:-$CSV_TIMEOUT}
read -p "Email to send CSV [cs@drewlentz.com]: " input && CSV_EMAIL=${input:-$CSV_EMAIL}
echo -e "Redirect Options:
 1) Original URL
 2) Fixed URL
 3) No Redirect"
read -p "Choose Redirect Mode [1]: " input
case $input in
  2)
    REDIRECT_MODE="fixed"
    read -p "Enter fixed redirect URL: " FIXED_REDIRECT_URL
    ;;
  3)
    REDIRECT_MODE="none"
    ;;
  *)
    REDIRECT_MODE="original"
    ;;
esac

# Step 3: Install required packages
apt-get update
apt-get install -y python3 python3-pip dnsmasq net-tools iptables postfix curl
python3 -m venv /opt/howzit-env
source /opt/howzit-env/bin/activate
pip install flask pandas

# Step 4: Setup directories
mkdir -p /var/www/howzit/uploads
mkdir -p /var/www/howzit/data

# Step 5: Write howzit.py
cat << 'EOF' > /usr/local/bin/howzit.py
#!/usr/bin/env python3
print("Starting Howzit Flask app...")
# Flask app code goes here...
EOF

chmod +x /usr/local/bin/howzit.py

# Step 6: Configure network interface
ip link set $CP_INTERFACE up
ip addr flush dev $CP_INTERFACE
ip addr add 10.69.0.1/24 dev $CP_INTERFACE

# Step 7: Configure dnsmasq
cat << EOF > /etc/dnsmasq.conf
interface=$CP_INTERFACE
dhcp-range=10.69.0.10,10.69.0.254,15m
dhcp-option=option:dns-server,8.8.8.8,10.69.0.1
EOF
systemctl restart dnsmasq

# Step 8: iptables forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -F
iptables -t nat -A POSTROUTING -o $INTERNET_INTERFACE -j MASQUERADE
iptables -t nat -A PREROUTING -i $CP_INTERFACE -p tcp --dport 80 -j DNAT --to-destination 10.69.0.1:80
iptables -t nat -A PREROUTING -i $CP_INTERFACE -p tcp --dport 443 -j DNAT --to-destination 10.69.0.1:80

# Step 9: Create systemd service
cat << EOF > /etc/systemd/system/howzit.service
[Unit]
Description=Howzit Captive Portal
After=network.target

[Service]
ExecStartPre=/bin/bash -c '
echo "[Howzit] Waiting for $CP_INTERFACE to come up..."
while true; do
  if ip addr show $CP_INTERFACE | grep -q "inet "; then
    echo "[Howzit] $CP_INTERFACE is ready. Proceeding."
    break
  fi
  echo "[Howzit] Still waiting for $CP_INTERFACE... retrying in 5 seconds."
  sleep 5
done'
ExecStart=/opt/howzit-env/bin/python /usr/local/bin/howzit.py
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reexec
systemctl daemon-reload
systemctl enable howzit.service
systemctl start howzit.service

clear
echo -e "\n\033[32m🎉 Congratulations! Howzit has been installed and started.\033[0m"
echo -e "Access the captive portal at: \033[1mhttp://10.69.0.1\033[0m"
