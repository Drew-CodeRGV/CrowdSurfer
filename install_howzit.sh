#!/bin/bash
# install_howzit.sh
# Version: 3.0.2

# ==============================
# ASCII Header
# ==============================
ascii_header=" _                       _ _   _ 
| |__   _____      _____(_) |_| |
| '_ \ / _ \ \ /\ / /_  / | __| |
| | | | (_) \ V  V / / /| | |_|_|
|_| |_|\___/ \_/\_/ /___|_|\__(_)"
echo "$ascii_header"
echo -e "\n\033[32mHowzit Captive Portal Installation Script - Version 3.0.2\033[0m\n"

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
      apt-get install -y "$pkg"
    fi
  done
}

configure_dnsmasq() {
  sed -i '/^dhcp-range=/d' /etc/dnsmasq.conf
  sed -i '/^interface=/d' /etc/dnsmasq.conf
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
  systemctl restart dnsmasq
}

configure_captive_interface() {
  # Flush and assign static IP to captive portal interface
  ip addr flush dev "${CP_INTERFACE}"
  ip addr add 10.69.0.1/24 dev "${CP_INTERFACE}"
  ip link set "${CP_INTERFACE}" up
}

# ==============================
# Copy Local Templates Function
# ==============================
copy_templates() {
  local tpl_dir="/usr/local/bin/templates"
  mkdir -p "$tpl_dir"
  if [ -f "splash.html" ]; then
    cp splash.html "$tpl_dir/"
    echo "Copied splash.html to $tpl_dir"
  else
    echo "Warning: splash.html not found in current directory."
  fi
  if [ -f "admin.html" ]; then
    cp admin.html "$tpl_dir/"
    echo "Copied admin.html to $tpl_dir"
  else
    echo "Warning: admin.html not found in current directory."
  fi
}

# ==============================
# Total Steps
# ==============================
TOTAL_STEPS=11
CURRENT_STEP=1

# ==============================
# Section: Rollback Routine
# ==============================
print_section_header "Rollback Routine"
if [ -f /usr/local/bin/howzit.py ]; then
  echo -e "\033[33mExisting Howzit installation detected. Rolling back...\033[0m"
  systemctl stop howzit.service 2>/dev/null
  systemctl disable howzit.service 2>/dev/null
  rm -f /etc/systemd/system/howzit.service /usr/local/bin/howzit.py
  sed -i "\|^interface=${CP_INTERFACE}\$|d" /etc/dnsmasq.conf
  sed -i "\|^dhcp-range=10\.69\.0\.10,10\.69\.0\.254,15m\$|d" /etc/dnsmasq.conf
  sed -i "\|^dhcp-option=option:router,10\.69\.0\.1\$|d" /etc/dnsmasq.conf
  sed -i "\|^dhcp-option=option:dns-server,8\.8\.8\.8,10\.69\.0\.1\$|d" /etc/dnsmasq.conf
  sed -i "\|^address=/captive.apple.com/10\.69\.0\.1\$|d" /etc/dnsmasq.conf
  sed -i "\|^address=/www.apple.com/library/test/success.html/10\.69\.0\.1\$|d" /etc/dnsmasq.conf
  sed -i "\|^address=/connectivitycheck.android.com/10\.69\.0\.1\$|d" /etc/dnsmasq.conf
  sed -i "\|^address=/clients3.google.com/generate_204/10\.69\.0\.1\$|d" /etc/dnsmasq.conf
  systemctl restart dnsmasq
  /sbin/iptables -t nat -F
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
SCRIPT_VERSION="3.0.0"
check_for_update() {
  if ! command -v curl >/dev/null 2>&1; then
    apt-get update && apt-get install -y curl
  fi
  REMOTE_SCRIPT=$(curl -fsSL "$REMOTE_URL")
  REMOTE_VERSION=$(echo "$REMOTE_SCRIPT" | grep '^SCRIPT_VERSION=' | head -n 1 | cut -d'=' -f2 | tr -d '"')
  if [ -n "$REMOTE_VERSION" ] && [ "$REMOTE_VERSION" != "$SCRIPT_VERSION" ]; then
    echo "New version available: $REMOTE_VERSION (current: $SCRIPT_VERSION)"
    read -p "Download and install new version automatically? (y/n) [y]: " update_choice
    update_choice=${update_choice:-y}
    if [[ "$update_choice" =~ ^[Yy]$ ]]; then
      NEW_SCRIPT="/tmp/install_howzit.sh.new"
      curl -fsSL "$REMOTE_URL" -o "$NEW_SCRIPT"
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
echo "  Redirect Mode:            $REDIRECT_MODE"
[ "$REDIRECT_MODE" == "fixed" ] && echo "  Fixed Redirect URL:                $FIXED_REDIRECT_URL"
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
apt-get update
echo
