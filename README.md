# Howzit Captive Portal Service
```
 __  __     ______     __     __     ______     __     ______    
/\ \_\ \   /\  __ \   /\ \  _ \ \   /\___  \   /\ \   /\__  _\   
\ \  __ \  \ \ \/\ \  \ \ \/ ".\ \  \/_/  /__  \ \ \  \/_/\ \/   
 \ \_\ \_\  \ \_____\  \ \__/".~\_\   /\_____\  \ \_\    \ \_\   
  \/_/\/_/   \/_____/   \/_/   \/_/   \/_____/   \/_/     \/_/
```

# Howzit Captive Portal

Howzit is a fully-functional captive portal solution designed for environments such as Raspberry Pi-based networks. It intercepts HTTP/HTTPS traffic on a dedicated captive portal interface and displays a customizable splash page. It also leverages DNS overrides and captive portal detection hooks to automatically trigger the portal on mobile devices.

## Features

- **Captive Portal Splash Page:**  
  Displays a customizable registration page and splash screen for users connecting to the captive network.

- **DNS Overrides for Captive Detection:**  
  Configures DNSMasq to override known captive portal detection domains (e.g., `captive.apple.com`, `connectivitycheck.android.com`) so that connected devices are automatically redirected to the portal.

- **Network Interface Configuration:**  
  Configures a designated captive portal interface (default: `eth0`) with a static IP address (`10.69.0.1`) and ensures proper DHCP leasing with a gateway of `10.69.0.1`.

- **IPTables NAT/DNAT & Forwarding:**  
  Sets up iptables rules to NAT outgoing traffic, redirect HTTP/HTTPS traffic to the captive portal, and allow proper forwarding between the captive and internet interfaces.

- **Flask and Waitress Backend:**  
  Uses Flask to serve the captive portal application and Waitress as the production WSGI server.

- **CSV Export & Email Notifications:**  
  Captures registration data, writes it to CSV files, and sends email notifications for registered users.

## Requirements

- A Debian-based system (e.g., Raspbian)
- Root privileges for installation
- The following packages (will be installed by the script if missing):
  - `python3`, `python3-flask`, `python3-pandas`, `python3-matplotlib`
  - `dnsmasq`, `net-tools`, `iptables`, `python3-pip`, `python3-waitress`
- An available captive network interface (default: `eth0`) and an Internet interface (default: `wlan0`)

## Installation

1. **Download the Script:**  
   Copy the `install_howzit.sh` script (version 3.0.0) into your system.

2. **Run the Script as Root:**  
   Execute the script with root privileges:
   ```bash
   sudo bash install_howzit.sh
