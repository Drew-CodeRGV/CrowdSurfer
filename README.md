# Howzit Captive Portal Service
```
 __  __     ______     __     __     ______     __     ______    
/\ \_\ \   /\  __ \   /\ \  _ \ \   /\___  \   /\ \   /\__  _\   
\ \  __ \  \ \ \/\ \  \ \ \/ ".\ \  \/_/  /__  \ \ \  \/_/\ \/   
 \ \_\ \_\  \ \_____\  \ \__/".~\_\   /\_____\  \ \_\    \ \_\   
  \/_/\/_/   \/_____/   \/_/   \/_/   \/_____/   \/_/     \/_/
```

Howzit is a captive portal service designed for the Raspberry Pi 4. It automatically sets up a captive portal on the built-in Ethernet (eth0) interface, routes traffic via an attached USB Ethernet adapter (eth1) or WiFi (wlan0), and provides a splash page for event registrations. User information is collected via a form, stored in a CSV file, and emailed after 5 minutes of inactivity. An admin page lets you update the splash header and view statistics with charts.

## Features

- **Automated Installation & Configuration**  
  Installs all necessary system packages and Python dependencies on a fresh Raspberry Pi (Debian-based systems).

- **Network Setup & NAT**  
  Configures eth0 with a static IP (192.168.4.1/24), enables IP forwarding, and sets up NAT with iptables. All HTTP traffic on eth0 is redirected to the captive portal.

- **Captive Portal with Registration Form**  
  Provides a splash page with a customizable header ("Welcome to the event!" by default) and a registration form that collects:
  - First Name
  - Last Name
  - Birthday (YYYY-MM-DD)
  - Zip Code
  - Email
  - Gender

- **CSV Management & Emailing**  
  Saves registrations to a CSV file (named using the current date/hour and a random 4-digit number). After 5 minutes of inactivity, the CSV is emailed to `cs@drewlentz.com`, and a new CSV session starts.

- **Admin Management Page**  
  Accessible at `/admin`, this page allows you to:
  - Update the splash header
  - View the total number of registrations
  - See charts for gender breakdown (pie chart), zip code distribution (bar chart), and age groups (bar chart)
  - Download the CSV file

- **Autostart on Boot**  
  A systemd service ensures that Howzit automatically starts at boot.

## Installation

This repository contains the installation script `install_howzit.sh`. To install and run Howzit on your Raspberry Pi, follow these steps:

1. **Download the Script**

   Clone this repository or download the `install_howzit.sh` file.

2. **Make the Script Executable**

   ```bash
   chmod +x install_howzit.sh
