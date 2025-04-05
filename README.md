# Howzit Captive Portal Service
```
 __  __     ______     __     __     ______     __     ______    
/\ \_\ \   /\  __ \   /\ \  _ \ \   /\___  \   /\ \   /\__  _\   
\ \  __ \  \ \ \/\ \  \ \ \/ ".\ \  \/_/  /__  \ \ \  \/_/\ \/   
 \ \_\ \_\  \ \_____\  \ \__/".~\_\   /\_____\  \ \_\    \ \_\   
  \/_/\/_/   \/_____/   \/_/   \/_/   \/_____/   \/_/     \/_/
```

# Howzit Captive Portal System

![Howzit Logo](https://github.com/Drew-CodeRGV/CrowdSurfer/raw/main/logo.png)

A lightweight, customizable captive portal solution for Raspberry Pi devices. Perfect for events, conferences, and temporary public Wi-Fi setups with user data collection.

## 🌟 Features

- **Easy to Deploy**: Simple bash installation script for Raspberry Pi
- **User Data Collection**: Collect visitor information through customizable registration forms
- **CSV Export**: Automatically collect and email registration data
- **Customizable Splash Page**: Easily modify the appearance of your portal
- **Logo Upload**: Add your own branding through the admin interface
- **Auto-Update System**: Templates automatically update from GitHub
- **Flexible Redirection**: Configure where users go after registration
- **MAC Address Tracking**: Associate registrations with device MAC addresses
- **Automatic Exemptions**: Once registered, devices can freely access the internet

## 📋 Components

### Core System

- **install_howzit.sh** - Main installation script that sets up the captive portal
- **howzit.py** - Python Flask application that handles the portal functionality
- **splash.html** - Template for the captive portal registration page
- **admin.html** - Template for the administrator dashboard

### Auto-Update System

- **howzit_heartbeat.sh** - Script that checks for template updates on GitHub
- **update_local_files.sh** - Script for manually updating templates from local files

## 🔧 Installation

### Prerequisites

- Raspberry Pi (any model with two network interfaces)
- Raspbian OS (or other Debian-based Linux)
- Internet connection for the installation process

### Quick Install

```bash
# Download the installation script
curl -O https://raw.githubusercontent.com/Drew-CodeRGV/CrowdSurfer/main/install_howzit.sh

# Make it executable
chmod +x install_howzit.sh

# Run the installation
sudo ./install_howzit.sh
```

### Connecting Your Hardware

1. Connect your Raspberry Pi to the internet via Wi-Fi (typically `wlan0`)
2. Connect an Ethernet cable or secondary Wi-Fi adapter (for the captive portal network)

## ⚙️ Configuration

During installation, you'll be prompted to configure:

- Device name
- Captive portal interface (the interface that clients will connect to)
- Internet interface (the interface connected to the internet)
- CSV timeout (how often to email collected data)
- Email address to receive CSV data
- Redirect mode (where to send users after registration)

## 👩‍💻 Administration

Access the admin panel by navigating to `http://10.69.0.1/admin` from a device connected to the captive portal network.

From the admin panel you can:
- Change the portal header text
- Upload a custom logo
- Change redirect settings
- Download collected registration data
- Revoke device exemptions
- View system status

## 🔄 Auto-Update System

The auto-update system automatically checks GitHub for updated templates and installs them without manual intervention:

```bash
# Install the auto-update system
sudo ./install_heartbeat.sh
```

Once installed, the system will:
- Check for template updates every 6 minutes
- Start automatically on boot
- Update templates when changes are detected on GitHub
- Display update status in the admin panel

## 🖼️ Customizing Templates

You can customize the portal by modifying the HTML templates:

1. Fork this repository
2. Modify `splash.html` and `admin.html` to your liking
3. Update the `GITHUB_RAW_URL` variable in `howzit_heartbeat.sh` to point to your repository
4. Push changes to your repository to update all deployed portals

## 📊 Data Collection

The system collects the following information from users:
- First Name
- Last Name
- Birthday
- Zip Code
- Email Address
- Gender
- MAC Address
- Registration Date/Time

This data is stored in CSV format and can be:
- Downloaded from the admin panel
- Automatically emailed at configurable intervals

## 🛠️ Troubleshooting

### View Service Status

```bash
# Check the main service status
sudo systemctl status howzit.service

# Check the auto-update service status
sudo systemctl status howzit-heartbeat.timer
```

### View Logs

```bash
# Main service logs
sudo journalctl -u howzit.service

# Auto-update logs
sudo tail -f /var/log/howzit_heartbeat.log
```

### Manual Template Update

```bash
# Place updated templates in the current directory, then run:
sudo /usr/local/bin/update_howzit.sh
```

## 🔒 Security Considerations

- This system is designed for temporary deployments and public Wi-Fi scenarios
- The admin interface is not password protected by default
- Consider adding authentication for production use
- User data is stored locally and can be accessed by anyone with admin access

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 👏 Acknowledgements

- Built with Flask, a lightweight WSGI web application framework
- Uses dnsmasq for DHCP and DNS services
- Uses iptables for network traffic management
- Developed by CodeRGV community members


