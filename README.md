# CrowdSurfer - Howzit Captive Portal

## About

CrowdSurfer's Howzit captive portal is an audience intelligence system designed to run on Raspberry Pi devices. It provides a captive portal WiFi solution for events, collecting valuable user data while offering WiFi access.

## Key Features

- **Captive Portal**: Intercepts web traffic on WiFi and USB-connected devices, redirecting to a registration splash page
- **Multi-Authentication**: Social login (Google, Facebook, Twitter, Apple) and direct form registration
- **High Capacity**: Supports approximately 6,000 concurrent connections with 30-minute lease times
- **Intelligent Routing**: WiFi and USB-connected devices see the captive portal while Ethernet connections bypass it
- **Data Collection**: Captures user information (name, email, ZIP code, etc.) and device metadata
- **Real-time Backups**: Stores data in local CSV with minute-by-minute backups
- **Google Sheets Integration**: Automatically exports data to Google Sheets with event-specific naming
- **Admin Dashboard**: Web interface for configuration, monitoring, and data management
- **Automated Setup**: One-click installation script for fresh Raspberry Pi deployment

## Technical Details

The system is built using:
- Node.js and Express for the web application
- Hostapd for WiFi access point management
- Dnsmasq for DHCP and DNS services
- Iptables for network traffic routing
- SQLite for session storage
- Custom network configuration to handle different interface types

## Deployment

Howzit is designed to be deployed inside "Barney boxes" - custom hardware units that combine a Raspberry Pi with enterprise-grade access points, providing both data collection and WiFi service in a portable package.

## Quick Start

```bash
# Install on a fresh Raspberry Pi
wget -O install-howzit.sh https://raw.githubusercontent.com/drewlentz/CrowdSurfer/main/howzit-raspi/install-howzit.sh
chmod +x install-howzit.sh
sudo ./install-howzit.sh

# Or customize your installation
sudo ./install-howzit.sh --ssid "My Event WiFi" --password "secure123" --event "Summer Festival 2025"
