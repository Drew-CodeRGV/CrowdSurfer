# howzit_qr.py
import qrcode
import io
import base64
from flask import Flask, render_template

app = Flask(__name__)

def generate_wifi_qr_code(ssid, password=None, security_type="WPA"):
    """
    Generate a QR code for WiFi connection
    
    Parameters:
    ssid (str): The name of the WiFi network
    password (str, optional): The password for the WiFi network. Default is None for open networks.
    security_type (str): The security type of the network. Options are "WPA", "WEP", or "" for none.
    
    Returns:
    str: Base64 encoded string of the QR code image
    """
    if password:
        # Format: WIFI:S:<SSID>;T:<Security type>;P:<Password>;;
        wifi_config = f"WIFI:S:{ssid};T:{security_type};P:{password};;"
    else:
        # For open networks without a password
        wifi_config = f"WIFI:S:{ssid};T:;P:;;"
    
    # Create QR code instance
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    
    # Add data to QR code
    qr.add_data(wifi_config)
    qr.make(fit=True)
    
    # Create an image from the QR code
    img = qr.make_image(fill_color="black", back_color="white")
    
    # Save image to a bytes buffer
    buffer = io.BytesIO()
    img.save(buffer)
    
    # Convert to base64 for embedding in HTML
    img_str = base64.b64encode(buffer.getvalue()).decode('utf-8')
    
    return img_str

@app.route('/')
def display_qr_code():
    # Network information - customize as needed
    network_name = "CrowdSurfer WiFi"
    network_password = "your_secure_password"  # Leave as None for open networks
    security_type = "WPA"  # Options: WPA, WEP, or "" for open networks
    
    # Generate QR code
    qr_code_base64 = generate_wifi_qr_code(network_name, network_password, security_type)
    
    # Render HTML with the QR code
    return render_template('howzit_qr.html', 
                          qr_code=qr_code_base64,
                          network_name=network_name)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
