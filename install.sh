#!/bin/bash
if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root. Trying to elevate..."
    exec sudo "$0" "$@"
fi

INSTALL_DIR="$(dirname "$(realpath "$0")")"

# Install system dependencies
apt-get update && apt-get full-upgrade -y
apt-get install -y python3 python3-venv python3-pip hostapd dnsmasq aircrack-ng chromium unclutter-xfixes

systemctl disable dnsmasq
systemctl disable hostapd

# Create a virtual environment and install Python dependencies
python3 -m venv "$INSTALL_DIR/venv"
"$INSTALL_DIR/venv/bin/pip" install -r "$INSTALL_DIR/requirements.txt"

# Create a startup script
cat <<EOL > "$INSTALL_DIR/startup.sh"
#!/bin/bash
source "$INSTALL_DIR/venv/bin/activate"
python3 "$INSTALL_DIR/src/webgui.py"
EOL

chmod +x "$INSTALL_DIR/startup.sh"

# Add the startup script to systemd
cat <<EOL > /etc/systemd/system/dot11pi.service
[Unit]
Description=Dot11Pi Service
After=network.target

[Service]
ExecStart="$INSTALL_DIR/startup.sh"
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOL

# Enable and start the service
systemctl enable dot11pi.service

cat <<EOL > /etc/chromium.d/dot11Pi
export CHROMIUM_FLAGS="$CHROMIUM_FLAGS --force-tablet-mode --tablet-ui --touch-devices --touch-events --noerrdialogs --disable-infobars --no-first-run --enable-features=OverlayScrollbar --start-maximized --incognito --disable-pinch"
unclutter-xfixes --hide-on-touch --start-hidden --timeout 0.000001 -b
EOL

echo "Installation complete. The Dot11Pi service has been installed."
echo "Rebooting in 5 seconds..."
sleep 5 
reboot now