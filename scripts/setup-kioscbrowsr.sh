#!/usr/bin/env bash
# setup-kioscbrowsr.sh
# Run as root on Debian 12/13 (or Debian-derived) to install KiOSC-BrowsR.
# Usage: sudo ./setup-kioscbrowsr.sh
set -euo pipefail

# Configurable defaults (can be overridden via env or edited after install)
KIOSK_USER="${KIOSK_USER:-kiosk}"
KIOSK_URL="${KIOSK_URL:-https://example.com}"
OSC_BIND="${OSC_BIND:-0.0.0.0}"
OSC_PORT="${OSC_PORT:-9000}"
UDP_TEXT_PORT="${UDP_TEXT_PORT:-9100}"
WEBADMIN_BIND="${WEBADMIN_BIND:-127.0.0.1}"
WEBADMIN_PORT="${WEBADMIN_PORT:-8080}"
WEBADMIN_USER="${WEBADMIN_USER:-admin}"
WEBADMIN_PASS="${WEBADMIN_PASS:-changeme}"
CHROME_DEB_URL="https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb"
VENV_DIR="/opt/kiosc-browsr/venv"
SERVICE_USER="${KIOSK_USER}"
CONFIG_FILE="/etc/kiosc-browsr/config.yaml"

echo "KiOSC-BrowsR installer"
echo "This will create a kiosk user '${KIOSK_USER}', install Chromium (or Chrome fallback),"
echo "and deploy the KiOSC-BrowsR services (OSC, UDP text, WebAdmin)."
read -rp "Continue? [y/N] " answer
if [[ "${answer,,}" != "y" ]]; then
  echo "Aborted."
  exit 1
fi

# Update & base deps
apt update
DEBIAN_FRONTEND=noninteractive apt install -y --no-install-recommends \
  xserver-xorg xinit openbox x11-xserver-utils fonts-dejavu-core unclutter \
  ca-certificates wget curl gnupg lsb-release sudo dbus-x11 python3 python3-venv \
  python3-distutils build-essential xdotool x11-utils xinput xmodmap \
  unattended-upgrades

# Attempt to install chromium from apt without pulling snap
CHROMIUM_OK=true
if apt -y install --no-install-recommends chromium; then
  echo "Chromium installed from apt."
else
  CHROMIUM_OK=false
fi

if [ "${CHROMIUM_OK}" = "false" ]; then
  echo "Falling back to Google Chrome .deb (non-snap)."
  tmpdeb="$(mktemp --suffix=.deb)"
  wget -O "${tmpdeb}" "${CHROME_DEB_URL}"
  apt install -y "${tmpdeb}" || { echo "Failed to install Chrome"; rm -f "${tmpdeb}"; exit 1; }
  rm -f "${tmpdeb}"
fi

# Create kiosk user (if missing)
if ! id -u "${KIOSK_USER}" >/dev/null 2>&1; then
  useradd -m -s /bin/bash -G sudo "${KIOSK_USER}"
  passwd -d "${KIOSK_USER}" || true
  echo "${KIOSK_USER} ALL=(ALL) NOPASSWD: /bin/systemctl restart kiosc-browsr.service, /bin/systemctl restart kiosc-webadmin.service" > /etc/sudoers.d/${KIOSK_USER}-limited || true
fi

# Create directories
mkdir -p /opt/kiosc-browsr
chown -R "${SERVICE_USER}:${SERVICE_USER}" /opt/kiosc-browsr

# Create python venv and install python deps
python3 -m venv "${VENV_DIR}"
"${VENV_DIR}/bin/pip" install --upgrade pip
"${VENV_DIR}/bin/pip" install python-osc pychrome flask pyyaml websocket-client

# Place application files (kiosc-browsr service and webadmin)
install -o "${SERVICE_USER}" -m 755 -d /opt/kiosc-browsr/app

# Download app files from repository
wget -O /opt/kiosc-browsr/app/kiosc_browsr.py https://raw.githubusercontent.com/DHPKE/KiOSC-BROSR/main/app/kiosc_browsr.py
wget -O /opt/kiosc-browsr/app/webadmin.py https://raw.githubusercontent.com/DHPKE/KiOSC-BROSR/main/app/webadmin.py

chmod 755 /opt/kiosc-browsr/app/kiosc_browsr.py
chmod 755 /opt/kiosc-browsr/app/webadmin.py
chown -R "${SERVICE_USER}:${SERVICE_USER}" /opt/kiosc-browsr

# Default config
mkdir -p /etc/kiosc-browsr
cat > "${CONFIG_FILE}" <<YAML
start_url: "${KIOSK_URL}"
debug_port: 9222
autostart: true
osc_bind: "${OSC_BIND}"
osc_port: ${OSC_PORT}
udp_text_bind: "${OSC_BIND}"
udp_text_port: ${UDP_TEXT_PORT}
web_bind: "${WEBADMIN_BIND}"
web_port: ${WEBADMIN_PORT}
web_user: "${WEBADMIN_USER}"
web_pass: "${WEBADMIN_PASS}"
chrome_cmd_template: "chromium --no-first-run --disable-infobars --kiosk --start-maximized --remote-debugging-port={debug} '{url}'"
reset_time: 3600
YAML

chown -R "${SERVICE_USER}:${SERVICE_USER}" /etc/kiosc-browsr

# Download systemd units from repository
wget -O /etc/systemd/system/kiosc-browsr.service https://raw.githubusercontent.com/DHPKE/KiOSC-BROSR/main/packaging/systemd/kiosc-browsr.service
wget -O /etc/systemd/system/kiosc-webadmin.service https://raw.githubusercontent.com/DHPKE/KiOSC-BROSR/main/packaging/systemd/kiosc-webadmin.service

# Configure getty autologin on tty1 for kiosk user
mkdir -p /etc/systemd/system/getty@tty1.service.d
cat > /etc/systemd/system/getty@tty1.service.d/override.conf <<'GETTY'
[Service]
ExecStart=
ExecStart=-/sbin/agetty --autologin kiosk --noclear %I $TERM
Type=simple
GETTY

# Mask other gettys to reduce switching to other virtual consoles
for tty in 2 3 4 5 6; do
  systemctl mask getty@tty${tty}.service || true
done

# Create X startup files for kiosk user
cat > /home/${KIOSK_USER}/.xinitrc <<'XINIT'
#!/bin/sh
# Disable screen blanking / DPMS
xset s off
xset s noblank
xset -dpms

# Hide cursor
unclutter -idle 0.5 -root &

# Disable common key combos via xmodmap (will be applied below)
if [ -f /home/kiosk/.Xmodmap ]; then
  xmodmap /home/kiosk/.Xmodmap
fi

# Start KiOSC-BrowsR controller runs Chromium; we still run openbox so session stays alive
openbox-session
XINIT
chown ${KIOSK_USER}:${KIOSK_USER} /home/${KIOSK_USER}/.xinitrc
chmod 755 /home/${KIOSK_USER}/.xinitrc

# Create .bash_profile to auto-start X on tty1
cat > /home/${KIOSK_USER}/.bash_profile <<'PROFILE'
# Start X automatically on tty1
if [ -z "$DISPLAY" ] && [ "$(tty)" = "/dev/tty1" ]; then
  # prevent multiple instances
  if ! pgrep -u "$USER" -x Xorg >/dev/null 2>&1; then
    exec /usr/bin/xinit /home/$(whoami)/.xinitrc -- :0
  fi
fi
PROFILE
chown ${KIOSK_USER}:${KIOSK_USER} /home/${KIOSK_USER}/.bash_profile
chmod 644 /home/${KIOSK_USER}/.bash_profile

# Create an Xmodmap file to disable Alt+Tab / Alt+F4 / Ctrl+Alt+Fx handling in X (best-effort)
cat > /home/${KIOSK_USER}/.Xmodmap <<'XMAP'
! Remove Alt and Super from modifier list that cause switching; map F1-F12 to no-op via keysym
keysym F1 = F1_Noop
keysym F2 = F2_Noop
keysym F3 = F3_Noop
keysym F4 = F4_Noop
keysym F5 = F5_Noop
keysym F6 = F6_Noop
keysym F7 = F7_Noop
keysym F8 = F8_Noop
keysym F9 = F9_Noop
keysym F10 = F10_Noop
keysym F11 = F11_Noop
keysym F12 = F12_Noop
! Unmap Alt+Tab by removing mod1 or mapping it away is tricky; this is best-effort.
XMAP
chown ${KIOSK_USER}:${KIOSK_USER} /home/${KIOSK_USER}/.Xmodmap
chmod 644 /home/${KIOSK_USER}/.Xmodmap

# Chromium policies (managed) to lock browser UI & default URL
mkdir -p /etc/chromium/policies/managed
cat > /etc/chromium/policies/managed/kioscbrowsr_policies.json <<POL
{
  "HomepageLocation": "${KIOSK_URL}",
  "HomepageIsNewTabPage": false,
  "RestoreOnStartup": 4,
  "RestoreOnStartupURLs": ["${KIOSK_URL}"],
  "IncognitoModeAvailability": 1,
  "PasswordManagerEnabled": false,
  "BrowserAddPersonEnabled": false,
  "BrowserGuestModeEnabled": false,
  "DefaultBrowserSettingEnabled": false,
  "DisablePrintPreview": true,
  "PromptForDownload": false
}
POL
mkdir -p /etc/opt/chrome/policies/managed
cp /etc/chromium/policies/managed/kioscbrowsr_policies.json /etc/opt/chrome/policies/managed/ 2>/dev/null || true

# Enable services
systemctl daemon-reload
systemctl enable --now kiosc-browsr.service kiosc-webadmin.service || true
systemctl restart getty@tty1.service || true

echo "Installation finished. Review /etc/kiosc-browsr/config.yaml and edit values (web credentials, bind addresses, URLs)."
echo "Then reboot to get autologin and X running, or switch to tty1 (Ctrl+Alt+F1) to see kiosk user."
echo "WebAdmin will be available on ${WEBADMIN_BIND}:${WEBADMIN_PORT} (if you left defaults)."
echo "OSC is on ${OSC_BIND}:${OSC_PORT}; UDP text on ${OSC_BIND}:${UDP_TEXT_PORT}."
echo "Default web admin user/pass: ${WEBADMIN_USER}/${WEBADMIN_PASS} (change immediately)."