#!/usr/bin/env bash
# install-rpi4.sh — KiOSC-BrowsR installer for Raspberry Pi 4 (Raspberry Pi OS 64-bit)
#
# Run as the desktop user (not root). Uses sudo internally where required.
# Usage:
#   bash install-rpi4.sh [OPTIONS]
#
# Options:
#   --url URL           Kiosk start URL (default: https://example.com)
#   --resolution WxH    Force display resolution, e.g. 1920x1200 or 1920x1080
#                       Appends video=HDMI-A-1:WxH_MR@60 to /boot/firmware/cmdline.txt
#                       (reduced-blanking CVT timing — required for most non-TV monitors)
#   --no-autostart      Skip XDG autostart entry
#   --help              Show this help
#
# What this script does:
#   1. Downloads the latest arm64 AppImage from GitHub
#   2. Extracts and installs to /opt/KiOSC-BrowsR/
#   3. Creates a .desktop launcher
#   4. Creates an XDG autostart entry so the app launches at login
#   5. Optionally sets the display resolution in /boot/firmware/cmdline.txt
#   6. Writes a starter config.yaml if none exists

set -euo pipefail

# ── Defaults ──────────────────────────────────────────────────────────────────
GITHUB_REPO="DHPKE/KiOSC-BROSR"
INSTALL_DIR="/opt/KiOSC-BrowsR"
BINARY="kiosc-browsr"
KIOSK_URL="https://example.com"
RESOLUTION=""
AUTOSTART=true
TMPDIR_WORK="$(mktemp -d)"
trap 'rm -rf "$TMPDIR_WORK"' EXIT

# ── Argument parsing ───────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --url)         KIOSK_URL="$2"; shift 2 ;;
    --resolution)  RESOLUTION="$2"; shift 2 ;;
    --no-autostart) AUTOSTART=false; shift ;;
    --help)
      sed -n '/^# /s/^# //p' "$0" | head -30
      exit 0 ;;
    *) echo "Unknown option: $1" >&2; exit 1 ;;
  esac
done

# ── Sanity checks ─────────────────────────────────────────────────────────────
ARCH="$(uname -m)"
if [[ "$ARCH" != "aarch64" ]]; then
  echo "ERROR: This script is for aarch64 (Raspberry Pi OS 64-bit). Detected: $ARCH" >&2
  exit 1
fi

if [[ "$EUID" -eq 0 ]]; then
  echo "ERROR: Run as your desktop user, not root. sudo will be called automatically." >&2
  exit 1
fi

if ! command -v curl >/dev/null 2>&1; then
  echo "Installing curl..."
  sudo apt-get install -y curl
fi

# ── Download latest arm64 AppImage ────────────────────────────────────────────
echo "Fetching latest release info from GitHub..."
RELEASE_JSON="$(curl -fsSL "https://api.github.com/repos/${GITHUB_REPO}/releases/latest")"
APPIMAGE_URL="$(echo "$RELEASE_JSON" | grep -o '"browser_download_url": *"[^"]*arm64\.AppImage"' | grep -o 'https://[^"]*')"
VERSION="$(echo "$RELEASE_JSON" | grep -o '"tag_name": *"[^"]*"' | grep -o 'v[^"]*')"

if [[ -z "$APPIMAGE_URL" ]]; then
  echo "ERROR: Could not find arm64 AppImage in latest release." >&2
  echo "Check https://github.com/${GITHUB_REPO}/releases" >&2
  exit 1
fi

APPIMAGE_FILE="$TMPDIR_WORK/KiOSC-BrowsR-arm64.AppImage"
echo "Downloading KiOSC-BrowsR ${VERSION} (arm64)..."
curl -fL --progress-bar "$APPIMAGE_URL" -o "$APPIMAGE_FILE"
chmod +x "$APPIMAGE_FILE"

# ── Extract AppImage ───────────────────────────────────────────────────────────
echo "Extracting..."
cd "$TMPDIR_WORK"
"$APPIMAGE_FILE" --appimage-extract >/dev/null
cd - >/dev/null

# ── Install to /opt/KiOSC-BrowsR ──────────────────────────────────────────────
echo "Installing to ${INSTALL_DIR}..."
sudo mkdir -p "$INSTALL_DIR"
sudo cp -r "$TMPDIR_WORK/squashfs-root/." "$INSTALL_DIR/"
sudo chmod +x "${INSTALL_DIR}/${BINARY}"

# Fix permissions — resources/ is copied as root but must be world-readable
sudo chmod -R a+rX "${INSTALL_DIR}/resources/"
sudo chmod -R a+rX "${INSTALL_DIR}/locales/" 2>/dev/null || true

# ── Write .desktop file ───────────────────────────────────────────────────────
DESKTOP_CONTENT="[Desktop Entry]
Name=KiOSC-BrowsR
Exec=env LD_LIBRARY_PATH=${INSTALL_DIR} ${INSTALL_DIR}/${BINARY} --no-sandbox %U
Terminal=false
Type=Application
Icon=kiosc-browsr
StartupWMClass=KiOSC-BrowsR
Comment=OSC/UDP-controlled browser kiosk
Categories=Utility;"

echo "$DESKTOP_CONTENT" | sudo tee "${INSTALL_DIR}/kiosc-browsr.desktop" >/dev/null
sudo mkdir -p /usr/share/applications
echo "$DESKTOP_CONTENT" | sudo tee /usr/share/applications/kiosc-browsr.desktop >/dev/null
echo "Desktop file written."

# ── XDG autostart ─────────────────────────────────────────────────────────────
if [[ "$AUTOSTART" == "true" ]]; then
  AUTOSTART_DIR="$HOME/.config/autostart"
  mkdir -p "$AUTOSTART_DIR"
  echo "$DESKTOP_CONTENT" > "$AUTOSTART_DIR/kiosc-browsr.desktop"
  echo "Autostart entry created: ${AUTOSTART_DIR}/kiosc-browsr.desktop"
fi

# ── Starter config.yaml ───────────────────────────────────────────────────────
CONFIG_DIR="$HOME/.config/kiosc-browsr"
CONFIG_FILE="$CONFIG_DIR/config.yaml"
if [[ ! -f "$CONFIG_FILE" ]]; then
  mkdir -p "$CONFIG_DIR"
  cat > "$CONFIG_FILE" <<YAML
start_url: "${KIOSK_URL}"
osc_bind: "0.0.0.0"
osc_port: 9000
udp_text_bind: "0.0.0.0"
udp_text_port: 9100
web_bind: "0.0.0.0"
web_port: 8080
web_user: "admin"
web_pass: "changeme"
reset_time: 3600
hmac_secret: ""
allowed_ips: []
kiosk: true
autostart: true
hide_cursor: false
test_mode: false
YAML
  echo "Config written: ${CONFIG_FILE}"
  echo "  --> Edit web_pass before exposing port 8080 to the network!"
else
  echo "Config already exists, skipping: ${CONFIG_FILE}"
fi

# ── Display resolution ─────────────────────────────────────────────────────────
if [[ -n "$RESOLUTION" ]]; then
  # Locate cmdline.txt (Raspberry Pi OS >= bookworm uses /boot/firmware/)
  if [[ -f /boot/firmware/cmdline.txt ]]; then
    CMDLINE=/boot/firmware/cmdline.txt
  elif [[ -f /boot/cmdline.txt ]]; then
    CMDLINE=/boot/cmdline.txt
  else
    echo "WARNING: Could not find cmdline.txt — skipping resolution change." >&2
    CMDLINE=""
  fi

  if [[ -n "$CMDLINE" ]]; then
    CURRENT="$(cat "$CMDLINE")"
    # Remove any existing video= parameter
    CLEANED="$(echo "$CURRENT" | sed 's/ *video=[^ ]*//g' | tr -s ' ')"
    NEW_LINE="${CLEANED} video=HDMI-A-1:${RESOLUTION}MR@60"
    echo "$NEW_LINE" | sudo tee "$CMDLINE" >/dev/null
    echo "Resolution set: video=HDMI-A-1:${RESOLUTION}MR@60"
    echo "  --> cmdline.txt updated. Changes take effect after reboot."
    echo "  --> If the display shows 'Signal error fD:', the pixel clock is still"
    echo "      too high for your monitor — try a lower resolution or use"
    echo "      config.txt hdmi_group/hdmi_mode settings instead."
  fi
fi

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
echo "KiOSC-BrowsR ${VERSION} installed successfully."
echo ""
echo "  Install dir : ${INSTALL_DIR}"
echo "  Config      : ${CONFIG_FILE}"
echo "  Web admin   : http://$(hostname -I | awk '{print $1}'):8080"
[[ "$AUTOSTART" == "true" ]] && echo "  Autostart   : enabled (launches at next desktop login)"
[[ -n "$RESOLUTION" ]] && echo "  Resolution  : ${RESOLUTION} (effective after reboot)"
echo ""
echo "To start now (without rebooting):"
echo "  LD_LIBRARY_PATH=${INSTALL_DIR} ${INSTALL_DIR}/${BINARY} --no-sandbox &"
echo ""
echo "To update later, re-run this script."
