# KiOSC-BrowsR

OSC / UDP-controlled browser kiosk for **Linux**, **macOS**, **Windows**, **Android**, and **iOS**.

A full-screen browser window is controlled remotely via OSC or plain UDP text messages — navigate to a URL, reload, clear cache, and more. Devices advertise themselves on the local network via **mDNS** so you never need to look up an IP address.

---

## Table of contents

1. [Quick start (desktop)](#quick-start-desktop)
2. [Escaping kiosk mode](#escaping-kiosk-mode)
3. [Web admin panel](#web-admin-panel)
4. [OSC command reference](#osc-command-reference)
5. [UDP plaintext command reference](#udp-plaintext-command-reference)
6. [Finding devices on the network (mDNS)](#finding-devices-on-the-network-mdns)
7. [Configuration file](#configuration-file)
8. [Building from source](#building-from-source)
9. [Mobile (Android / iOS)](#mobile-android--ios)
10. [Linux kiosk machine setup](#linux-kiosk-machine-setup)

---

## Quick start (desktop)

### Download a release

Go to [Releases](https://github.com/DHPKE/KiOSC-BROSR/releases) and download the file for your platform:

| Platform | File |
|---|---|
| macOS (Apple Silicon) | `KiOSC-BrowsR-*-arm64.dmg` |
| macOS (Intel) | `KiOSC-BrowsR-*.dmg` |
| Linux (Debian / Ubuntu) | `kiosc-browsr_*.deb` |
| Linux (any distro) | `KiOSC-BrowsR-*.AppImage` |
| Windows | `KiOSC-BrowsR-Setup-*.exe` |

### Run in development mode (no kiosk)

```bash
npm install
npm run dev          # windowed, no kiosk lock — F12 opens DevTools
```

### Run in full kiosk mode

```bash
npm start            # full-screen kiosk, all OS-level chrome hidden
```

---

## Escaping kiosk mode

The kiosk window is intentionally lock-down. Here is how to exit depending on your situation:

### Via the web admin panel (recommended)

Open a browser on **any other device** on the same network and go to:

```
http://<hostname>.local:8080
```

Log in with the credentials from your config (default: `admin` / `changeme`), then use the **Stop** button to navigate the kiosk to `about:blank`, or **Restart** to reload.

To fully quit the app from the admin panel, use the OS-level approach below — there is no remote quit command by design (safety).

### Keyboard shortcuts (when you have a keyboard attached)

| OS | Action | Shortcut |
|---|---|---|
| **All** | Exit dev mode (`--no-kiosk`) | `Alt+F4` / `Cmd+Q` |
| **Windows** | Task Manager | `Ctrl+Shift+Esc`, then end the `kiosc-browsr` process |
| **macOS** | Force quit | `Cmd+Option+Esc`, select KiOSC-BrowsR |
| **Linux (X11)** | Kill window | `Ctrl+Alt+T` on another TTY, then `pkill kiosc-browsr` |
| **Linux (kiosk machine)** | Switch TTY | `Ctrl+Alt+F2`, log in, then `sudo systemctl stop kiosc-browsr` |

### Via SSH (headless / kiosk machine)

```bash
ssh user@<hostname>
sudo systemctl stop kiosc-browsr
```

### Via OSC or UDP (from a controller)

Send the `stop` command — this navigates the kiosk to a blank page but keeps the app running (ready to receive a `start` or `goto` command):

```
OSC:  /stop
UDP:  stop
```

### Disable kiosk mode permanently

Set `kiosk: false` in your config file (see [Configuration](#configuration-file)) and restart the app. The window will be a normal resizable frame with a title bar — press `F12` to open DevTools.

---

## Web admin panel

The built-in HTTP admin panel runs on port **8080** by default (configurable).

**Access:** `http://<hostname>.local:8080`

Protected by HTTP Basic Auth — default credentials: `admin` / `changeme`.  
**Change these before deploying** via the config file (`web_user`, `web_pass`).

### What you can do from the admin panel

| Section | Actions |
|---|---|
| **Status** | Live view of current URL, active state, auto-reset timer |
| **Find this device** | mDNS hostname and copy buttons for OSC port, UDP port, web admin URL |
| **Navigate** | Type any URL and press Go, or use Reload / Home / Stop / Clear Cache |
| **Settings** | Change home URL, auto-reset timer, mDNS device name (saved to disk) |

---

## OSC command reference

Default port: **9000 UDP**

| Address | Arguments | Action |
|---|---|---|
| `/goto` | `string url` | Navigate to URL |
| `/start` | *(optional)* `string url` | Navigate to URL (or home if no arg) |
| `/home` | — | Navigate to home URL |
| `/stop` | — | Navigate to `about:blank` |
| `/reload` | — | Reload current page |
| `/restart` | *(optional)* `string url` | Navigate to URL (or home) |
| `/clear` | — | Clear browser cache and storage |
| `/set_reset_time` | `int seconds` | Set auto-reset timer (0 = disabled) |
| `/status` | — | Log current status to console |

**Example** (from TouchOSC, QLab, or any OSC app):
- Target: `<hostname>.local` port `9000`
- Message: `/goto` with string arg `https://my-show-page.com`

---

## UDP plaintext command reference

Default port: **9100 UDP**

Send a plain UTF-8 text packet:

```
goto https://example.com
reload
home
stop
clear
set_reset_time 300
```

Useful for simple integrations (shell scripts, lighting consoles, custom hardware):

```bash
echo "goto https://example.com" | nc -u <hostname>.local 9100
```

### Optional HMAC authentication

Set `hmac_secret` in config. Append a hex HMAC-SHA256 signature as the last token:

```
goto https://example.com <hex_hmac_of_"goto https://example.com">
```

---

## Finding devices on the network (mDNS)

KiOSC-BrowsR advertises two mDNS services on startup:

| Service type | Name | Resolves to |
|---|---|---|
| `_osc._udp` | `KiOSC-BrowsR (<device-name>)` | OSC control port |
| `_http._tcp` | `KiOSC-BrowsR Admin (<device-name>)` | Web admin port |

**From a browser:** `http://<hostname>.local:8080`

**From an OSC controller** (TouchOSC, Chataigne, QLab, etc.): browse for `_osc._udp` services — the kiosk will appear by name with its address and port pre-filled.

**From the command line:**
```bash
# macOS / Linux with avahi
dns-sd -B _osc._udp local          # macOS
avahi-browse _osc._udp             # Linux
```

**Device name** is the machine hostname by default. Override with `mdns_name` in config.

---

## Configuration file

KiOSC-BrowsR looks for a config file in this order:

1. Path in the `KIOSC_CONFIG` environment variable
2. `<userData>/config.yaml` (writable app data folder)
3. `/etc/kiosc-browsr/config.yaml` (Linux system-wide)

If none is found, built-in defaults are used.

### Full config reference

```yaml
# URL to load on startup and after auto-reset
start_url: "https://example.com"

# Enable full-screen kiosk mode (false = windowed, useful for development)
kiosk: true

# Automatically load start_url after this many seconds of inactivity (0 = disabled)
reset_time: 3600

# mDNS device name — shown in OSC browser and web admin
# Default: machine hostname
mdns_name: "my-kiosk"

# OSC UDP listener
osc_bind: "0.0.0.0"
osc_port: 9000

# UDP plaintext listener
udp_text_bind: "0.0.0.0"
udp_text_port: 9100

# Web admin panel
web_bind: "0.0.0.0"   # use 127.0.0.1 to restrict to localhost only
web_port: 8080
web_user: "admin"
web_pass: "changeme"  # CHANGE THIS

# Optional: restrict OSC/UDP control to specific IP addresses
# Leave empty ([]) to allow all
allowed_ips: []
#  - "192.168.1.50"
#  - "10.0.0.1"

# Optional HMAC-SHA256 secret for UDP plaintext authentication
# Leave empty to disable
hmac_secret: ""

# Start kiosk browser on launch
autostart: true
```

### Where is userData?

| OS | Path |
|---|---|
| macOS | `~/Library/Application Support/kiosc-browsr/` |
| Windows | `%APPDATA%\kiosc-browsr\` |
| Linux | `~/.config/kiosc-browsr/` |

---

## Building from source

**Prerequisites:** Node.js 22+, npm

```bash
git clone https://github.com/DHPKE/KiOSC-BROSR.git
cd KiOSC-BROSR
npm install

# Development (windowed, F12 = DevTools)
npm run dev

# Production kiosk
npm start

# Package for distribution
npm run build:mac      # → dist/*.dmg
npm run build:linux    # → dist/*.deb + *.AppImage
npm run build:win      # → dist/*-Setup.exe
npm run build:all      # all three
```

---

## Mobile (Android / iOS)

The mobile app uses [Capacitor](https://capacitorjs.com/). The kiosk display is a fullscreen `<iframe>` — your JS OSC/UDP context stays alive while the iframe shows kiosk content.

**Triple-tap anywhere** on screen to open the settings overlay.

### Prerequisites

- Android: Android Studio
- iOS: Xcode (macOS only)

### Build

```bash
cd src/mobile
npm install
npm run build                  # bundle JS → dist/

# First time only
npx cap add android
npx cap add ios

# After every JS change
npx cap sync

# Open in IDE
npx cap open android           # Android Studio
npx cap open ios               # Xcode
```

### Mobile OSC commands

Same as desktop — all commands listed in the [OSC reference](#osc-command-reference) above are supported. The app listens on the configured OSC port (default 9000) via `@capacitor-community/udp`.

> **iOS note:** UDP sockets require the app to be in the foreground. This is the expected behaviour for a kiosk that is always on-screen.

---

## Linux kiosk machine setup

For a dedicated Debian/Ubuntu kiosk machine that boots straight into the browser, use the legacy installer script (installs Chromium + Python-based service):

```bash
sudo bash scripts/setup-kioscbrowsr.sh
```

For the new Electron-based service on Linux, install the `.deb` from Releases and enable it as a systemd service:

```bash
sudo dpkg -i kiosc-browsr_*.deb
sudo systemctl enable --now kiosc-browsr
```

The service runs as the current user's desktop session. For a true headless kiosk, configure autologin and add `kiosc-browsr` to the autostart of your window manager.
