#!/bin/bash
# KiOSC-BrowsR installer
#
# HOW TO RUN THIS SCRIPT:
#   Right-click (or Control-click) this file → Open
#   When macOS asks "are you sure?", click Open.
#
# DO NOT double-click — macOS Sequoia blocks quarantined scripts with
# a "damaged" error on double-click; right-click → Open bypasses it.
#
# ALTERNATIVE (Terminal):
#   xattr -cr ~/Downloads/KiOSC-BrowsR-*.dmg
#   Then mount the DMG and drag KiOSC-BrowsR.app to Applications.

set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
APP_NAME="KiOSC-BrowsR.app"
SRC="$SCRIPT_DIR/$APP_NAME"
DEST="/Applications/$APP_NAME"

if [ ! -d "$SRC" ]; then
  osascript -e 'display alert "Install failed" message "KiOSC-BrowsR.app not found next to this script."'
  exit 1
fi

# Remove quarantine from the source .app so Gatekeeper allows it
xattr -dr com.apple.quarantine "$SRC" 2>/dev/null || true

# Copy to /Applications using ditto (preserves code signature)
if [ -d "$DEST" ]; then
  rm -rf "$DEST"
fi
ditto "$SRC" "$DEST"

# Remove quarantine from the installed copy too
xattr -dr com.apple.quarantine "$DEST" 2>/dev/null || true

osascript -e 'display notification "KiOSC-BrowsR has been installed to Applications." with title "Install complete"'

open "$DEST"
