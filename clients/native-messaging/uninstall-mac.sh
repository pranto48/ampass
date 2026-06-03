#!/bin/bash
# AMPass Native Messaging Host - macOS Uninstallation Script

echo "============================================"
echo " AMPass Native Messaging Host Uninstaller (Mac)"
echo "============================================"
echo ""

HOST_NAME="com.ampass.desktop"

CHROME_MANIFEST_DIR="$HOME/Library/Application Support/Google/Chrome/NativeMessagingHosts"
EDGE_MANIFEST_DIR="$HOME/Library/Application Support/Microsoft/Edge/NativeMessagingHosts"
FIREFOX_MANIFEST_DIR="$HOME/Library/Application Support/Mozilla/NativeMessagingHosts"

rm -f "$CHROME_MANIFEST_DIR/$HOST_NAME.json"
rm -f "$EDGE_MANIFEST_DIR/$HOST_NAME.json"
rm -f "$FIREFOX_MANIFEST_DIR/$HOST_NAME.json"

echo "Removed Native Messaging Host manifests from:"
echo "  Chrome:  $CHROME_MANIFEST_DIR/$HOST_NAME.json"
echo "  Edge:    $EDGE_MANIFEST_DIR/$HOST_NAME.json"
echo "  Firefox: $FIREFOX_MANIFEST_DIR/$HOST_NAME.json"
echo ""
echo "============================================"
echo " Uninstallation complete!"
echo "============================================"
