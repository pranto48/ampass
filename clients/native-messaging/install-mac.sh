#!/bin/bash
# AMPass Native Messaging Host - macOS Installation Script

echo "============================================"
echo " AMPass Native Messaging Host Installer (Mac)"
echo "============================================"
echo ""

EXTENSION_ID=$1
if [ -z "$EXTENSION_ID" ]; then
    echo "Using default/common development extension IDs."
    echo "To install for a specific extension ID, run:"
    echo "  ./install-mac.sh <your-extension-id>"
    echo ""
    EXTENSION_ID="REPLACE_WITH_YOUR_EXTENSION_ID"
fi

HOST_NAME="com.ampass.desktop"

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
WORKSPACE_DIR="$( cd "$SCRIPT_DIR/../.." && pwd )"
BINARY_PATH=""
if [ -f "/Applications/AMPass.app/Contents/MacOS/ampass-desktop" ]; then
    BINARY_PATH="/Applications/AMPass.app/Contents/MacOS/ampass-desktop"
elif [ -f "/Applications/AMPass.app/Contents/MacOS/AMPass" ]; then
    BINARY_PATH="/Applications/AMPass.app/Contents/MacOS/AMPass"
elif [ -f "$HOME/Applications/AMPass.app/Contents/MacOS/ampass-desktop" ]; then
    BINARY_PATH="$HOME/Applications/AMPass.app/Contents/MacOS/ampass-desktop"
elif [ -f "$HOME/Applications/AMPass.app/Contents/MacOS/AMPass" ]; then
    BINARY_PATH="$HOME/Applications/AMPass.app/Contents/MacOS/AMPass"
elif [ -f "$WORKSPACE_DIR/clients/desktop-tauri/src-tauri/target/release/bundle/macos/AMPass.app/Contents/MacOS/AMPass" ]; then
    BINARY_PATH="$WORKSPACE_DIR/clients/desktop-tauri/src-tauri/target/release/bundle/macos/AMPass.app/Contents/MacOS/AMPass"
elif [ -f "$WORKSPACE_DIR/clients/desktop-tauri/src-tauri/target/release/ampass-desktop" ]; then
    BINARY_PATH="$WORKSPACE_DIR/clients/desktop-tauri/src-tauri/target/release/ampass-desktop"
fi

if [ -z "$BINARY_PATH" ]; then
    echo "ERROR: AMPass binary not found."
    echo "Please install AMPass to /Applications or build the Tauri app first using:"
    echo "  cd clients/desktop-tauri && npm run build"
    exit 1
fi

echo "Found AMPass binary at:"
echo "  $BINARY_PATH"
echo ""

CHROME_MANIFEST_DIR="$HOME/Library/Application Support/Google/Chrome/NativeMessagingHosts"
EDGE_MANIFEST_DIR="$HOME/Library/Application Support/Microsoft/Edge/NativeMessagingHosts"
FIREFOX_MANIFEST_DIR="$HOME/Library/Application Support/Mozilla/NativeMessagingHosts"

mkdir -p "$CHROME_MANIFEST_DIR"
mkdir -p "$EDGE_MANIFEST_DIR"
mkdir -p "$FIREFOX_MANIFEST_DIR"

generate_manifest() {
    local ext_id=$1
    cat <<EOF
{
  "name": "com.ampass.desktop",
  "description": "AMPass Desktop App - Native Messaging Host",
  "path": "$BINARY_PATH",
  "type": "stdio",
  "allowed_origins": [
    "chrome-extension://$ext_id/"
  ]
}
EOF
}

generate_firefox_manifest() {
    local ext_id=$1
    cat <<EOF
{
  "name": "com.ampass.desktop",
  "description": "AMPass Desktop App - Native Messaging Host",
  "path": "$BINARY_PATH",
  "type": "stdio",
  "allowed_extensions": [
    "$ext_id"
  ]
}
EOF
}

if [ "$EXTENSION_ID" = "REPLACE_WITH_YOUR_EXTENSION_ID" ]; then
    cat <<EOF > "$CHROME_MANIFEST_DIR/$HOST_NAME.json"
{
  "name": "com.ampass.desktop",
  "description": "AMPass Desktop App - Native Messaging Host",
  "path": "$BINARY_PATH",
  "type": "stdio",
  "allowed_origins": [
    "chrome-extension://pgbgflbgdbigekigbdfifidplpohhblg/",
    "chrome-extension://hdbjdbpjldchglhllkgpkebgijndhogo/",
    "chrome-extension://kgkldldplhdbjgclpohhblgjndhogo/",
    "chrome-extension://REPLACE_WITH_YOUR_EXTENSION_ID/"
  ]
}
EOF
else
    generate_manifest "$EXTENSION_ID" > "$CHROME_MANIFEST_DIR/$HOST_NAME.json"
fi

cp "$CHROME_MANIFEST_DIR/$HOST_NAME.json" "$EDGE_MANIFEST_DIR/$HOST_NAME.json"

if [ "$EXTENSION_ID" != "REPLACE_WITH_YOUR_EXTENSION_ID" ]; then
    generate_firefox_manifest "$EXTENSION_ID" > "$FIREFOX_MANIFEST_DIR/$HOST_NAME.json"
else
    cat <<EOF > "$FIREFOX_MANIFEST_DIR/$HOST_NAME.json"
{
  "name": "com.ampass.desktop",
  "description": "AMPass Desktop App - Native Messaging Host",
  "path": "$BINARY_PATH",
  "type": "stdio",
  "allowed_extensions": [
    "ampass@example.com"
  ]
}
EOF
fi

echo "Registered Native Messaging Host manifest for:"
echo "  Chrome:  $CHROME_MANIFEST_DIR/$HOST_NAME.json"
echo "  Edge:    $EDGE_MANIFEST_DIR/$HOST_NAME.json"
echo "  Firefox: $FIREFOX_MANIFEST_DIR/$HOST_NAME.json"
echo ""
echo "Manifest contents:"
cat "$CHROME_MANIFEST_DIR/$HOST_NAME.json"
echo ""
echo "============================================"
echo " Installation complete!"
echo " Please restart Chrome/Edge to apply changes."
echo "============================================"
