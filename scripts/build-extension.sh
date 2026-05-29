#!/usr/bin/env bash
# AMPass Browser Extension — Build/Package Script
# Produces a .zip ready for Chrome Web Store or manual distribution

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$SCRIPT_DIR/.."
EXT_DIR="$ROOT/clients/browser-extension"
RELEASE_DIR="$ROOT/release/browser-extension"

# Read version from manifest
VERSION=$(grep '"version"' "$EXT_DIR/manifest.json" | head -1 | sed 's/.*"version": *"\([^"]*\)".*/\1/')
ZIP_NAME="ampass-extension-v${VERSION}.zip"

echo "Building AMPass Browser Extension v${VERSION}..."

# Validate icons exist and are real PNGs
for size in 16 32 48 128; do
  ICON="$EXT_DIR/assets/icons/icon-${size}.png"
  if [ ! -f "$ICON" ] || [ "$(wc -c < "$ICON")" -lt 100 ]; then
    echo "ERROR: Icon $ICON is missing or too small (placeholder). Run icon generation first."
    exit 1
  fi
done
echo "✓ Icons validated"

# Create release dir
mkdir -p "$RELEASE_DIR"

# Build zip (exclude dev files)
cd "$EXT_DIR"
zip -r "$RELEASE_DIR/$ZIP_NAME" . \
  --exclude "*.DS_Store" \
  --exclude ".git/*" \
  --exclude "test-pages/*" \
  --exclude "README.md" \
  --exclude "SECURITY.md"

echo "✓ Package created: $RELEASE_DIR/$ZIP_NAME"
echo ""
echo "To load in Chrome:"
echo "  1. Open chrome://extensions/"
echo "  2. Enable Developer Mode"
echo "  3. Click 'Load unpacked' → select $EXT_DIR"
echo ""
echo "To publish to Chrome Web Store:"
echo "  Upload $RELEASE_DIR/$ZIP_NAME"
echo ""
echo "Extension size: $(du -sh "$RELEASE_DIR/$ZIP_NAME" | cut -f1)"
