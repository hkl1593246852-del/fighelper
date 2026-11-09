#!/bin/bash
# Build FilzaWQ.dylib with Theos, inject it into a Filza IPA, repackage unsigned.
#
# Usage: ci/build_filzawq.sh <Filza.ipa> [out.ipa]
#
# Environment:
#   THEOS   Theos root (default ~/theos)
#   SIGN    "1" to ad-hoc sign the result (default), "0" to leave it unsigned
set -euo pipefail

IPA="${1:?usage: build_filzawq.sh <Filza.ipa> [out.ipa]}"
OUT="${2:-build/FilzaWQ.ipa}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
THEOS="${THEOS:-$HOME/theos}"

echo "==> Theos at $THEOS"
if [ ! -d "$THEOS" ]; then
  git clone --recursive --depth 1 https://github.com/theos/theos.git "$THEOS"
fi
export THEOS

# Use the iOS SDK that ships with the runner's Xcode instead of theos/sdks.
if SYSROOT="$(xcrun --sdk iphoneos --show-sdk-path 2>/dev/null)" && [ -d "$SYSROOT" ]; then
  export SYSROOT
  echo "    SYSROOT=$SYSROOT"
else
  echo "==> No Xcode iOS SDK; falling back to theos/sdks"
  if [ ! -d "$THEOS/sdks" ] || [ -z "$(ls -A "$THEOS/sdks" 2>/dev/null)" ]; then
    git clone --depth 1 https://github.com/theos/sdks "$THEOS/sdks"
  fi
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "==> Staging tweak project"
mkdir -p "$WORK/proj"
cp "$ROOT/flzq/FilzaWQ.xm" "$WORK/proj/"
cp "$ROOT/flzq/Wq.h"       "$WORK/proj/"
cp "$ROOT/flz/Wq.m"        "$WORK/proj/"

cat > "$WORK/proj/Makefile" <<'MK'
ARCHS = arm64
TARGET = iphone:clang:latest:15.0
INSTALL_TARGET_PROCESSES = Filza

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = FilzaWQ
FilzaWQ_FILES = FilzaWQ.xm Wq.m $(THEOS)/vendor/orion/fishhook/fishhook.c
FilzaWQ_CFLAGS = -fobjc-arc -I$(THEOS_PROJECT_DIR) -I$(THEOS)/vendor/orion/fishhook
FilzaWQ_FRAMEWORKS = Foundation UIKit Security
# fishhook rebinds the symbol table entries, so no substrate and no Logos hooks.

include $(THEOS)/makefiles/tweak.mk
MK

echo "==> Building dylib"
( cd "$WORK/proj" && make clean >/dev/null 2>&1 || true; make FINALPACKAGE=1 )
DYLIB="$(find "$WORK/proj/.theos" -name 'FilzaWQ.dylib' | head -n 1)"
[ -n "$DYLIB" ] || { echo "dylib not produced"; exit 1; }
echo "    $DYLIB ($(stat -c%s "$DYLIB" 2>/dev/null || stat -f%z "$DYLIB") bytes)"

echo "==> Unpacking Filza IPA"
mkdir -p "$WORK/ipa"
unzip -q "$IPA" -d "$WORK/ipa"
APP="$(find "$WORK/ipa/Payload" -maxdepth 1 -name '*.app' -type d | head -n 1)"
[ -n "$APP" ] || { echo "no .app in Payload"; exit 1; }
EXEC_NAME="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleExecutable' "$APP/Info.plist")"
BIN="$APP/$EXEC_NAME"
[ -f "$BIN" ] || { echo "binary $BIN missing"; exit 1; }
echo "    app=$APP"
echo "    bin=$BIN"

echo "==> Injecting"
mkdir -p "$APP/Frameworks"
cp "$DYLIB" "$APP/Frameworks/FilzaWQ.dylib"
if ! command -v insert_dylib >/dev/null 2>&1; then
  echo "insert_dylib not found; installing"
  ( cd "$WORK" && git clone -q --depth 1 https://github.com/Tyilo/insert_dylib.git && \
    cd insert_dylib && xcodebuild -quiet -project insert_dylib.xcodeproj -target insert_dylib \
      CONFIGURATION_BUILD_DIR="$WORK/bin" >/dev/null && \
    cp "$WORK/bin/insert_dylib" /usr/local/bin/ )
fi
insert_dylib --inplace --strip-codesig --all-yes \
  "@executable_path/Frameworks/FilzaWQ.dylib" "$BIN"

echo "==> Signing"
if [ "${SIGN:-1}" = "1" ]; then
  ENT="$(mktemp)"
  cp "$ROOT/flzq/filza.entitlements" "$ENT" 2>/dev/null || cat > "$ENT" <<'PL'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>com.apple.security.application-groups</key>
  <array><string>group.com.you.filzalite</string></array>
</dict></plist>
PL
  find "$APP" -name '*.dylib' -exec codesign -f -s - {} \;
  codesign -f -s - --entitlements "$ENT" "$BIN"
  codesign -f -s - "$APP"
fi

echo "==> Packaging"
mkdir -p "$(dirname "$OUT")"
rm -f "$OUT"
( cd "$WORK/ipa" && zip -qry "$ROOT/$OUT" Payload )
echo "==> Done: $OUT ($(stat -c%s "$ROOT/$OUT" 2>/dev/null || stat -f%z "$ROOT/$OUT") bytes)"
shasum -a 256 "$ROOT/$OUT"
