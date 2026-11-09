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
if [ ! -d "$THEOS/sdks" ] || [ -z "$(ls -A "$THEOS/sdks" 2>/dev/null)" ]; then
  git clone --depth 1 https://github.com/theos/sdks "$THEOS/sdks"
fi
export THEOS

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "==> Staging tweak project"
mkdir -p "$WORK/proj"
cp "$ROOT/flzq/FilzaWQ.xm" "$WORK/proj/"
cp "$ROOT/flzq/Wq.h"       "$WORK/proj/"
cp "$ROOT/flz/Wq.m"        "$WORK/proj/"

cat > "$WORK/proj/Makefile" <<'MK'
ARCHS = arm64 arm64e
TARGET = iphone:clang:16.5:15.0
INSTALL_TARGET_PROCESSES = Filza

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = FilzaWQ
FilzaWQ_FILES = FilzaWQ.xm Wq.m
FilzaWQ_CFLAGS = -fobjc-arc -I$(THEOS_PROJECT_DIR)
FilzaWQ_FRAMEWORKS = Foundation UIKit
FilzaWQ_LIBRARIES = substrate

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
BIN="$(find "$APP" -maxdepth 1 -type f -perm +111 | head -n 1)"
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
