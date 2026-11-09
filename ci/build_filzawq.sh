#!/bin/bash
# Build FilzaWQ.dylib and load it into Filza without modifying the main binary.
#
# Filza ships Filza.signature: a 256-byte signature over its main executable, so
# adding LC_LOAD_DYLIB trips "Main binary was modified" and the check cannot be
# satisfied at runtime. Instead this replaces an already-linked framework with a
# re-exporting dylib:
#
#   Frameworks/lib7z.framework/lib7z        -> our dylib (constructor runs)
#   Frameworks/lib7z.framework/lib7z_orig   -> the real lib7z, re-exported
#
# The main binary keeps its original load command, so it stays byte-identical and
# the signature check still passes.
#
# Usage: ci/build_filzawq.sh <Filza.ipa> [out.ipa]
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

REHOST="$APP/Frameworks/lib7z.framework/lib7z"
[ -f "$REHOST" ] || { echo "rehost target $REHOST missing"; exit 1; }

echo "==> Moving the original lib7z aside"
cp "$REHOST" "$WORK/lib7z_orig.dylib"
install_name_tool -id "@rpath/lib7z.framework/lib7z_orig" "$WORK/lib7z_orig.dylib"
cp "$WORK/lib7z_orig.dylib" "$APP/Frameworks/lib7z.framework/lib7z_orig"

echo "==> Staging tweak project"
mkdir -p "$WORK/proj"
cp "$ROOT/flzq/FilzaWQ.xm" "$WORK/proj/"
cp "$ROOT/flzq/Wq.h"       "$WORK/proj/"
cp "$ROOT/flz/Wq.m"        "$WORK/proj/"

cat > "$WORK/proj/Makefile" <<MK
ARCHS = arm64
TARGET = iphone:clang:latest:15.0
INSTALL_TARGET_PROCESSES = Filza

include \$(THEOS)/makefiles/common.mk

TWEAK_NAME = FilzaWQ
FilzaWQ_FILES = FilzaWQ.xm Wq.m
FilzaWQ_CFLAGS = -fobjc-arc -I\$(THEOS_PROJECT_DIR)
FilzaWQ_FRAMEWORKS = Foundation UIKit
FilzaWQ_LDFLAGS = -Wl,-install_name,@rpath/lib7z.framework/lib7z \\
                  -Wl,-reexport_library,$WORK/lib7z_orig.dylib

include \$(THEOS)/makefiles/tweak.mk
MK

echo "==> Building dylib"
( cd "$WORK/proj" && make clean >/dev/null 2>&1 || true; make FINALPACKAGE=1 )
DYLIB="$(find "$WORK/proj/.theos" -name 'FilzaWQ.dylib' | head -n 1)"
[ -n "$DYLIB" ] || { echo "dylib not produced"; exit 1; }
echo "    $DYLIB ($(stat -f%z "$DYLIB") bytes)"

echo "==> Undefined symbols"
nm -u "$DYLIB" | sed 's/^/    /'
if nm -u "$DYLIB" | grep -Eq 'SecTask|_SecStaticCode|_csops'; then
  echo "private API is linked directly; dyld will abort at launch" >&2
  exit 1
fi

echo "==> Installing as lib7z"
cp "$DYLIB" "$REHOST"

echo "==> Signing"
find "$APP" -name '*.dylib' -exec codesign -f -s - {} \; 2>/dev/null || true
codesign -f -s - "$APP" 2>/dev/null || true

echo "==> Packaging"
mkdir -p "$(dirname "$OUT")"
rm -f "$OUT"
( cd "$WORK/ipa" && zip -qry "$ROOT/$OUT" Payload )
echo "==> Done: $OUT ($(stat -f%z "$ROOT/$OUT") bytes)"
shasum -a 256 "$ROOT/$OUT"
