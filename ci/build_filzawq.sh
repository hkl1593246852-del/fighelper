#!/bin/bash
# Build the diagnostic dylib into a Filza base and repackage an unsigned IPA.
# Runs on Linux: no Xcode, no codesign, no install_name_tool.
#
# Two base layouts are supported:
#   slot   - the base already links Frameworks/FilzaApplySandboxExt.dylib
#   rehost - a stock Filza linking @rpath/lib7z.framework/lib7z; our dylib takes
#            that path and re-exports the real library, so the main binary keeps
#            its load commands and Filza.signature still validates
#
# Usage: ci/build_filzawq.sh <base.ipa> [out.ipa]
set -euo pipefail

IPA="${1:?usage: build_filzawq.sh <base.ipa> [out.ipa]}"
OUT="${2:-build/FilzaWQ.ipa}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
THEOS="${THEOS:-$HOME/theos}"
TOOL="python3 $ROOT/ci/macho_tool.py"

echo "==> Theos at $THEOS"
if [ ! -d "$THEOS" ]; then
  git clone --recursive --depth 1 https://github.com/theos/theos.git "$THEOS"
fi
export THEOS

SDKS_DIR="$THEOS/sdks"
if [ ! -d "$SDKS_DIR" ] || [ -z "$(ls -A "$SDKS_DIR" 2>/dev/null)" ]; then
  echo "==> Fetching theos/sdks"
  rm -rf "$SDKS_DIR"
  if ! git clone --depth 1 https://github.com/theos/sdks.git "$SDKS_DIR"; then
    echo "clone failed" >&2
  fi
fi

echo "==> Available SDKs"
ls -la "$SDKS_DIR" | sed -n '1,15p'

SDK_PATH="$(find "$SDKS_DIR" -maxdepth 1 -name 'iPhoneOS*.sdk' | sort -V | tail -n 1)"
if [ -z "$SDK_PATH" ]; then
  echo "no iPhoneOS sdk found under $SDKS_DIR" >&2
  exit 1
fi
SDK_NAME="$(basename "$SDK_PATH" .sdk)"
SDK_VER="${SDK_NAME#iPhoneOS}"
echo "    using $SDK_NAME"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "==> Unpacking base IPA"
mkdir -p "$WORK/ipa"
unzip -q "$IPA" -d "$WORK/ipa"
APP="$(find "$WORK/ipa/Payload" -maxdepth 1 -name '*.app' -type d | sed -n '1p')"
[ -n "$APP" ] || { echo "no .app in Payload"; exit 1; }
EXEC_NAME="$($TOOL executable "$APP/Info.plist")"
BIN="$APP/$EXEC_NAME"
[ -f "$BIN" ] || { echo "binary $BIN missing"; exit 1; }
echo "    app=$APP"
echo "    bin=$BIN"

SLOT="$APP/Frameworks/FilzaApplySandboxExt.dylib"
REHOST="$APP/Frameworks/lib7z.framework/lib7z"

if [ -f "$SLOT" ]; then
  MODE=slot
  INSTALL_NAME="@executable_path/Frameworks/FilzaApplySandboxExt.dylib"
elif [ -f "$REHOST" ]; then
  MODE=rehost
  INSTALL_NAME="@rpath/lib7z.framework/lib7z"
else
  echo "base has neither a FilzaApplySandboxExt nor a lib7z slot"; exit 1
fi
echo "==> Mode: $MODE"

if [ "$MODE" = "rehost" ]; then
  echo "==> Moving the original lib7z aside"
  cp "$REHOST" "$WORK/lib7z_orig.dylib"
  $TOOL set-id "$WORK/lib7z_orig.dylib" \
    "@rpath/lib7z.framework/lib7z" "@executable_path/Frameworks/lib7z_orig.dylib"
  cp "$WORK/lib7z_orig.dylib" "$APP/Frameworks/lib7z_orig.dylib"
fi

echo "==> Staging tweak project"
mkdir -p "$WORK/proj"
cp "$ROOT/flzq/FilzaWQ.xm" "$WORK/proj/"
cp "$ROOT/flzq/Wq.h"       "$WORK/proj/"
cp "$ROOT/flz/Wq.m"        "$WORK/proj/"

REEXPORT=""
[ "$MODE" = "rehost" ] && REEXPORT="-Wl,-reexport_library,$WORK/lib7z_orig.dylib"

cat > "$WORK/proj/Makefile" <<MK
ARCHS = arm64
TARGET = iphone:clang:$SDK_VER:15.0
INSTALL_TARGET_PROCESSES = Filza

include \$(THEOS)/makefiles/common.mk

TWEAK_NAME = FilzaWQ
FilzaWQ_FILES = FilzaWQ.xm Wq.m
FilzaWQ_CFLAGS = -fobjc-arc -I\$(THEOS_PROJECT_DIR)
FilzaWQ_FRAMEWORKS = Foundation UIKit
FilzaWQ_LDFLAGS = -Wl,-install_name,$INSTALL_NAME $REEXPORT

include \$(THEOS)/makefiles/tweak.mk
MK

echo "==> Building dylib"
if ! ( cd "$WORK/proj" && { make clean >/dev/null 2>&1 || true; }; make FINALPACKAGE=1 ); then
  echo "==> build failed"
  exit 1
fi
DYLIB="$(find "$WORK/proj/.theos" -name 'FilzaWQ.dylib' | sed -n '1p')"
[ -n "$DYLIB" ] || { echo "dylib not produced"; exit 1; }
echo "    $DYLIB ($(stat -c%s "$DYLIB") bytes)"

echo "==> Undefined symbols"
nm -u "$DYLIB" | sed 's/^/    /' || true
if nm -u "$DYLIB" | grep -Eq 'SecTask|_SecStaticCode|_csops'; then
  echo "private API linked directly; dyld will abort at launch" >&2
  exit 1
fi

echo "==> Installing dylib"
if [ "$MODE" = "slot" ]; then
  cp "$DYLIB" "$SLOT"
  echo "==> Disabling the self-check lookup"
  $TOOL rename "$BIN" SecStaticCodeCheckValidity SecStaticCodeCheckValiditq
  $TOOL rename "$BIN" SecStaticCodeCheckValidityWithErrors SecStaticCodeCheckValiditqWithErrors
else
  cp "$DYLIB" "$REHOST"
fi

echo "==> Stripping signatures"
$TOOL strip-signature "$BIN" || true
[ -f "$SLOT" ] && $TOOL strip-signature "$SLOT" || true
[ -f "$REHOST" ] && $TOOL strip-signature "$REHOST" || true
[ -f "$APP/Frameworks/lib7z_orig.dylib" ] && $TOOL strip-signature "$APP/Frameworks/lib7z_orig.dylib" || true
for fw in "$APP"/Frameworks/*.framework; do
  [ -d "$fw" ] || continue
  name="$(basename "$fw" .framework)"
  [ -f "$fw/$name" ] && $TOOL strip-signature "$fw/$name" || true
done
rm -rf "$APP/_CodeSignature" "$APP/embedded.mobileprovision"

echo "==> Packaging"
mkdir -p "$(dirname "$OUT")"
rm -f "$OUT"
( cd "$WORK/ipa" && zip -qry "$ROOT/$OUT" Payload )
echo "==> Done: $OUT ($(stat -c%s "$ROOT/$OUT") bytes)"
sha256sum "$ROOT/$OUT"
