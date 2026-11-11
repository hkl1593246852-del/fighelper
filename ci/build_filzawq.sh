#!/bin/bash
# Build the diagnostic dylib into a Filza base and repackage an unsigned IPA.
# macOS runner: Xcode toolchain and Theos, no shims.
#
#   slot   - the base already links Frameworks/FilzaApplySandboxExt.dylib
#   rehost - a stock Filza linking @rpath/lib7z.framework/lib7z; the dylib takes
#            that path and re-exports the real library, so the main binary keeps
#            its load commands and Filza.signature still validates
#
# Usage: ci/build_filzawq.sh <base.ipa> [out.ipa]
set -euo pipefail

IPA="${1:?usage: build_filzawq.sh <base.ipa> [out.ipa]}"
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
  echo "==> No Xcode SDK; falling back to theos/sdks"
  if [ ! -d "$THEOS/sdks" ] || [ -z "$(ls -A "$THEOS/sdks" 2>/dev/null)" ]; then
    git clone --depth 1 https://github.com/theos/sdks "$THEOS/sdks"
  fi
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "==> Unpacking base IPA"
mkdir -p "$WORK/ipa"
unzip -q "$IPA" -d "$WORK/ipa"
APP="$(find "$WORK/ipa/Payload" -maxdepth 1 -name '*.app' -type d | sed -n '1p')"
[ -n "$APP" ] || { echo "no .app in Payload"; exit 1; }
EXEC_NAME="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleExecutable' "$APP/Info.plist")"
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
  install_name_tool -id "@rpath/lib7z_orig.dylib" "$WORK/lib7z_orig.dylib"
  cp "$WORK/lib7z_orig.dylib" "$APP/Frameworks/lib7z_orig.dylib"
fi

echo "==> Staging tweak project"
mkdir -p "$WORK/proj"
cp "$ROOT/flzq/FilzaWQ.xm" "$WORK/proj/"
cp "$ROOT/flzq/Wq.h"       "$WORK/proj/"
cp "$ROOT/flzq/Mcm.h"      "$WORK/proj/"
cp "$ROOT/flzq/Mcm.m"      "$WORK/proj/"
cp "$ROOT/flz/Wq.m"        "$WORK/proj/"

REEXPORT=""
[ "$MODE" = "rehost" ] && REEXPORT="-Wl,-reexport_library,$WORK/lib7z_orig.dylib"

cat > "$WORK/proj/Makefile" <<MK
ARCHS = arm64
TARGET = iphone:clang:latest:15.0
INSTALL_TARGET_PROCESSES = Filza

include \$(THEOS)/makefiles/common.mk

TWEAK_NAME = FilzaWQ
FilzaWQ_FILES = FilzaWQ.xm Wq.m Mcm.m
FilzaWQ_CFLAGS = -fobjc-arc -I\$(THEOS_PROJECT_DIR)
FilzaWQ_FRAMEWORKS = Foundation UIKit
FilzaWQ_LDFLAGS = -Wl,-install_name,$INSTALL_NAME $REEXPORT

include \$(THEOS)/makefiles/tweak.mk
MK

echo "==> Building dylib"
if ! ( cd "$WORK/proj" && { make clean >/dev/null 2>&1 || true; }; make FINALPACKAGE=1 ); then
  echo "==> build failed"; exit 1
fi
DYLIB="$(find "$WORK/proj/.theos" -name 'FilzaWQ.dylib' | sed -n '1p')"
[ -n "$DYLIB" ] || { echo "dylib not produced"; exit 1; }
echo "    $DYLIB ($(stat -f%z "$DYLIB") bytes)"

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
  python3 - "$BIN" <<'PY'
import sys
path = sys.argv[1]
data = bytearray(open(path, "rb").read())
for old, new in ((b"SecStaticCodeCheckValidity", b"SecStaticCodeCheckValiditq"),
                 (b"SecStaticCodeCheckValidityWithErrors", b"SecStaticCodeCheckValiditqWithErrors")):
    n = data.count(old)
    if n:
        data = data.replace(old, new)
        print(f"  renamed {old.decode()} x{n}")
open(path, "wb").write(data)
PY
else
  cp "$DYLIB" "$REHOST"
fi

echo "==> Stripping signatures"
codesign --remove-signature "$BIN" 2>/dev/null || true
[ -f "$SLOT" ] && codesign --remove-signature "$SLOT" 2>/dev/null || true
[ -f "$REHOST" ] && codesign --remove-signature "$REHOST" 2>/dev/null || true
[ -f "$APP/Frameworks/lib7z_orig.dylib" ] && codesign --remove-signature "$APP/Frameworks/lib7z_orig.dylib" 2>/dev/null || true
for fw in "$APP"/Frameworks/*.framework; do
  [ -d "$fw" ] || continue
  name="$(basename "$fw" .framework)"
  [ -f "$fw/$name" ] && codesign --remove-signature "$fw/$name" 2>/dev/null || true
done
rm -rf "$APP/_CodeSignature" "$APP/embedded.mobileprovision"

echo "==> Packaging"
mkdir -p "$(dirname "$OUT")"
rm -f "$OUT"
( cd "$WORK/ipa" && zip -qry "$ROOT/$OUT" Payload )
echo "==> Done: $OUT ($(stat -f%z "$ROOT/$OUT") bytes)"
shasum -a 256 "$ROOT/$OUT"
