#!/bin/bash
# Build our diagnostic dylib into a Filza base and repackage an unsigned IPA.
#
# Two base layouts are supported:
#
#   slot   - the base already links Frameworks/FilzaApplySandboxExt.dylib
#            (Filza 4.0.0 bases, e.g. MchinaMd57764/filza-wq). The dylib is
#            replaced in place, so the main binary and its load commands stay
#            untouched and no integrity check fires.
#
#   rehost - a stock Filza that links @rpath/lib7z.framework/lib7z (5.0.x, which
#            validates Filza.signature over its main binary). The dylib takes
#            over that path and re-exports the real lib7z so symbols still
#            resolve and the main binary stays byte-identical.
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
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "==> Unpacking base IPA"
mkdir -p "$WORK/ipa"
unzip -q "$IPA" -d "$WORK/ipa"
APP="$(find "$WORK/ipa/Payload" -maxdepth 1 -name '*.app' -type d | head -n 1)"
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
  echo "==> Mode: slot (existing FilzaApplySandboxExt slot)"
elif [ -f "$REHOST" ]; then
  MODE=rehost
  INSTALL_NAME="@rpath/lib7z.framework/lib7z"
  echo "==> Mode: rehost (lib7z slot)"
else
  echo "base has neither a FilzaApplySandboxExt nor a lib7z slot"; exit 1
fi

if [ "$MODE" = "rehost" ]; then
  echo "==> Moving the original lib7z aside"
  cp "$REHOST" "$WORK/lib7z_orig.dylib"
  install_name_tool -id "@executable_path/Frameworks/lib7z_orig.dylib" "$WORK/lib7z_orig.dylib"
  cp "$WORK/lib7z_orig.dylib" "$APP/Frameworks/lib7z_orig.dylib"
fi

echo "==> Disabling Filza's self-check lookup"
# Filza resolves the code-signing verifier with dlsym. Renaming the symbol it asks
# for makes the lookup fail, and the check is skipped. Same length, so no offsets
# move.
python3 - "$BIN" <<'PY'
import sys

path = sys.argv[1]
data = bytearray(open(path, "rb").read())
targets = [
    (b"SecStaticCodeCheckValidity", b"SecStaticCodeCheckValiditq"),
    (b"SecStaticCodeCheckValidityWithErrors", b"SecStaticCodeCheckValiditqWithErrors"),
]
patched = 0
for old, new in targets:
    assert len(old) == len(new)
    n = data.count(old)
    if n:
        data = data.replace(old, new)
        patched += n
        print(f"  renamed {old.decode()} x{n}")
if patched == 0:
    print("  no lookup strings found")
open(path, "wb").write(data)
PY

echo "==> Staging tweak project"
mkdir -p "$WORK/proj"
cp "$ROOT/flzq/FilzaWQ.xm" "$WORK/proj/"
cp "$ROOT/flzq/Wq.h"       "$WORK/proj/"
cp "$ROOT/flz/Wq.m"        "$WORK/proj/"

REEXPORT=""
if [ "$MODE" = "rehost" ]; then
  REEXPORT="-Wl,-reexport_library,$WORK/lib7z_orig.dylib"
fi

cat > "$WORK/proj/Makefile" <<MK
ARCHS = arm64
TARGET = iphone:clang:latest:15.0
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
DYLIB="$(find "$WORK/proj/.theos" -name 'FilzaWQ.dylib' | head -n 1)"
[ -n "$DYLIB" ] || { echo "dylib not produced"; exit 1; }
echo "    $DYLIB ($(stat -f%z "$DYLIB") bytes)"

echo "==> Undefined symbols"
nm -u "$DYLIB" | sed 's/^/    /'
if nm -u "$DYLIB" | grep -Eq 'SecTask|_SecStaticCode|_csops'; then
  echo "private API is linked directly; dyld will abort at launch" >&2
  exit 1
fi

echo "==> Installing dylib"
if [ "$MODE" = "slot" ]; then
  cp "$DYLIB" "$SLOT"
else
  cp "$DYLIB" "$REHOST"
fi

echo "==> Signing"
codesign -f -s - "$APP/Frameworks/lib7z_orig.dylib" 2>/dev/null || true
find "$APP/Frameworks" -maxdepth 2 \( -name '*.dylib' -o -name '*.framework' \) -exec codesign -f -s - {} \; 2>/dev/null || true
codesign -f -s - "$APP" 2>/dev/null || true

echo "==> Packaging"
mkdir -p "$(dirname "$OUT")"
rm -f "$OUT"
( cd "$WORK/ipa" && zip -qry "$ROOT/$OUT" Payload )
echo "==> Done: $OUT ($(stat -f%z "$ROOT/$OUT") bytes)"
shasum -a 256 "$ROOT/$OUT"
