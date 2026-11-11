"""Mach-O helpers that run anywhere (no Xcode, no codesign, no install_name_tool).

Commands:
  strip-signature <file>              remove LC_CODE_SIGNATURE and truncate the blob
  set-id <file> <old> <new>           rewrite an LC_ID_DYLIB / LC_REEXPORT path
  rename <file> <old> <new>           replace a byte string of equal length
  executable <Info.plist>             print CFBundleExecutable
  set-bundle-id <Info.plist> <id>     rewrite CFBundleIdentifier
"""
import plistlib
import struct
import sys

LC_SEGMENT_64 = 0x19
LC_CODE_SIGNATURE = 0x1D
LC_ID_DYLIB = 0x0D
LC_REEXPORT_DYLIB = 0x8000001F


def strip_signature(path):
    data = bytearray(open(path, "rb").read())
    magic, = struct.unpack_from("<I", data, 0)
    if magic != 0xFEEDFACF:
        print("not a 64-bit Mach-O")
        return 1

    ncmds, sizeofcmds = struct.unpack_from("<II", data, 16)

    off = 32
    found = None
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", data, off)
        if cmd == LC_CODE_SIGNATURE:
            dataoff, datasize = struct.unpack_from("<II", data, off + 8)
            found = (off, cmdsize, dataoff, datasize)
            break
        off += cmdsize

    if found is None:
        print("no LC_CODE_SIGNATURE")
        return 0

    cmd_off, cmd_size, data_off, data_size = found
    # drop the load command and close the gap
    del data[cmd_off:cmd_off + cmd_size]
    struct.pack_into("<II", data, 16, ncmds - 1, sizeofcmds - cmd_size)
    # the signature blob sits at the end of the file
    if data_off + data_size <= len(data):
        del data[data_off:data_off + data_size]

    open(path, "wb").write(data)
    print(f"stripped LC_CODE_SIGNATURE ({data_size} bytes)")
    return 0


def set_id(path, old, new):
    data = bytearray(open(path, "rb").read())
    old_b = old.encode() + b"\0"
    new_b = new.encode() + b"\0"
    if len(new_b) > len(old_b):
        print("replacement longer than original")
        return 1
    i = data.find(old_b)
    if i < 0:
        print("string not found")
        return 1
    data[i:i + len(old_b)] = new_b + b"\0" * (len(old_b) - len(new_b))
    open(path, "wb").write(data)
    print(f"id set to {new}")
    return 0


def rename(path, old, new):
    if len(old) != len(new):
        print("lengths differ")
        return 1
    data = open(path, "rb").read()
    n = data.count(old.encode())
    if n == 0:
        print("no occurrences")
        return 0
    open(path, "wb").write(data.replace(old.encode(), new.encode()))
    print(f"renamed {n} occurrence(s)")
    return 0


def executable(plist_path):
    info = plistlib.loads(open(plist_path, "rb").read())
    print(info.get("CFBundleExecutable", ""))
    return 0


def set_bundle_id(plist_path, value):
    info = plistlib.loads(open(plist_path, "rb").read())
    info["CFBundleIdentifier"] = value
    open(plist_path, "wb").write(plistlib.dumps(info, fmt=plistlib.FMT_BINARY))
    print(f"bundle id set to {value}")
    return 0


def main(argv):
    cmd = argv[1]
    if cmd == "strip-signature":
        return strip_signature(argv[2])
    if cmd == "set-id":
        return set_id(argv[2], argv[3], argv[4])
    if cmd == "rename":
        return rename(argv[2], argv[3], argv[4])
    if cmd == "executable":
        return executable(argv[2])
    if cmd == "set-bundle-id":
        return set_bundle_id(argv[2], argv[3])
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
