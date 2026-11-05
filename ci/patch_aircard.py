"""Rewrite AirCard-iOS/project.yml so the static AirliftFFI library links.

XcodeGen models an xcframework dependency as a framework, which only yields
FRAMEWORK_SEARCH_PATHS; AirliftFFI is a static .a plus a modulemap, so Swift
needs the include path and the linker needs -lairlift_ffi.
"""
import pathlib
import sys

ROOT = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "aircard")
p = ROOT / "project.yml"
s = p.read_text()

old_dep = """    dependencies:
      - framework: AirliftFFI.xcframework
        embed: false
"""
if old_dep in s:
    s = s.replace(old_dep, "")

old_flags = '        OTHER_LDFLAGS: "-lc++"'
new_flags = (
    '        OTHER_LDFLAGS: "-lairlift_ffi -lc++"\n'
    '        LIBRARY_SEARCH_PATHS: "$(SRCROOT)/AirliftFFI.xcframework/ios-arm64"\n'
    '        SWIFT_INCLUDE_PATHS: "$(SRCROOT)/AirliftFFI.xcframework/ios-arm64/Headers"\n'
    '        HEADER_SEARCH_PATHS: "$(SRCROOT)/AirliftFFI.xcframework/ios-arm64/Headers"'
)
if old_flags in s:
    s = s.replace(old_flags, new_flags)
else:
    print("warning: OTHER_LDFLAGS line not found, project.yml left as is", file=sys.stderr)

p.write_text(s)
print(s)
