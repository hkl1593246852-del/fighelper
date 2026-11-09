import SwiftUI

/// App Group that must exist in the provisioning profile. Replace the string if
/// you register a different one; WQAccess returns -1 when it cannot resolve.
let kAppGroup = "group.com.you.filzalite"

struct Entry: Identifiable {
    let path: String
    var id: String { path }
    var name: String { (path as NSString).lastPathComponent }
}

struct BrowserView: View {
    @State private var cwd = "/var/mobile/Containers/Data/Application"
    @State private var entries: [Entry] = []
    @State private var status = "idle"
    @State private var busy = false
    @State private var preview: String?
    @State private var handle: Int64 = -1

    var body: some View {
        NavigationStack {
            List {
                Section {
                    Text(status).font(.system(.footnote, design: .monospaced))
                }
                Section("entries (\(entries.count))") {
                    ForEach(entries) { e in
                        Button {
                            Task { await open(e.path) }
                        } label: {
                            HStack {
                                Image(systemName: e.name.contains(".") ? "doc" : "folder")
                                Text(e.name).font(.system(.body, design: .monospaced))
                            }
                        }
                    }
                }
            }
            .navigationTitle(cwd)
            .toolbar {
                ToolbarItem(placement: .topBarLeading) {
                    Button("Up") { Task { await open((cwd as NSString).deletingLastPathComponent) } }
                }
                ToolbarItem(placement: .topBarTrailing) {
                    Button("Reload") { Task { await load() } }
                }
            }
            .task { await load() }
            .sheet(item: Binding(get: { preview.map(Preview.init) }, set: { _ in preview = nil })) {
                Text($0.text).font(.system(.footnote, design: .monospaced)).padding()
            }
        }
    }

    struct Preview: Identifiable {
        let text: String
        var id: String { text }
    }

    private func access(_ path: String) -> Int64 {
        if handle > 0 { WQRelease(handle) }
        handle = WQAccess(path, kAppGroup, 0)
        if handle < 0 && handle != -255 {
            handle = WQAccess(path, kAppGroup, 1)   // iOS 26.x flag set
        }
        return handle
    }

    private func load() async {
        busy = true
        defer { busy = false }
        let h = access(cwd)
        status = "access(\(cwd)) = \(h)"
        let list = WQEntries(cwd, 400_000) as? [String] ?? []
        entries = list.map { Entry(path: (cwd as NSString).appendingPathComponent($0)) }
        status += "  entries=\(entries.count)"
    }

    private func open(_ path: String) async {
        var isDir: ObjCBool = false
        let exists = FileManager.default.fileExists(atPath: path, isDirectory: &isDir)
        if !exists || isDir.boolValue {
            cwd = path
            await load()
            return
        }
        let h = access(path)
        guard h >= 0 else {
            status = "open \(path) denied (h=\(h))"
            return
        }
        if let data = FileManager.default.contents(atPath: path) {
            preview = "\(path)\n\(data.count) bytes\n\n"
                + (String(data: data.prefix(4000), encoding: .utf8) ?? "<binary>")
        } else {
            status = "read failed \(path)"
        }
    }
}
