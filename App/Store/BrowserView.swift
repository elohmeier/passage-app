import PassStore
import SwiftUI

enum Route: Hashable {
    case folder(String)
    case entry(EntryPath)
    case keys
    case settings
    case decryptFile
}

struct BrowserView: View {
    @Environment(AppModel.self) private var model
    @Environment(StoreModel.self) private var store
    @State private var path = NavigationPath()
    @State private var query = ""
    @State private var debugEditor: EntryEditorView.Mode?

    var body: some View {
        NavigationStack(path: $path) {
            Group {
                if query.isEmpty {
                    FolderView(folder: "")
                } else {
                    SearchResultsView(results: store.snapshot.search(query))
                }
            }
            .navigationTitle(store.name)
            .searchable(text: $query, prompt: "Search \(store.snapshot.entries.count) Passwords")
            .textInputAutocapitalization(.never)
            .autocorrectionDisabled()
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Menu("More", systemImage: "ellipsis") {
                        Button("Keys", systemImage: "key") { path.append(Route.keys) }
                        Button("Decrypt a File", systemImage: "doc.badge.ellipsis") { path.append(Route.decryptFile) }
                        Button("Settings", systemImage: "gear") { path.append(Route.settings) }
                    }
                }
            }
            #if DEBUG
                .onAppear(perform: applyDebugRoute)
                .sheet(item: $debugEditor) { EntryEditorView(mode: $0) }
            #endif
            .navigationDestination(for: Route.self) { route in
                switch route {
                case .folder(let f): FolderView(folder: f)
                case .entry(let e): EntryView(entry: e)
                case .keys: KeysView()
                case .settings: SettingsView()
                case .decryptFile: DecryptFileView()
                }
            }
        }
    }
}

#if DEBUG
    extension BrowserView {
        /// `-PassageRoute entry:path`, `folder:path`, `search:query`, `keys` or `settings`.
        fileprivate func applyDebugRoute() {
            guard path.isEmpty, let route = UserDefaults.standard.string(forKey: "PassageRoute") else { return }
            let (kind, arg) = route.split(separator: ":", maxSplits: 1).map(String.init).splitFirst()
            switch kind {
            case "entry": path.append(Route.entry(EntryPath(arg)))
            case "folder": path.append(Route.folder(arg))
            case "search": query = arg
            case "keys": path.append(Route.keys)
            case "new": debugEditor = .new(folder: arg)
            case "identity":
                path.append(Route.keys)
                if let device = model.deviceIdentity { path.append(device) }
            case "settings": path.append(Route.settings)
            default: break
            }
        }
    }

    extension Array where Element == String {
        fileprivate func splitFirst() -> (String, String) { (first ?? "", count > 1 ? self[1] : "") }
    }
#endif

struct FolderView: View {
    @Environment(StoreModel.self) private var store
    let folder: String
    @State private var creating: EntryEditorView.Mode?

    var body: some View {
        let contents = store.snapshot.contents(of: folder)
        List {
            if folder.isEmpty { RecipientStatusSection() }
            ForEach(contents.folders, id: \.self) { f in
                NavigationLink(value: Route.folder(f)) {
                    Label(EntryPath(f).name, systemImage: "folder")
                }
            }
            ForEach(contents.entries) { entry in
                NavigationLink(value: Route.entry(entry)) { EntryLabel(entry: entry, title: entry.name) }
            }
        }
        .overlay {
            if contents.folders.isEmpty && contents.entries.isEmpty && !store.isLoading {
                ContentUnavailableView(
                    "No Passwords", systemImage: "tray",
                    description: Text("This folder contains no .age files."))
            }
        }
        .navigationTitle(folder.isEmpty ? store.name : EntryPath(folder).name)
        .refreshable { await store.sync() }
        .toolbar {
            ToolbarItem(placement: .bottomBar) {
                Button("New Password", systemImage: "plus") { creating = .new(folder: folder) }
            }
        }
        .sheet(item: $creating) { EntryEditorView(mode: $0) }
    }
}

struct SearchResultsView: View {
    let results: [EntryPath]

    var body: some View {
        List(results) { entry in
            NavigationLink(value: Route.entry(entry)) {
                VStack(alignment: .leading) {
                    EntryLabel(entry: entry, title: entry.name)
                    if !entry.folder.isEmpty {
                        Text(entry.folder)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
            }
        }
        .overlay {
            if results.isEmpty { ContentUnavailableView.search }
        }
    }
}

/// An entry row; dimmed with a lock-slash icon if it isn't encrypted to this device.
struct EntryLabel: View {
    @Environment(StoreModel.self) private var store
    let entry: EntryPath
    let title: String

    var body: some View {
        let unreadable = store.readability?.unreadable.contains(entry) == true
        Label(title, systemImage: unreadable ? "lock.slash" : "key.horizontal")
            .foregroundStyle(unreadable ? .secondary : .primary)
            .accessibilityHint(unreadable ? Text("Not encrypted to this device yet") : Text(""))
    }
}
