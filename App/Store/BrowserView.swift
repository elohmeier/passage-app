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
    @Environment(StoreModel.self) private var store
    @State private var path = NavigationPath()
    @State private var query = ""

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

struct FolderView: View {
    @Environment(StoreModel.self) private var store
    let folder: String

    var body: some View {
        let contents = store.snapshot.contents(of: folder)
        List {
            ForEach(contents.folders, id: \.self) { f in
                NavigationLink(value: Route.folder(f)) {
                    Label(EntryPath(f).name, systemImage: "folder")
                }
            }
            ForEach(contents.entries) { entry in
                NavigationLink(value: Route.entry(entry)) {
                    Label(entry.name, systemImage: "key.horizontal")
                }
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
        .refreshable { await store.refresh() }
    }
}

struct SearchResultsView: View {
    let results: [EntryPath]

    var body: some View {
        List(results) { entry in
            NavigationLink(value: Route.entry(entry)) {
                VStack(alignment: .leading) {
                    Text(entry.name)
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
