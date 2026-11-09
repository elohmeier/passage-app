import KeyStore
import PassStore
import SwiftUI

/// What an entry view does after its entry was deleted (nil) or renamed. In the iPad split view
/// it updates the selection; elsewhere the entry view dismisses itself.
struct EntryMovedAction {
    let handler: (EntryPath?) -> Void
    func callAsFunction(_ entry: EntryPath?) { handler(entry) }
}

extension EnvironmentValues {
    @Entry var entryMoved: EntryMovedAction?
}

/// The iPad layout: folders in the sidebar, the folder's passwords (or search results) in
/// the middle, the selected password on the right. Keys and Settings open as sheets.
struct SplitBrowserView: View {
    @Environment(AppModel.self) private var model
    @Environment(StoreModel.self) private var store
    @Environment(\.scenePhase) private var scenePhase

    enum SidebarItem: Hashable {
        case all
        case folder(String)
    }

    enum Sheet: String, Identifiable {
        case keys, settings, decryptFile
        var id: String { rawValue }
    }

    @State private var sidebar: SidebarItem? = .all
    @State private var selection: EntryPath?
    @State private var query = ""
    @State private var sheet: Sheet?
    @FocusState private var searchFocused: Bool
    @State private var focusSearchWhenActive = false
    @State private var debugAutoFill: String?
    @State private var columns = NavigationSplitViewVisibility.all

    var body: some View {
        NavigationSplitView(columnVisibility: $columns) {
            FolderSidebar(selection: $sidebar)
                .navigationTitle(store.name)
                .toolbar {
                    ToolbarItem(placement: .topBarTrailing) {
                        Menu("More", systemImage: "ellipsis") {
                            Button("Keys", systemImage: "key") { sheet = .keys }
                            Button("Decrypt a File", systemImage: "doc.badge.ellipsis") { sheet = .decryptFile }
                            Button("Settings", systemImage: "gear") { sheet = .settings }
                        }
                    }
                }
        } content: {
            EntryListColumn(scope: sidebar ?? .all, query: query, selection: $selection)
                .searchable(text: $query, prompt: "Search \(store.snapshot.entries.count) Passwords")
                .searchFocused($searchFocused)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
        } detail: {
            if let selection {
                NavigationStack {
                    EntryView(entry: selection)
                        .id(selection)
                }
            } else {
                ContentUnavailableView(
                    "No Password Selected", systemImage: "key.horizontal",
                    description: Text("Choose a password to see it here."))
            }
        }
        .environment(\.entryMoved, EntryMovedAction { selection = $0 })
        // A deleted or synced-away entry shouldn't stay on screen.
        .onChange(of: store.snapshot) { _, snapshot in
            if let selection, !snapshot.entries.contains(selection) { self.selection = nil }
        }
        .sheet(item: $sheet) { sheet in
            NavigationStack {
                Group {
                    switch sheet {
                    case .keys: KeysView()
                    case .settings: SettingsView()
                    case .decryptFile: DecryptFileView()
                    }
                }
                .toolbar {
                    ToolbarItem(placement: .confirmationAction) {
                        Button("Done", role: .confirm) { self.sheet = nil }
                    }
                }
            }
        }
        .onChange(of: model.pendingRoute, initial: true) { _, route in
            guard let route else { return }
            model.pendingRoute = nil
            switch route {
            case .entry(let entry):
                sidebar = .all
                selection = entry
            case .search:
                focusSearchWhenActive = true
                focusSearchIfActive()
            }
        }
        .onChange(of: scenePhase) { _, _ in focusSearchIfActive() }
        #if DEBUG
            .onAppear(perform: applyDebugRoute)
            .modifier(DebugAutoFillSheet(target: $debugAutoFill))
        #endif
    }

    private func focusSearchIfActive() {
        guard focusSearchWhenActive, scenePhase == .active else { return }
        focusSearchWhenActive = false
        Task {
            try? await Task.sleep(for: .milliseconds(300))
            searchFocused = true
        }
    }

    #if DEBUG
        /// The iPad subset of `-PassageRoute`: `entry:`, `folder:`, `search:`, `keys`,
        /// `settings`, `autofill:`.
        private func applyDebugRoute() {
            guard let route = UserDefaults.standard.string(forKey: "PassageRoute") else { return }
            let parts = route.split(separator: ":", maxSplits: 1).map(String.init)
            let arg = parts.count > 1 ? parts[1] : ""
            switch parts.first {
            case "entry":
                sidebar = .folder(EntryPath(arg).folder)
                selection = EntryPath(arg)
            case "folder":
                sidebar = .folder(arg)
                // Show the folder tree, also in portrait where it's collapsed by default.
                Task {
                    try? await Task.sleep(for: .seconds(1))
                    columns = .all
                }
            case "search": query = arg
            case "keys": sheet = .keys
            case "settings": sheet = .settings
            case "autofill": debugAutoFill = arg
            default: break
            }
        }
    #endif
}

/// All Passwords and the folder tree.
private struct FolderSidebar: View {
    @Environment(StoreModel.self) private var store
    @Binding var selection: SplitBrowserView.SidebarItem?

    struct Node: Identifiable {
        let path: String
        var children: [Node]?
        var id: String { path }
        var name: String { EntryPath(path).name }
    }

    private var tree: [Node] {
        func nodes(in folder: String) -> [Node]? {
            let subfolders = store.snapshot.contents(of: folder).folders
            guard !subfolders.isEmpty else { return nil }
            return subfolders.map { Node(path: $0, children: nodes(in: $0)) }
        }
        return nodes(in: "") ?? []
    }

    var body: some View {
        List(selection: $selection) {
            Label("All Passwords", systemImage: "key.horizontal")
                .badge(store.snapshot.entries.count)
                .tag(SplitBrowserView.SidebarItem.all)
            if !tree.isEmpty {
                Section("Folders") {
                    OutlineGroup(tree, children: \.children) { node in
                        Label(node.name, systemImage: "folder")
                            .tag(SplitBrowserView.SidebarItem.folder(node.path))
                    }
                }
            }
        }
        .listStyle(.sidebar)
        .refreshable { await store.sync() }
    }
}

/// The passwords in a folder (and its subfolders), or search results across the store.
private struct EntryListColumn: View {
    @Environment(StoreModel.self) private var store
    let scope: SplitBrowserView.SidebarItem
    let query: String
    @Binding var selection: EntryPath?
    @State private var creating: EntryEditorView.Mode?
    @State private var settingUp = false

    private var folder: String {
        if case .folder(let f) = scope { return f }
        return ""
    }

    private var entries: [EntryPath] {
        if !query.isEmpty { return store.snapshot.search(query) }
        guard !folder.isEmpty else { return store.snapshot.entries }
        return store.snapshot.entries.filter { $0.path.hasPrefix(folder + "/") }
    }

    private var title: String {
        if !query.isEmpty { return String(localized: "Results") }
        return folder.isEmpty ? String(localized: "All Passwords") : EntryPath(folder).name
    }

    var body: some View {
        let entries = entries
        List(selection: $selection) {
            if query.isEmpty, folder.isEmpty {
                SyncStatusSection()
                RecipientChangesSection()
                SetUpStoreSection(settingUp: $settingUp)
                RecipientStatusSection()
            }
            Section {
                ForEach(entries) { entry in
                    VStack(alignment: .leading, spacing: 2) {
                        EntryLabel(entry: entry, title: entry.name)
                        let subfolder = relativeFolder(of: entry)
                        if !subfolder.isEmpty {
                            Text(subfolder)
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    }
                    .tag(entry)
                }
            }
        }
        .overlay {
            if !query.isEmpty, entries.isEmpty {
                ContentUnavailableView.search(text: query)
            } else if query.isEmpty, entries.isEmpty, !store.isLoading, !store.needsSetup {
                ContentUnavailableView("No Passwords", systemImage: "tray", description: Text("This folder contains no .age files."))
            }
        }
        .navigationTitle(title)
        .refreshable { await store.sync() }
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Button("New Password", systemImage: "plus") { creating = .new(folder: folder) }
                    .keyboardShortcut("n")
                    .disabled(store.needsSetup)
            }
        }
        .sheet(item: $creating) { mode in
            EntryEditorView(mode: mode) { saved in selection = saved }
        }
        .sheet(isPresented: $settingUp) { SetUpStoreView() }
    }

    /// The entry's folder below the current one, e.g. `work/vpn` in `work` shows nothing,
    /// `work/clients/acme` shows `clients`.
    private func relativeFolder(of entry: EntryPath) -> String {
        guard query.isEmpty, !folder.isEmpty else { return entry.folder }
        return entry.folder == folder ? "" : String(entry.folder.dropFirst(folder.count + 1))
    }
}
