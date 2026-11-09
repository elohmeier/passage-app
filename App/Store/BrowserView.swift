import KeyStore
import PassStore
import SwiftUI

enum Route: Hashable {
    case folder(String)
    case entry(EntryPath)
    case keys
    case identity(StoredIdentity)
    case settings
    case decryptFile
}

struct BrowserView: View {
    @Environment(AppModel.self) private var model
    @Environment(StoreModel.self) private var store
    @State private var path = NavigationPath()
    @State private var query = ""
    @FocusState private var searchFocused: Bool
    @State private var focusSearchWhenActive = false
    @Environment(\.scenePhase) private var scenePhase

    private func focusSearchIfActive() {
        guard focusSearchWhenActive, scenePhase == .active else { return }
        focusSearchWhenActive = false
        Task {
            try? await Task.sleep(for: .milliseconds(300))
            searchFocused = true
        }
    }
    @State private var debugEditor: EntryEditorView.Mode?
    @State private var debugAutoFill: String?

    var body: some View {
        NavigationStack(path: $path) {
            // One view for both browsing and searching: swapping views when the query becomes
            // non-empty would drop the search field's focus after the first keystroke.
            FolderView(folder: "", query: query)
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
            .onChange(of: model.pendingRoute, initial: true) { _, route in
                guard let route else { return }
                model.pendingRoute = nil
                switch route {
                case .entry(let entry):
                    path = NavigationPath()
                    path.append(Route.entry(entry))
                case .search:
                    path = NavigationPath()
                    focusSearchWhenActive = true
                    focusSearchIfActive()
                }
            }
            // An intent can set the route while the app is still coming back from the
            // background, when focusing does nothing. Apply it once the scene is active.
            .onChange(of: scenePhase) { _, _ in focusSearchIfActive() }
            .searchFocused($searchFocused)
            #if DEBUG
                .onAppear(perform: applyDebugRoute)
                .sheet(item: $debugEditor) { EntryEditorView(mode: $0) }
                .sheet(isPresented: Binding(get: { debugAutoFill != nil }, set: { if !$0 { debugAutoFill = nil } })) {
                    // The AutoFill extension's picker, hosted in the app for screenshots.
                    let target = debugAutoFill ?? ""
                    let kind: PickerKind = target.hasPrefix("passkey:")
                        ? .passkey(PasskeyRequest(relyingParty: String(target.dropFirst(8)), clientDataHash: Data(count: 32), allowedCredentials: []))
                        : .password
                    CredentialPickerView(
                        kind: kind, services: [target], autoSelect: nil, cancel: { debugAutoFill = nil },
                        complete: { _ in debugAutoFill = nil })
                }
            #endif
            .navigationDestination(for: Route.self) { route in
                switch route {
                case .folder(let f): FolderView(folder: f)
                case .entry(let e): EntryView(entry: e)
                case .keys: KeysView()
                case .identity(let identity): IdentityDetailView(identity: identity)
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
            case "autofill": debugAutoFill = arg
            case "autofillpasskey": debugAutoFill = "passkey:" + arg
            case "identity":
                if let device = model.deviceIdentity { path.append(Route.identity(device)) }
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
    /// Non-empty: show search results across the store instead of the folder.
    var query: String = ""
    @State private var creating: EntryEditorView.Mode?
    #if DEBUG
        @State private var settingUp = UserDefaults.standard.bool(forKey: "PassageDebugSetUpSheet")
    #else
        @State private var settingUp = false
    #endif

    var body: some View {
        let contents = store.snapshot.contents(of: folder)
        let results = query.isEmpty ? [] : store.snapshot.search(query)
        List {
            if !query.isEmpty {
                ForEach(results) { SearchResultRow(entry: $0) }
            } else {
                if folder.isEmpty {
                    SyncStatusSection()
                    SetUpStoreSection(settingUp: $settingUp)
                    RecipientStatusSection()
                }
                ForEach(contents.folders, id: \.self) { f in
                    NavigationLink(value: Route.folder(f)) {
                        Label(EntryPath(f).name, systemImage: "folder")
                    }
                }
                ForEach(contents.entries) { entry in
                    NavigationLink(value: Route.entry(entry)) { EntryLabel(entry: entry, title: entry.name) }
                }
            }
        }
        .overlay {
            if !query.isEmpty {
                if results.isEmpty { ContentUnavailableView.search(text: query) }
            } else if contents.folders.isEmpty && contents.entries.isEmpty && !store.isLoading && !(folder.isEmpty && store.needsSetup) {
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
                    .disabled(store.needsSetup)
            }
        }
        .sheet(item: $creating) { EntryEditorView(mode: $0) }
        .sheet(isPresented: $settingUp) { SetUpStoreView() }
    }
}

struct SearchResultRow: View {
    let entry: EntryPath

    var body: some View {
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
