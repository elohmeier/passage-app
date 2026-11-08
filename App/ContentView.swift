import SwiftUI

struct ContentView: View {
    @Environment(StoreModel.self) private var store

    var body: some View {
        if store.store == nil {
            WelcomeView()
        } else {
            BrowserView()
        }
    }
}

/// Shown when no store is open.
struct WelcomeView: View {
    @Environment(AppModel.self) private var model
    @Environment(StoreModel.self) private var store
    @State private var showingPicker = false

    var body: some View {
        NavigationStack {
            List {
                Section {
                    ContentUnavailableView {
                        Label("No Password Store", systemImage: "lock.rectangle.stack")
                    } description: {
                        Text("Open the folder that contains your passage store, for example in iCloud Drive or another Files location.")
                    } actions: {
                        Button("Open Folder…", systemImage: "folder") { showingPicker = true }
                            .buttonStyle(.borderedProminent)
                    }
                }
                Section {
                    NavigationLink {
                        KeysView()
                    } label: {
                        Label("Keys", systemImage: "key")
                            .badge(model.identities.count)
                    }
                } footer: {
                    if model.deviceIdentity == nil {
                        Text("Create this device's key first, and add its recipient to your store's .age-recipients.")
                    }
                }
            }
            .navigationTitle("Passage")
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    NavigationLink {
                        SettingsView()
                    } label: {
                        Label("Settings", systemImage: "gear")
                    }
                }
            }
            .fileImporter(isPresented: $showingPicker, allowedContentTypes: [.folder]) { result in
                if case .success(let url) = result { store.open(pickedURL: url) }
            }
        }
    }
}

#Preview {
    ContentView()
        .environment(AppModel.preview())
        .environment(StoreModel(defaults: UserDefaults(suiteName: "preview")!))
}
