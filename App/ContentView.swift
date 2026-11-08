import KeyStore
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
    private var debugCloneURL: String {
        #if DEBUG
            UserDefaults.standard.string(forKey: "PassageCloneURL") ?? ""
        #else
            ""
        #endif
    }

    @Environment(AppModel.self) private var model
    @Environment(StoreModel.self) private var store
    @State private var showingPicker = false
    @State private var showingClone = false
    @State private var showingGitHub = false

    var body: some View {
        NavigationStack {
            List {
                Section {
                    VStack(spacing: 12) {
                        Image(systemName: "lock.rectangle.stack")
                            .font(.system(size: 52))
                            .foregroundStyle(.tint)
                        Text("No Password Store")
                            .font(.title2.bold())
                        Text("Open the folder that contains your passage store, for example in iCloud Drive, or clone it from a git repository.")
                            .multilineTextAlignment(.center)
                            .foregroundStyle(.secondary)
                    }
                    .frame(maxWidth: .infinity)
                    .padding(.vertical)
                    .listRowBackground(Color.clear)
                }
                Section {
                    if AppConfig.gitHubClientID != nil {
                        Button("Connect GitHub", systemImage: "link") { showingGitHub = true }
                    }
                    Button("Open Folder…", systemImage: "folder") { showingPicker = true }
                    Button("Clone Git Repository…", systemImage: "arrow.triangle.branch") { showingClone = true }
                    Button("Try Demo Store", systemImage: "sparkles") { store.openDemoStore(using: model) }
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
            .sheet(isPresented: $showingClone) { CloneView(remote: debugCloneURL) }
            .sheet(isPresented: $showingGitHub) {
                if let id = AppConfig.gitHubClientID, let slug = AppConfig.gitHubAppSlug {
                    GitHubConnectView(clientID: id, appSlug: slug)
                }
            }
            #if DEBUG
                .onAppear {
                    if UserDefaults.standard.string(forKey: "PassageRoute") == "clone" { showingClone = true }
                    if UserDefaults.standard.string(forKey: "PassageRoute") == "github" { showingGitHub = true }
                }
            #endif
            .fileImporter(isPresented: $showingPicker, allowedContentTypes: [.folder]) { result in
                if case .success(let url) = result { store.open(pickedURL: url) }
            }
        }
    }
}

#Preview {
    ContentView()
        .environment(AppModel.preview())
        .environment(StoreModel(defaults: UserDefaults(suiteName: "preview")!, secrets: InMemorySecretStore()))
}
