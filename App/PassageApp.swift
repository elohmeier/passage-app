import KeyStore
import SwiftUI

@main
struct PassageApp: App {
    @State private var model = AppModel.live()
    @State private var store = StoreModel(
        defaults: AppModel.sharedDefaults,
        secrets: KeychainSecretStore(service: AppConfig.keychainService + ".git", accessGroup: AppConfig.keychainAccessGroup))
    @Environment(\.scenePhase) private var scenePhase

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environment(model)
                .environment(store)
                .onAppear {
                    #if DEBUG
                        // Screenshot/automation hook: `-PassageDemo YES` opens the demo store with an
                        // unprotected key (the Simulator can't answer Face ID prompts unattended).
                        if UserDefaults.standard.bool(forKey: "PassageDemo"), store.store == nil {
                            store.openDemoStore(using: model, protection: .unprotected)
                            return
                        }
                    #endif
                    store.restore()
                    #if DEBUG
                        // `-PassageClone <url>` clones a repository on launch.
                        if let remote = UserDefaults.standard.string(forKey: "PassageClone"), store.gitConfig?.remote != remote {
                            Task {
                                do {
                                    try await store.clone(remote: remote, branch: nil, username: "", password: "")
                                } catch {
                                    store.errorMessage = error.localizedDescription
                                }
                            }
                        }
                    #endif
                }
                // Hide content in the app switcher.
                .overlay {
                    if scenePhase != .active {
                        PrivacyCover()
                    }
                }
                .alert(
                    "Error", isPresented: Binding(get: { model.errorMessage != nil }, set: { if !$0 { model.errorMessage = nil } })
                ) {
                    Button("OK") {}
                } message: {
                    Text(model.errorMessage ?? "")
                }
                .alert(
                    "Store Error", isPresented: Binding(get: { store.errorMessage != nil }, set: { if !$0 { store.errorMessage = nil } })
                ) {
                    Button("OK") {}
                } message: {
                    Text(store.errorMessage ?? "")
                }
        }
        .onChange(of: scenePhase) { _, phase in
            switch phase {
            case .background: model.lock()
            // Pick up changes from other devices whenever the app comes back.
            case .active where store.gitConfig != nil: Task { await store.sync() }
            default: break
            }
        }
    }
}

struct PrivacyCover: View {
    var body: some View {
        ZStack {
            Rectangle().fill(.regularMaterial)
            Image(systemName: "lock.fill")
                .font(.system(size: 48))
                .foregroundStyle(.secondary)
        }
        .ignoresSafeArea()
    }
}
