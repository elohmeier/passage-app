import KeyStore
import PassStore
import SwiftUI

@main
struct PassageApp: App {
    init() {
        StoreModel.beginBackgroundTask = {
            let id = UIApplication.shared.beginBackgroundTask(withName: "Sync")
            return { UIApplication.shared.endBackgroundTask(id) }
        }
    }

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
                .onChange(of: model.identities, initial: true) { _, identities in store.identities = identities }
                .onAppear {
                    #if DEBUG
                        if UserDefaults.standard.bool(forKey: "PassageReset") { store.close() }
                        // Screenshot/automation hook: `-PassageDemo YES` opens the demo store with an
                        // unprotected key (the Simulator can't answer Face ID prompts unattended).
                        if UserDefaults.standard.bool(forKey: "PassageDemo"), store.store == nil {
                            store.openDemoStore(using: model, protection: .unprotected)
                            return
                        }
                    #endif
                    store.restore()
                    #if DEBUG
                        // `-PassageDebugAddRecipient YES` taps "Add This Device as Recipient" after the first sync.
                        if UserDefaults.standard.bool(forKey: "PassageDebugAddRecipient") {
                            Task {
                                try? await Task.sleep(for: .seconds(4))
                                do { try await store.addDeviceAsRecipient() } catch { store.errorMessage = error.localizedDescription }
                            }
                        }
                        // `-PassageDebugSave <path>` writes a test entry through the normal save path.
                        if let path = UserDefaults.standard.string(forKey: "PassageDebugSave") {
                            Task {
                                do {
                                    try await store.save(EntryPath(path), text: "debug-\(Int(Date.now.timeIntervalSince1970))\nusername: simulator\n", isNew: true)
                                } catch {
                                    store.errorMessage = error.localizedDescription
                                }
                            }
                        }
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
                    "Conflicting Edits", isPresented: Binding(get: { !store.conflictCopies.isEmpty }, set: { if !$0 { store.conflictCopies = [] } })
                ) {
                    Button("OK") {}
                } message: {
                    Text("Another device changed the same entries. Their version is kept, and yours was saved alongside as:\n\n\(store.conflictCopies.joined(separator: "\n"))\n\nCompare them and delete the one you don't need.")
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
            case .active where store.gitConfig != nil: Task { await store.sync(.automatic) }
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
