import AuthenticationServices
import BackgroundTasks
import KeyStore
import PassStore
import SwiftUI

@main
struct PassageApp: App {
    static let refreshTask = "de.nerdworks.passage.refresh"

    static func scheduleRefresh() async {
        let request = BGAppRefreshTaskRequest(identifier: refreshTask)
        request.earliestBeginDate = .now.addingTimeInterval(60 * 60)
        try? BGTaskScheduler.shared.submit(request)
    }

    init() {
        PassageEnvironment.model.hardwareKeyAgreement = { identity, share in
            try await YubiKeyService.shared.keyAgreement(for: identity, share: share)
        }
        StoreModel.beginBackgroundTask = {
            let id = UIApplication.shared.beginBackgroundTask(withName: "Sync")
            return { UIApplication.shared.endBackgroundTask(id) }
        }
    }

    @State private var model = PassageEnvironment.model
    @State private var store = PassageEnvironment.store
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
                        // `-PassageDebugPasskey <rp>` creates a passkey through the extension's save path.
                        if let rp = UserDefaults.standard.string(forKey: "PassageDebugPasskey") {
                            Task {
                                try? await Task.sleep(for: .seconds(2))
                                let passkey = Passkey.create(relyingParty: rp, userName: "simulator", userHandle: Data("sim-user".utf8))
                                do {
                                    let synced = try await store.save(
                                        passkey.suggestedPath, text: passkey.entryText, isNew: true,
                                        message: "Add passkey for simulator at \(rp).")
                                    await AutoFillStore.learn(passkey.suggestedPath, from: Entry(passkey.entryText))
                                    print("PASSKEY_SAVED synced=\(synced)")
                                } catch {
                                    store.errorMessage = error.localizedDescription
                                }
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
                        // `-PassageDebugSetUp YES` sets up an empty store with a throwaway recovery key.
                        if UserDefaults.standard.bool(forKey: "PassageDebugSetUp") {
                            Task {
                                try? await Task.sleep(for: .seconds(2))
                                guard store.needsSetup, let device = model.deviceIdentity else { return print("SETUP_SKIPPED") }
                                do {
                                    try await store.setUpNewStore(device: device, recovery: RecoveryKit(postQuantum: true))
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
                .modifier(PINPrompt(service: YubiKeyService.shared))
                // Credential Exchange: another app (e.g. Apple Passwords) hands over credentials.
                .onContinueUserActivity(ASCredentialExchangeActivity) { activity in
                    Task { await CredentialExchangeImport.shared.handle(activity) }
                }
                .sheet(isPresented: Binding(
                    get: { CredentialExchangeImport.shared.pending != nil },
                    set: { if !$0 { CredentialExchangeImport.shared.pending = nil } })
                ) {
                    if let pending = CredentialExchangeImport.shared.pending { CredentialImportView(pending: pending) }
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
        // Background refresh: sync the git store now and then, so AutoFill and the app open
        // with current data. Fetch, merge and push need no keys; nothing is decrypted.
        .backgroundTask(.appRefresh(Self.refreshTask)) {
            await Self.scheduleRefresh()
            await MainActor.run { PassageEnvironment.store.restore() }
            await PassageEnvironment.store.sync(.automatic)
        }
        .onChange(of: scenePhase) { _, phase in
            switch phase {
            case .background:
                Task { await Self.scheduleRefresh() }
                model.lock()
                YubiKeyService.shared.forgetPIN()
            case .active:
                // A Control Center button may have left a route for us.
                if let route = PendingRoute.take() { model.pendingRoute = route }
                // Pick up changes from other devices whenever the app comes back.
                if store.gitConfig != nil { Task { await store.sync(.automatic) } }
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

/// The YubiKey PIN alert.
private struct PINPrompt: ViewModifier {
    @Bindable var service: YubiKeyService
    @State private var pin = ""

    func body(content: Content) -> some View {
        content.alert(
            "YubiKey PIN", isPresented: Binding(get: { service.pinRequest != nil }, set: { if !$0 { finish(nil) } }),
            presenting: service.pinRequest
        ) { _ in
            SecureField("PIN", text: $pin)
                .keyboardType(.numberPad)
                .textContentType(.oneTimeCode)
            Button("Continue") { finish(pin) }
            Button("Cancel", role: .cancel) { finish(nil) }
        } message: { request in
            Text(request.message)
        }
    }

    private func finish(_ value: String?) {
        guard let request = service.pinRequest else { return }
        service.pinRequest = nil
        pin = ""
        request.continuation.resume(returning: value)
    }
}
