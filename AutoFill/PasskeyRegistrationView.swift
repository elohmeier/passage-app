import LocalAuthentication
import PassStore
import SwiftUI

/// Confirms and creates a new passkey: user verification, key generation, then saving it to
/// the store right away (commit and push), so the passkey isn't only on this phone.
struct PasskeyRegistrationView: View {
    @Environment(StoreModel.self) private var store
    let relyingParty: String
    let userName: String
    let userHandle: Data
    let cancel: () -> Void
    let complete: (Passkey) -> Void

    private enum Phase: Equatable {
        case confirm
        case saving
        case savedLocally(Passkey)
        case failed(String)
    }

    @State private var phase = Phase.confirm

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    LabeledContent("Website", value: relyingParty)
                    LabeledContent("Account", value: userName.isEmpty ? "—" : userName)
                } footer: {
                    Text("The passkey is saved in your password store, encrypted like your passwords, so you can use it on your other devices too.")
                }

                switch phase {
                case .confirm:
                    Section {
                        Button("Save Passkey in Passage", systemImage: "person.badge.key") { Task { await create() } }
                            .bold()
                    }
                case .saving:
                    Section {
                        HStack(spacing: 12) {
                            ProgressView()
                            Text("Saving and syncing…")
                        }
                    }
                case .savedLocally(let passkey):
                    Section {
                        Label("Saved on this iPhone. It couldn't be synced yet and will be pushed with the next sync.", systemImage: "icloud.slash")
                        Button("Continue") { complete(passkey) }.bold()
                    }
                case .failed(let message):
                    Section {
                        Label(message, systemImage: "exclamationmark.triangle").foregroundStyle(.red)
                        Button("Try Again") { Task { await create() } }
                    }
                }
            }
            .navigationTitle("New Passkey")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel", role: .cancel, action: cancel).disabled(phase == .saving) }
            }
        }
    }

    private func create() async {
        // The passkey claims user verification, so verify the user first.
        do {
            _ = try await LAContext().evaluatePolicy(
                .deviceOwnerAuthentication, localizedReason: String(localized: "Create a passkey for \(relyingParty)"))
        } catch {
            return
        }
        phase = .saving
        let passkey = Passkey.create(relyingParty: relyingParty, userName: userName, userHandle: userHandle)
        var path = passkey.suggestedPath
        var n = 2
        while store.snapshot.entries.contains(path) {
            path = EntryPath(passkey.suggestedPath.path + "-\(n)")
            n += 1
        }
        do {
            let synced = try await store.save(
                path, text: passkey.entryText, isNew: true,
                message: "Add passkey for \(userName.isEmpty ? relyingParty : userName) at \(relyingParty).")
            await AutoFillStore.learn(path, from: Entry(passkey.entryText))
            if synced {
                complete(passkey)
            } else {
                phase = .savedLocally(passkey)
            }
        } catch {
            phase = .failed(error.localizedDescription)
        }
    }
}
