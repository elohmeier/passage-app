import AuthenticationServices
import CryptoKit
import PassStore
import SwiftUI

/// Imports credentials another app (e.g. Apple Passwords) hands over via Credential Exchange
/// (iOS 26): logins with TOTP and notes, and passkeys, as pass entries.
@MainActor @Observable
final class CredentialExchangeImport {
    static let shared = CredentialExchangeImport()

    struct Pending {
        let source: String
        let items: [ImportedItem]
        let skipped: Int
        var logins: Int { items.filter { $0.password != nil || $0.otp != nil || !$0.notes.isEmpty }.count }
        var passkeys: Int { items.reduce(0) { $0 + $1.passkeys.count } }
    }

    var pending: Pending?
    var error: String?

    func handle(_ activity: NSUserActivity) async {
        guard let token = activity.userInfo?[ASCredentialImportToken] as? UUID else {
            error = String(localized: "The import couldn't be started.")
            return
        }
        do {
            let data = try await ASCredentialImportManager().importCredentials(token: token)
            pending = Self.convert(data)
        } catch {
            self.error = error.localizedDescription
        }
    }

    static func convert(_ data: ASExportedCredentialData) -> Pending {
        var items: [ImportedItem] = []
        var skipped = 0
        for account in data.accounts {
            for exported in account.items {
                var item = ImportedItem(title: exported.title)
                item.urls = exported.scope?.urls.map(\.absoluteString) ?? []
                for credential in exported.credentials {
                    switch credential {
                    case .basicAuthentication(let basic):
                        item.userName = basic.userName?.value ?? item.userName
                        item.password = basic.password?.value ?? item.password
                    case .totp(let totp):
                        let algorithm: OTP.Algorithm = switch totp.algorithm {
                        case .sha256: .sha256
                        case .sha512: .sha512
                        default: .sha1
                        }
                        item.otp = OTP(
                            kind: .totp(period: Int(totp.period)), secret: totp.secret, algorithm: algorithm, digits: Int(totp.digits),
                            issuer: totp.issuer, account: totp.userName)
                    case .note(let note):
                        item.notes.append(note.content.value)
                    case .passkey(let passkey):
                        // CXF passkey keys are PKCS#8 DER.
                        guard let key = try? P256.Signing.PrivateKey(derRepresentation: passkey.key) else {
                            skipped += 1
                            continue
                        }
                        item.passkeys.append(Passkey(
                            relyingParty: passkey.relyingPartyIdentifier, userName: passkey.userName, credentialID: passkey.credentialID,
                            userHandle: passkey.userHandle, privateKey: key))
                    default:
                        skipped += 1
                    }
                }
                items.append(item)
            }
        }
        return Pending(source: data.exporterDisplayName, items: items, skipped: skipped)
    }
}

struct CredentialImportView: View {
    @Environment(StoreModel.self) private var store
    @Environment(\.dismiss) private var dismiss
    let pending: CredentialExchangeImport.Pending
    @State private var importing = false
    @State private var result: String?

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    LabeledContent("Logins", value: pending.logins, format: .number)
                    LabeledContent("Passkeys", value: pending.passkeys, format: .number)
                    if pending.skipped > 0 {
                        LabeledContent("Not supported", value: pending.skipped, format: .number)
                    }
                } header: {
                    Text("From \(pending.source)")
                } footer: {
                    Text("Logins go to imported/<site>/<user>, passkeys to passkeys/<site>/<user>, encrypted to your store's recipients and committed as one change. Existing entries are never overwritten.")
                }
                if let result {
                    Section { Text(result) }
                }
            }
            .navigationTitle("Import")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel", role: .cancel) { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button(result == nil ? "Import" : "Done", role: .confirm) {
                        if result != nil { dismiss() } else { Task { await run() } }
                    }
                    .disabled(importing || store.store == nil)
                }
            }
            .overlay {
                if store.store == nil {
                    ContentUnavailableView(
                        "No Password Store", systemImage: "lock.rectangle.stack",
                        description: Text("Open or connect your store in Passage first, then export again."))
                }
            }
        }
    }

    private func run() async {
        importing = true
        defer { importing = false }
        let entries = CredentialImport.entries(for: pending.items, existing: Set(store.snapshot.entries))
        do {
            let synced = try await store.importEntries(entries, message: "Import \(entries.count) entries from \(pending.source).")
            for entry in entries { await AutoFillStore.learn(entry.path, from: Entry(entry.text)) }
            result = synced
                ? String(localized: "Imported \(entries.count) entries.")
                : String(localized: "Imported \(entries.count) entries on this iPhone; they'll sync with the next sync.")
        } catch {
            result = error.localizedDescription
        }
    }
}
