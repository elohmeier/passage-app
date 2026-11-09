import AuthenticationServices
import Foundation
import PassStore

/// Persists the AutoFill index in the App Group and publishes it to iOS's credential identity
/// store, which powers QuickType suggestions. Only domains, usernames and entry paths are
/// published; secrets are decrypted on selection.
enum AutoFillStore {
    static var url: URL {
        (FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: AppConfig.appGroup) ?? .applicationSupportDirectory)
            .appending(path: "autofill-index.json")
    }

    static func load() -> AutoFillIndex {
        guard let data = try? Data(contentsOf: url) else { return AutoFillIndex() }
        return (try? JSONDecoder().decode(AutoFillIndex.self, from: data)) ?? AutoFillIndex()
    }

    static func save(_ index: AutoFillIndex) {
        guard let data = try? JSONEncoder().encode(index) else { return }
        try? FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        try? data.write(to: url, options: [.atomic, .completeFileProtection])
    }

    /// Updates the index for the current entries and republishes it.
    static func update(entries: [EntryPath]) async {
        let index = load().updated(for: entries)
        save(index)
        await publish(index)
    }

    /// Records a decrypted entry's url/username/OTP and republishes.
    static func learn(_ entry: EntryPath, from content: Entry) async {
        var index = load()
        let before = index
        index.learn(entry, from: content)
        guard index != before else { return }
        save(index)
        await publish(index)
    }

    static func clear() async {
        try? FileManager.default.removeItem(at: url)
        try? await ASCredentialIdentityStore.shared.removeAllCredentialIdentities()
    }

    static func publish(_ index: AutoFillIndex) async {
        let store = ASCredentialIdentityStore.shared
        guard await store.state().isEnabled else { return }
        var identities: [any ASCredentialIdentity] = []
        for item in index.items {
            if let p = item.passkey {
                identities.append(ASPasskeyCredentialIdentity(
                    relyingPartyIdentifier: p.relyingParty, userName: p.userName, credentialID: p.credentialID,
                    userHandle: p.userHandle, recordIdentifier: item.path))
                continue
            }
            let user = item.username ?? EntryPath(item.path).name
            for domain in item.domains {
                let service = ASCredentialServiceIdentifier(identifier: domain, type: .domain)
                identities.append(ASPasswordCredentialIdentity(serviceIdentifier: service, user: user, recordIdentifier: item.path))
                if item.hasOTP {
                    identities.append(ASOneTimeCodeCredentialIdentity(serviceIdentifier: service, label: item.path, recordIdentifier: item.path))
                }
            }
        }
        try? await store.replaceCredentialIdentities(identities)
    }
}
