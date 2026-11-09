import KeyStore
import PassStore
import SwiftUI
import os

private let log = Logger(subsystem: "de.nerdworks.passage", category: "AutoFill")

/// A passkey sign-in request: what's needed to build the assertion.
struct PasskeyRequest: Equatable {
    let relyingParty: String
    let clientDataHash: Data
    /// Credential IDs the site accepts; empty means any.
    let allowedCredentials: [Data]
}

enum PickerKind: Equatable {
    case password, oneTimeCode, text
    case passkey(PasskeyRequest)
}

enum PickerCompletion {
    case password(user: String, password: String)
    case oneTimeCode(String)
    case text(String)
    case passkey(Passkey, authenticatorData: Data, signature: Data, clientDataHash: Data)
}

/// Suggested entries for the requesting site, plus search over the whole store. Picking an
/// entry decrypts it (Face ID) and completes the request.
struct CredentialPickerView: View {
    @Environment(AppModel.self) private var model
    @Environment(StoreModel.self) private var store
    let kind: PickerKind
    let services: [String]
    let autoSelect: EntryPath?
    let cancel: () -> Void
    let complete: (PickerCompletion) -> Void

    @State private var query = ""
    @State private var working: EntryPath?
    @State private var error: String?
    @State private var textChoices: (EntryPath, Entry)?
    /// Set when Face ID couldn't be shown automatically; the user continues by tapping.
    @State private var needsTap: EntryPath?

    private var index: AutoFillIndex { AutoFillStore.load().updated(for: store.snapshot.entries) }

    private var suggested: [EntryPath] {
        if case .passkey(let request) = kind {
            return AutoFillMatcher.passkeys(index.items, relyingParty: request.relyingParty, allowed: request.allowedCredentials)
                .map { EntryPath($0.path) }
        }
        var seen = Set<String>()
        return services.flatMap { AutoFillMatcher.match(index.items, service: $0) }
            .filter { $0.passkey == nil }
            .filter { kind != .oneTimeCode || $0.hasOTP || !$0.fromContent }
            .filter { seen.insert($0.path).inserted }
            .map { EntryPath($0.path) }
    }

    private var serviceHost: String? {
        if case .passkey(let request) = kind { return request.relyingParty }
        return services.first.flatMap { URLComponents(string: $0.contains("://") ? $0 : "https://" + $0)?.host }
    }

    private var isPasskey: Bool {
        if case .passkey = kind { return true }
        return false
    }

    var body: some View {
        NavigationStack {
            List {
                if let needsTap {
                    Section {
                        Button("Continue with Face ID", systemImage: "faceid") { Task { await pick(needsTap) } }
                            .bold()
                    } footer: {
                        Text(needsTap.path)
                    }
                }
                if let error {
                    Section { Label(error, systemImage: "exclamationmark.triangle").foregroundStyle(.red) }
                }
                if query.isEmpty, !suggested.isEmpty {
                    Section(isPasskey ? "Passkeys for \(serviceHost ?? "this site")" : "Suggested for \(serviceHost ?? "this site")") {
                        ForEach(suggested) { row($0) }
                    }
                }
                if !isPasskey {
                    Section(query.isEmpty ? "All Passwords" : "Results") {
                        ForEach(store.snapshot.search(query)) { row($0) }
                    }
                } else if suggested.isEmpty {
                    ContentUnavailableView(
                        "No Passkey", systemImage: "person.badge.key",
                        description: Text("Passage has no passkey for \(serviceHost ?? "this site"). If you created one elsewhere, open Passage and run Prepare AutoFill after syncing."))
                }
            }
            .overlay {
                if store.store == nil {
                    ContentUnavailableView(
                        "No Password Store", systemImage: "lock.rectangle.stack",
                        description: Text("Open the Passage app and set up your store first."))
                }
            }
            .searchable(text: $query, placement: .navigationBarDrawer(displayMode: .always))
            .textInputAutocapitalization(.never)
            .autocorrectionDisabled()
            .navigationTitle(title)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel", role: .cancel, action: cancel) }
            }
            .sheet(isPresented: Binding(get: { textChoices != nil }, set: { if !$0 { textChoices = nil } })) {
                if let (entry, content) = textChoices {
                    TextChoiceView(entry: entry, content: content) { complete(.text($0)) }
                }
            }
            .task {
                // The extension's sheet may still be appearing, and Face ID is refused until
                // it has (LAError.notInteractive). Wait, retry a few times, then ask for a tap.
                guard let autoSelect else { return }
                for attempt in 0..<4 {
                    try? await Task.sleep(for: .milliseconds(attempt == 0 ? 350 : 700))
                    if await pick(autoSelect, automatic: true) { return }
                }
                needsTap = autoSelect
            }
        }
    }

    private var title: LocalizedStringKey {
        switch kind {
        case .password: "Passwords"
        case .oneTimeCode: "One-Time Codes"
        case .text: "Insert from Passage"
        case .passkey: "Sign In with a Passkey"
        }
    }

    private func row(_ entry: EntryPath) -> some View {
        Button {
            Task { await pick(entry) }
        } label: {
            HStack {
                VStack(alignment: .leading) {
                    Text(entry.name)
                    if !entry.folder.isEmpty {
                        Text(entry.folder).font(.caption).foregroundStyle(.secondary)
                    }
                }
                Spacer()
                if working == entry { ProgressView() }
            }
        }
        .tint(.primary)
        .disabled(working != nil)
    }

    /// Decrypts `entry` and completes the request. Returns false if Face ID couldn't be shown
    /// yet (only reported when `automatic`, so the caller can retry).
    @discardableResult
    private func pick(_ entry: EntryPath, automatic: Bool = false) async -> Bool {
        working = entry
        error = nil
        defer { working = nil }
        do {
            let plaintext: Data
            do {
                plaintext = try await model.decrypt(store.read(entry))
            } catch KeyStoreError.notInteractive where automatic {
                log.info("decrypt not interactive yet, will retry")
                return false
            }
            needsTap = nil
            let content = Entry(String(decoding: plaintext, as: UTF8.self))
            await AutoFillStore.learn(entry, from: content)
            switch kind {
            case .password:
                guard let password = content.password else {
                    error = String(localized: "This entry has no password.")
                    return true
                }
                complete(.password(user: content.username ?? entry.name, password: password))
            case .oneTimeCode:
                guard let otp = content.otp else {
                    error = String(localized: "This entry has no one-time code.")
                    return true
                }
                complete(.oneTimeCode(otp.code()))
            case .text:
                textChoices = (entry, content)
            case .passkey(let request):
                guard let passkey = Passkey(entry: content), passkey.relyingParty.lowercased() == request.relyingParty.lowercased() else {
                    error = String(localized: "This entry has no passkey for \(request.relyingParty).")
                    return true
                }
                let (authenticatorData, signature) = try passkey.assertion(clientDataHash: request.clientDataHash)
                complete(.passkey(passkey, authenticatorData: authenticatorData, signature: signature, clientDataHash: request.clientDataHash))
            }
        } catch {
            log.error("pick failed: \(String(describing: error), privacy: .public)")
            self.error = error.localizedDescription
        }
        return true
    }
}

/// For text insertion: choose which value of the entry to insert.
private struct TextChoiceView: View {
    let entry: EntryPath
    let content: Entry
    let choose: (String) -> Void

    var body: some View {
        NavigationStack {
            List {
                if let password = content.password { choice("Password", password, secret: true) }
                if let username = content.username { choice("Username", username) }
                if let otp = content.otp { choice("One-Time Code", otp.code()) }
                ForEach(content.fields) { field in
                    choice(field.key ?? String(localized: "Note"), field.value, secret: field.isSensitive)
                }
            }
            .navigationTitle(entry.name)
            .navigationBarTitleDisplayMode(.inline)
        }
        .presentationDetents([.medium, .large])
    }

    private func choice(_ label: String, _ value: String, secret: Bool = false) -> some View {
        Button { choose(value) } label: {
            VStack(alignment: .leading) {
                Text(label).font(.caption).foregroundStyle(.secondary)
                Text(secret ? String(repeating: "•", count: 10) : value).lineLimit(2)
            }
        }
        .tint(.primary)
    }
}
