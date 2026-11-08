import PassStore
import SwiftUI

enum PickerKind {
    case password, oneTimeCode, text
}

enum PickerCompletion {
    case password(user: String, password: String)
    case oneTimeCode(String)
    case text(String)
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

    private var index: AutoFillIndex { AutoFillStore.load().updated(for: store.snapshot.entries) }

    private var suggested: [EntryPath] {
        var seen = Set<String>()
        return services.flatMap { AutoFillMatcher.match(index.items, service: $0) }
            .filter { kind != .oneTimeCode || $0.hasOTP || !$0.fromContent }
            .filter { seen.insert($0.path).inserted }
            .map { EntryPath($0.path) }
    }

    private var serviceHost: String? {
        services.first.flatMap { URLComponents(string: $0.contains("://") ? $0 : "https://" + $0)?.host }
    }

    var body: some View {
        NavigationStack {
            List {
                if let error {
                    Section { Label(error, systemImage: "exclamationmark.triangle").foregroundStyle(.red) }
                }
                if query.isEmpty, !suggested.isEmpty {
                    Section("Suggested for \(serviceHost ?? "this site")") {
                        ForEach(suggested) { row($0) }
                    }
                }
                Section(query.isEmpty ? "All Passwords" : "Results") {
                    ForEach(store.snapshot.search(query)) { row($0) }
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
                if let autoSelect { await pick(autoSelect) }
            }
        }
    }

    private var title: LocalizedStringKey {
        switch kind {
        case .password: "Passwords"
        case .oneTimeCode: "One-Time Codes"
        case .text: "Insert from Passage"
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

    private func pick(_ entry: EntryPath) async {
        working = entry
        error = nil
        defer { working = nil }
        do {
            let plaintext = try await model.decrypt(store.read(entry))
            let content = Entry(String(decoding: plaintext, as: UTF8.self))
            await AutoFillStore.learn(entry, from: content)
            switch kind {
            case .password:
                guard let password = content.password else {
                    error = String(localized: "This entry has no password.")
                    return
                }
                complete(.password(user: content.username ?? entry.name, password: password))
            case .oneTimeCode:
                guard let otp = content.otp else {
                    error = String(localized: "This entry has no one-time code.")
                    return
                }
                complete(.oneTimeCode(otp.code()))
            case .text:
                textChoices = (entry, content)
            }
        } catch {
            self.error = error.localizedDescription
        }
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
