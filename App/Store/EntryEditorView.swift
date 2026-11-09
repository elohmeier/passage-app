import PassStore
import SwiftUI

/// Creates a new entry or edits an existing one.
struct EntryEditorView: View {
    enum Mode: Equatable, Identifiable {
        case new(folder: String)
        case edit(EntryPath, text: String)

        var id: String {
            switch self {
            case .new(let folder): "new:" + folder
            case .edit(let entry, _): "edit:" + entry.path
            }
        }
    }

    @Environment(StoreModel.self) private var store
    @Environment(\.dismiss) private var dismiss
    let mode: Mode
    var onSaved: (EntryPath) -> Void = { _ in }

    @State private var path: String
    @State private var draft: EntryDraft
    @State private var revealPassword = false
    @State private var showingGenerator = false
    @State private var scanningOTP = false
    @State private var recipients: Result<[String], any Error>?
    @State private var saving = false
    @State private var error: String?

    init(mode: Mode, onSaved: @escaping (EntryPath) -> Void = { _ in }) {
        self.mode = mode
        self.onSaved = onSaved
        switch mode {
        case .new(let folder):
            _path = State(initialValue: folder.isEmpty ? "" : folder + "/")
            _draft = State(initialValue: EntryDraft(password: PasswordGenerator.password()))
        case .edit(let entry, let text):
            _path = State(initialValue: entry.path)
            _draft = State(initialValue: EntryDraft(text))
        }
    }

    private var initialPath: String {
        switch mode {
        case .new(let folder): folder.isEmpty ? "" : folder + "/"
        case .edit(let entry, _): entry.path
        }
    }

    private var isNew: Bool {
        if case .new = mode { return true }
        return false
    }

    private var trimmedPath: String {
        path.split(separator: "/").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }.joined(separator: "/")
    }

    /// Nil if the name is valid, otherwise why not.
    private var pathProblem: String? {
        let p = trimmedPath
        if p.isEmpty || path.trimmingCharacters(in: .whitespaces).hasSuffix("/") { return String(localized: "Enter a name.") }
        if store.snapshot.folders.contains(p) { return String(localized: "A folder with this name exists.") }
        if p.split(separator: "/").contains(where: { $0.hasPrefix(".") }) { return String(localized: "Names can't start with a dot.") }
        if p.hasSuffix(".age") { return String(localized: "Leave out the .age extension.") }
        let target = EntryPath(p)
        let unchanged = if case .edit(let original, _) = mode { original == target } else { false }
        if !unchanged, store.snapshot.entries.contains(target) { return String(localized: "An entry with this name already exists.") }
        return nil
    }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    TextField("folder/name", text: $path)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                } header: {
                    Text("Name")
                } footer: {
                    if let pathProblem, path != initialPath { Text(pathProblem).foregroundStyle(.red) }
                }

                Section("Password") {
                    HStack {
                        Group {
                            if revealPassword {
                                TextField("Password", text: $draft.password)
                            } else {
                                SecureField("Password", text: $draft.password)
                            }
                        }
                        .font(.body.monospaced())
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        Button(revealPassword ? "Hide" : "Show", systemImage: revealPassword ? "eye.slash" : "eye") { revealPassword.toggle() }
                            .labelStyle(.iconOnly)
                            .buttonStyle(.borderless)
                    }
                    Button("Generate…", systemImage: "wand.and.stars") { showingGenerator = true }
                }

                Section("Login") {
                    TextField("Username", text: $draft.username)
                        .textContentType(.username)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                    TextField("Website", text: $draft.url)
                        .keyboardType(.URL)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                }

                Section {
                    TextField("otpauth://totp/…", text: Binding(get: { draft.otpURI ?? "" }, set: { draft.otpURI = $0.isEmpty ? nil : $0 }))
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .font(.caption.monospaced())
                    Button("Scan QR Code", systemImage: "qrcode.viewfinder") { scanningOTP = true }
                } header: {
                    Text("One-Time Code")
                } footer: {
                    if let uri = draft.otpURI, !uri.isEmpty, OTP(uri: uri) == nil {
                        Text("Not a valid otpauth:// URI.").foregroundStyle(.red)
                    }
                }

                Section("Other Fields") {
                    ForEach($draft.otherFields) { $field in
                        VStack(alignment: .leading) {
                            TextField("Name", text: Binding(get: { field.key ?? "" }, set: { field.key = $0.isEmpty ? nil : $0 }))
                                .font(.caption)
                                .textInputAutocapitalization(.never)
                            TextField("Value", text: $field.value, axis: .vertical)
                        }
                    }
                    .onDelete { draft.otherFields.remove(atOffsets: $0) }
                    Button("Add Field", systemImage: "plus") { draft.otherFields.append(.init(key: "", value: "")) }
                }

                Section {
                    RecipientsSummary(result: recipients)
                }

                if let error {
                    Section { Label(error, systemImage: "exclamationmark.triangle").foregroundStyle(.red) }
                }
            }
            .navigationTitle(isNew ? "New Password" : "Edit")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel", role: .cancel) { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Save", role: .confirm) { Task { await save() } }
                        .disabled(pathProblem != nil || saving)
                }
            }
            .sheet(isPresented: $scanningOTP) {
                QRScannerView(title: "Scan One-Time Code") { text in
                    guard OTP(uri: text) != nil else { return false }
                    draft.otpURI = text
                    return true
                }
            }
            .sheet(isPresented: $showingGenerator) {
                GeneratorView { draft.password = $0 }
            }
            .task(id: trimmedPath) {
                guard !trimmedPath.isEmpty else { return }
                recipients = await store.recipients(for: EntryPath(trimmedPath))
            }
            .interactiveDismissDisabled(saving)
        }
    }

    private func save() async {
        saving = true
        error = nil
        defer { saving = false }
        let target = EntryPath(trimmedPath)
        do {
            if case .edit(let original, _) = mode, original != target {
                try await store.rename(original, to: target, text: draft.text)
            } else {
                try await store.save(target, text: draft.text, isNew: isNew)
            }
            onSaved(target)
            dismiss()
        } catch {
            self.error = error.localizedDescription
        }
    }
}

private struct RecipientsSummary: View {
    let result: Result<[String], any Error>?

    var body: some View {
        switch result {
        case nil:
            Label("Checking recipients…", systemImage: "person.2")
                .foregroundStyle(.secondary)
        case .success(let recipients) where recipients.isEmpty:
            Label("No .age-recipients applies here, so the entry can't be encrypted.", systemImage: "exclamationmark.triangle")
                .foregroundStyle(.red)
        case .success(let recipients):
            DisclosureGroup {
                ForEach(recipients, id: \.self) { r in
                    Text(r).font(.caption.monospaced()).lineLimit(1).truncationMode(.middle)
                }
            } label: {
                Label("Encrypted to \(recipients.count) recipient\(recipients.count == 1 ? "" : "s")", systemImage: "lock")
            }
        case .failure(let error):
            Label(error.localizedDescription, systemImage: "exclamationmark.triangle")
                .foregroundStyle(.red)
        }
    }
}

struct GeneratorView: View {
    @Environment(\.dismiss) private var dismiss
    @AppStorage("generatorKind") private var passphrase = false
    @State private var options = PasswordGenerator.Options()
    @State private var phrase = PasswordGenerator.PassphraseOptions()
    @State private var value = ""
    let onUse: (String) -> Void

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Picker("Kind", selection: $passphrase) {
                        Text("Password").tag(false)
                        Text("Passphrase").tag(true)
                    }
                    .pickerStyle(.segmented)
                    Text(value)
                        .font(.title3.monospaced())
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                    Button("Regenerate", systemImage: "arrow.clockwise", action: regenerate)
                } footer: {
                    let bits = passphrase ? PasswordGenerator.entropy(phrase) : PasswordGenerator.entropy(options)
                    Text("About \(Int(bits)) bits of entropy")
                }

                if passphrase {
                    Section {
                        Stepper("\(phrase.words) words", value: $phrase.words, in: 3...10)
                        Picker("Separator", selection: $phrase.separator) {
                            Text("-").tag("-")
                            Text("space").tag(" ")
                            Text(".").tag(".")
                            Text("_").tag("_")
                        }
                        Toggle("Capitalize", isOn: $phrase.capitalize)
                        Toggle("Include a Digit", isOn: $phrase.includeDigit)
                    }
                } else {
                    Section {
                        Stepper("\(options.length) characters", value: $options.length, in: 8...64)
                        Toggle("Uppercase", isOn: $options.uppercase)
                        Toggle("Digits", isOn: $options.digits)
                        Toggle("Symbols", isOn: $options.symbols)
                    }
                }
            }
            .navigationTitle("Generate")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel", role: .cancel) { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Use", role: .confirm) {
                        onUse(value)
                        dismiss()
                    }
                }
            }
            .onAppear(perform: regenerate)
            .onChange(of: options) { regenerate() }
            .onChange(of: phrase) { regenerate() }
            .onChange(of: passphrase) { regenerate() }
        }
        .presentationDetents([.medium, .large])
    }

    private func regenerate() {
        value = passphrase ? PasswordGenerator.passphrase(phrase) : PasswordGenerator.password(options)
    }
}
