import KeyStore
import SwiftUI

struct ImportIdentityView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @State private var text = ""
    @State private var name = "Imported Key"
    @State private var protection = KeyProtection.biometryCurrentSet
    @State private var showingFilePicker = false

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    TextEditor(text: $text)
                        .font(.caption.monospaced())
                        .frame(minHeight: 120)
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.characters)
                        .privacySensitive()
                    Button("Choose File…", systemImage: "folder") { showingFilePicker = true }
                } header: {
                    Text("Identity")
                } footer: {
                    Text("Paste AGE-SECRET-KEY-1… or AGE-SECRET-KEY-PQ-1… lines, for example from your passage identities file. Comments are ignored.")
                }

                Section("Name") {
                    TextField("Name", text: $name)
                }

                Section {
                    Picker("Protection", selection: $protection) {
                        Text(KeyProtection.biometryCurrentSet.title).tag(KeyProtection.biometryCurrentSet)
                        Text(KeyProtection.userPresence.title).tag(KeyProtection.userPresence)
                    }
                    .pickerStyle(.inline)
                    .labelsHidden()
                } header: {
                    Text("Protection")
                } footer: {
                    Text("The key is encrypted to a new Secure Enclave key with this protection, so it can't be used or extracted without you.")
                }
            }
            .navigationTitle("Import Key")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel", role: .cancel) { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Import", role: .confirm) {
                        if model.importIdentities(text, name: name, protection: protection) {
                            text = ""
                            dismiss()
                        }
                    }
                    .disabled(text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                }
            }
            .fileImporter(isPresented: $showingFilePicker, allowedContentTypes: [.plainText, .data]) { result in
                guard case .success(let url) = result else { return }
                let scoped = url.startAccessingSecurityScopedResource()
                defer { if scoped { url.stopAccessingSecurityScopedResource() } }
                if let contents = try? String(contentsOf: url, encoding: .utf8) {
                    text = contents
                }
            }
        }
    }
}
