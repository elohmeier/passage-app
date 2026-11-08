import SwiftUI
import UniformTypeIdentifiers

/// Decrypts a single .age file. Mainly to check the key setup before a store is connected.
struct DecryptFileView: View {
    @Environment(AppModel.self) private var model
    @State private var showingPicker = false
    @State private var fileName: String?
    @State private var plaintext: String?
    @State private var error: String?
    @State private var working = false

    var body: some View {
        Form {
            Section {
                Button("Choose .age File…", systemImage: "doc") { showingPicker = true }
                    .disabled(working)
            } footer: {
                Text("Encrypt something on your Mac with `age -r <this device's recipient>` and open it here.")
            }

            if working {
                ProgressView()
            }

            if let plaintext {
                Section(fileName ?? "") {
                    Text(plaintext)
                        .font(.body.monospaced())
                        .textSelection(.enabled)
                        .privacySensitive()
                }
            }

            if let error {
                Section {
                    Label(error, systemImage: "exclamationmark.triangle")
                        .foregroundStyle(.red)
                }
            }
        }
        .navigationTitle("Decrypt a File")
        .fileImporter(isPresented: $showingPicker, allowedContentTypes: [.data]) { result in
            guard case .success(let url) = result else { return }
            Task { await decrypt(url) }
        }
        .onDisappear { plaintext = nil }
    }

    private func decrypt(_ url: URL) async {
        plaintext = nil
        error = nil
        fileName = url.lastPathComponent
        let scoped = url.startAccessingSecurityScopedResource()
        defer { if scoped { url.stopAccessingSecurityScopedResource() } }
        working = true
        defer { working = false }
        do {
            let data = try Data(contentsOf: url)
            let output = try await model.decrypt(data)
            plaintext = String(decoding: output, as: UTF8.self)
        } catch {
            self.error = error.localizedDescription
        }
    }
}
