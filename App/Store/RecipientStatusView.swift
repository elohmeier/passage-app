import PassStore
import SwiftUI

/// Setup guidance at the top of the store: add this device as a recipient, then wait for the
/// desktop to re-encrypt.
struct RecipientStatusSection: View {
    @Environment(StoreModel.self) private var store
    @State private var adding = false
    @State private var error: String?

    private var command: String {
        store.gitConfig != nil ? "cd ~/.passage/store && git pull && passage reencrypt && git push" : "passage reencrypt"
    }

    var body: some View {
        if let r = store.readability, !r.isRecipient || r.readable < r.total {
            Section {
                if !r.isRecipient {
                    Label("This device isn't a recipient yet", systemImage: "person.badge.plus")
                        .font(.headline)
                    Text("Entries are only readable here once they're encrypted to this device's key. Add it to the store's .age-recipients, then re-encrypt on your computer.")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                    Button {
                        Task {
                            adding = true
                            defer { adding = false }
                            do { try await store.addDeviceAsRecipient() } catch { self.error = error.localizedDescription }
                        }
                    } label: {
                        Label(adding ? "Adding…" : "Add This Device as Recipient", systemImage: "plus.circle.fill")
                    }
                    .disabled(adding)
                    if let error { Text(error).font(.caption).foregroundStyle(.red) }
                } else {
                    Label("\(r.readable) of \(r.total) entries readable here", systemImage: "lock.rotation")
                        .font(.headline)
                    ProgressView(value: Double(r.readable), total: Double(max(r.total, 1)))
                    Text("This device is a recipient now. Re-encrypt the store on your computer so existing entries include it:")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                    HStack {
                        Text(command)
                            .font(.caption.monospaced())
                            .textSelection(.enabled)
                        Spacer()
                        Button("Copy", systemImage: "doc.on.doc") { UIPasteboard.general.string = command }
                            .labelStyle(.iconOnly)
                            .buttonStyle(.borderless)
                    }
                }
            }
        }
    }
}
