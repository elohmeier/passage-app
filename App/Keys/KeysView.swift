import KeyStore
import SwiftUI

struct KeysView: View {
    @Environment(AppModel.self) private var model
    @State private var showingImport = false
    @State private var pendingDelete: StoredIdentity?

    var body: some View {
        List {
            Section {
                if let device = model.deviceIdentity {
                    NavigationLink { IdentityDetailView(identity: device) } label: { IdentityRow(identity: device) }
                } else {
                    Button {
                        model.createDeviceIdentity(name: UIDevice.current.name)
                    } label: {
                        Label("Create Device Key", systemImage: "plus.circle.fill")
                    }
                }
            } header: {
                Text("This Device")
            } footer: {
                Text("Created in the Secure Enclave. It can't be exported, so make sure your store has another recipient you can recover with.")
            }

            Section("Imported") {
                ForEach(model.identities.filter { $0.kind == .imported }) { identity in
                    NavigationLink { IdentityDetailView(identity: identity) } label: { IdentityRow(identity: identity) }
                        .swipeActions {
                            Button("Delete", role: .destructive) { pendingDelete = identity }
                        }
                }
                Button {
                    showingImport = true
                } label: {
                    Label("Import Key…", systemImage: "square.and.arrow.down")
                }
            }
        }
        .navigationTitle("Keys")
        .sheet(isPresented: $showingImport) { ImportIdentityView() }
        .confirmationDialog(
            "Delete \(pendingDelete?.name ?? "")?", isPresented: Binding(get: { pendingDelete != nil }, set: { if !$0 { pendingDelete = nil } }),
            titleVisibility: .visible
        ) {
            Button("Delete Key", role: .destructive) {
                if let pendingDelete { model.delete(pendingDelete) }
            }
        } message: {
            Text("Files encrypted only to this key can no longer be decrypted on this device.")
        }
    }
}

struct IdentityRow: View {
    let identity: StoredIdentity

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(identity.name)
            Text(identity.kindDescription)
                .font(.caption)
                .foregroundStyle(.secondary)
        }
    }
}

extension StoredIdentity {
    var kindDescription: LocalizedStringResource {
        switch kind {
        case .secureEnclave: "Secure Enclave"
        case .imported: recipients.first?.hasPrefix("age1pq1") == true ? "Imported, post-quantum" : "Imported"
        case .simulator: "Simulator (not hardware-protected)"
        }
    }
}

#Preview {
    NavigationStack { KeysView() }
        .environment(AppModel.preview())
}
