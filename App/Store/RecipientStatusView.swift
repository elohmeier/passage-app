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

/// A quiet status row when the last sync failed (e.g. offline), with a retry.
struct SyncStatusSection: View {
    @Environment(StoreModel.self) private var store

    var body: some View {
        if let problem = store.syncProblem {
            Section {
                HStack(alignment: .firstTextBaseline) {
                    Label {
                        VStack(alignment: .leading, spacing: 2) {
                            Text("Couldn't sync").font(.subheadline.bold())
                            Text(problem).font(.caption).foregroundStyle(.secondary)
                        }
                    } icon: {
                        Image(systemName: "icloud.slash").foregroundStyle(.orange)
                    }
                    Spacer()
                    if store.isSyncing {
                        ProgressView()
                    } else {
                        Button("Retry") { Task { await store.sync() } }
                            .buttonStyle(.borderless)
                    }
                }
            }
        }
    }
}

/// Recipient changes that arrived from elsewhere, to approve before new entries are encrypted
/// to them; and the sync stop when both sides changed a `.age-recipients`.
struct RecipientChangesSection: View {
    @Environment(StoreModel.self) private var store
    @State private var confirming = false

    var body: some View {
        if store.recipientsConflict {
            Section {
                Label("Recipients changed on both sides", systemImage: "person.2.badge.gearshape")
                    .font(.headline)
                Text("This device and the remote both changed who the store is encrypted to, so syncing stopped. Keeping the remote's version saves this device's as a conflict copy; you then review the result.")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                Button("Keep the Remote's Recipients", systemImage: "arrow.down.circle") {
                    Task { await store.syncKeepingRemoteRecipients() }
                }
                .disabled(store.isSyncing)
            }
        }
        if !store.recipientChanges.isEmpty {
            Section {
                Label("Recipients changed", systemImage: "person.badge.shield.exclamationmark")
                    .font(.headline)
                    .foregroundStyle(.orange)
                ForEach(store.recipientChanges) { change in
                    VStack(alignment: .leading, spacing: 4) {
                        Text(change.folder.isEmpty ? "Whole store" : change.folder)
                            .font(.subheadline.bold())
                        ForEach(change.added, id: \.recipient) { added in
                            Label {
                                VStack(alignment: .leading) {
                                    if let label = added.label { Text(label) }
                                    Text(added.recipient)
                                        .font(.caption.monospaced())
                                        .lineLimit(1)
                                        .truncationMode(.middle)
                                        .foregroundStyle(.secondary)
                                }
                            } icon: {
                                Image(systemName: "plus.circle.fill").foregroundStyle(.orange)
                            }
                        }
                        ForEach(change.removed, id: \.self) { removed in
                            Label {
                                Text(removed)
                                    .font(.caption.monospaced())
                                    .lineLimit(1)
                                    .truncationMode(.middle)
                            } icon: {
                                Image(systemName: "minus.circle.fill").foregroundStyle(.secondary)
                            }
                        }
                    }
                }
                Text("New entries will be readable by every recipient. If you don't recognize an added one, don't approve: someone with access to the repository may be trying to read your new passwords. Saving is paused until you decide.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                Button("Approve Recipients", systemImage: "checkmark.shield") { confirming = true }
                    .confirmationDialog("Encrypt new entries to these recipients?", isPresented: $confirming, titleVisibility: .visible) {
                        Button("Approve") { Task { await store.approveRecipients() } }
                    }
            }
        }
    }
}
