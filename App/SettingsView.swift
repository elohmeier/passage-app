import GitSync
import SwiftUI

struct SettingsView: View {
    @Environment(AppModel.self) private var model
    @Environment(StoreModel.self) private var store
    @State private var confirmingClose = false
    @State private var sshKey: String?
    @State private var autoFillStatus: String?
    @State private var preparing = false

    var body: some View {
        @Bindable var model = model
        Form {
            Section {
                Picker("Require Face ID", selection: $model.unlockOption) {
                    ForEach(UnlockOption.allCases) { Text($0.title).tag($0) }
                }
            } footer: {
                Text("How long one authentication keeps your keys unlocked. Leaving the app always locks them.")
            }

            Section {
                Picker("Clear Clipboard", selection: $model.clipboardSeconds) {
                    ForEach([15, 30, 60, 120], id: \.self) { Text(Duration.seconds($0), format: .units(allowed: [.seconds, .minutes])).tag($0) }
                }
            } footer: {
                Text("Copied passwords stay on this device only and are removed after this time.")
            }

            if store.store != nil {
                Section {
                    Button(preparing ? "Preparing…" : "Prepare AutoFill", systemImage: "key.viewfinder") {
                        Task {
                            preparing = true
                            defer { preparing = false }
                            do {
                                let n = try await model.prepareAutoFill(store: store)
                                autoFillStatus = String(localized: "Indexed \(n) entries.")
                            } catch {
                                autoFillStatus = error.localizedDescription
                            }
                        }
                    }
                    .disabled(preparing)
                } header: {
                    Text("AutoFill")
                } footer: {
                    Text((autoFillStatus.map { $0 + " " } ?? "") + "Turn on Passage in Settings › General › AutoFill & Passwords. Preparing decrypts every entry once, after one Face ID, to learn websites and usernames; only those are shared with iOS for suggestions. Entries you open are learned automatically.")
                }
            }

            Section {
                if let sshKey {
                    LabeledContent("SSH Key") {
                        Text(sshKey).font(.caption.monospaced()).lineLimit(1).truncationMode(.middle)
                    }
                    Button("Copy Public Key", systemImage: "doc.on.doc") { UIPasteboard.general.string = sshKey }
                }
                NavigationLink("Known Hosts") { KnownHostsView() }
            } header: {
                Text("SSH")
            } footer: {
                Text("This device's key is in the Secure Enclave. GitHub's host keys are built in.")
            }

            if store.store != nil {
                Section {
                    if let git = store.gitConfig {
                        LabeledContent("Repository", value: git.gitHub?.fullName ?? git.remote)
                        if let gitHub = git.gitHub, let url = URL(string: "https://github.com/\(gitHub.fullName)/settings/keys") {
                            Link(destination: url) { Label("Deploy Keys on GitHub", systemImage: "arrow.up.forward.app") }
                        }
                        if let commit = store.lastCommit {
                            LabeledContent("Last Commit") {
                                VStack(alignment: .trailing) {
                                    Text(commit.summary)
                                    Text(commit.date, format: .relative(presentation: .named))
                                        .font(.caption)
                                }
                            }
                        }
                        Button(store.isSyncing ? "Syncing…" : "Sync Now", systemImage: "arrow.triangle.2.circlepath") {
                            Task { await store.sync() }
                        }
                        .disabled(store.isSyncing)
                    } else {
                        LabeledContent("Folder", value: store.name)
                    }
                    LabeledContent("Entries", value: store.snapshot.entries.count, format: .number)
                    Button("Close Store", role: .destructive) { confirmingClose = true }
                } header: {
                    Text("Store")
                } footer: {
                    if store.gitConfig?.gitHub != nil {
                        Text("Closing deletes the local clone and this store's SSH key. Also remove the \"Passage on …\" deploy key on GitHub; the key itself is gone either way.")
                    } else if store.gitConfig != nil {
                        Text("Closing deletes the local clone and the saved token. The remote repository is not touched.")
                    } else {
                        Text("Closing only forgets the folder. Nothing is deleted.")
                    }
                }
            }
        }
        .navigationTitle("Settings")
        .task { sshKey = try? store.deviceSSHKey().publicKeyLine(comment: "passage-ios") }
        .confirmationDialog("Close \(store.name)?", isPresented: $confirmingClose, titleVisibility: .visible) {
            Button("Close Store", role: .destructive) { store.close() }
        }
    }
}

struct KnownHostsView: View {
    @Environment(StoreModel.self) private var store

    var body: some View {
        List {
            Section("Trusted") {
                ForEach(store.knownHosts.keys.sorted { $0.host < $1.host }, id: \.self) { key in
                    HostKeyRow(key: key)
                        .swipeActions {
                            Button("Remove", role: .destructive) { store.forget(key) }
                        }
                }
            }
            Section {
                ForEach(KnownHosts.pinned.sorted { $0.key < $1.key }, id: \.self) { HostKeyRow(key: $0) }
            } header: {
                Text("Built In")
            } footer: {
                Text("From GitHub's published host keys.")
            }
        }
        .overlay {
            if store.knownHosts.keys.isEmpty && KnownHosts.pinned.isEmpty { ContentUnavailableView("No Known Hosts", systemImage: "server.rack") }
        }
        .navigationTitle("Known Hosts")
    }
}

private struct HostKeyRow: View {
    let key: HostKey

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(key.host)
            Text("\(key.algorithm) \(key.fingerprint)")
                .font(.caption.monospaced())
                .foregroundStyle(.secondary)
        }
    }
}
