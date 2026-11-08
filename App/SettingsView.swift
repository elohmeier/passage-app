import SwiftUI

struct SettingsView: View {
    @Environment(AppModel.self) private var model
    @Environment(StoreModel.self) private var store
    @State private var confirmingClose = false

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
                    if let git = store.gitConfig {
                        LabeledContent("Repository", value: git.remote)
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
                    if store.gitConfig != nil {
                        Text("Closing deletes the local clone and the saved token. The remote repository is not touched.")
                    } else {
                        Text("Closing only forgets the folder. Nothing is deleted.")
                    }
                }
            }
        }
        .navigationTitle("Settings")
        .confirmationDialog("Close \(store.name)?", isPresented: $confirmingClose, titleVisibility: .visible) {
            Button("Close Store", role: .destructive) { store.close() }
        }
    }
}
