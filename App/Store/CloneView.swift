import SwiftUI

struct CloneView: View {
    @Environment(StoreModel.self) private var store
    @Environment(\.dismiss) private var dismiss
    @State private var remote = ""
    @State private var branch = ""
    @State private var username = ""
    @State private var password = ""
    @State private var error: String?
    @State private var cloning = false

    private var isSSH: Bool {
        remote.hasPrefix("ssh://") || (remote.contains("@") && remote.contains(":") && !remote.contains("://"))
    }

    private var canClone: Bool {
        !cloning && !isSSH && (remote.hasPrefix("https://") || remote.hasPrefix("file://") || remote.hasPrefix("/"))
    }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    TextField("https://github.com/you/password-store.git", text: $remote)
                        .keyboardType(.URL)
                        .textContentType(.URL)
                    TextField("Branch (optional)", text: $branch)
                } header: {
                    Text("Repository")
                } footer: {
                    if isSSH {
                        Text("SSH isn't supported yet. Use the repository's HTTPS URL with an access token.")
                            .foregroundStyle(.red)
                    }
                }

                Section {
                    TextField("Username", text: $username)
                        .textContentType(.username)
                    SecureField("Access Token or Password", text: $password)
                        .textContentType(.password)
                } header: {
                    Text("Credentials")
                } footer: {
                    Text("For GitHub, create a fine-grained token limited to this repository with \"Contents: Read and write\". The token stays in this device's keychain. Leave empty for public repositories.")
                }

                if let progress = store.cloneProgress {
                    Section {
                        ProgressView(value: progress.fraction) {
                            Text("Cloning…")
                        } currentValueLabel: {
                            if progress.totalObjects > 0 {
                                Text("\(progress.receivedObjects) of \(progress.totalObjects) objects")
                            }
                        }
                    }
                }

                if let error {
                    Section {
                        Label(error, systemImage: "exclamationmark.triangle")
                            .foregroundStyle(.red)
                    }
                }
            }
            .textInputAutocapitalization(.never)
            .autocorrectionDisabled()
            .navigationTitle("Clone Repository")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel", role: .cancel) { dismiss() }
                        .disabled(cloning)
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Clone", role: .confirm) { Task { await clone() } }
                        .disabled(!canClone)
                }
            }
            .interactiveDismissDisabled(cloning)
        }
    }

    private func clone() async {
        cloning = true
        error = nil
        defer { cloning = false }
        do {
            let trimmedBranch = branch.trimmingCharacters(in: .whitespaces)
            try await store.clone(
                remote: remote.trimmingCharacters(in: .whitespaces), branch: trimmedBranch.isEmpty ? nil : trimmedBranch,
                username: username.trimmingCharacters(in: .whitespaces), password: password)
            dismiss()
        } catch {
            self.error = error.localizedDescription
        }
    }
}
