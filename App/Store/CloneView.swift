import GitSync
import SwiftUI

struct CloneView: View {
    @Environment(StoreModel.self) private var store
    @Environment(\.dismiss) private var dismiss
    @Environment(\.openURL) private var openURL
    @State private var remote = ""
    @State private var branch = ""
    @State private var username = ""
    @State private var password = ""
    @State private var error: String?
    @State private var cloning = false
    @State private var hostToTrust: HostKey?
    @State private var publicKey: String?
    @State private var scanning = false

    init(remote: String = "") {
        _remote = State(initialValue: remote)
    }

    private var trimmedRemote: String { remote.trimmingCharacters(in: .whitespaces) }
    private var isSSH: Bool { GitStoreConfig.isSSH(trimmedRemote) }

    private var canClone: Bool {
        !cloning && (isSSH || trimmedRemote.hasPrefix("https://") || trimmedRemote.hasPrefix("file://") || trimmedRemote.hasPrefix("/"))
    }

    var body: some View {
        NavigationStack {
            Form {
                Section("Repository") {
                    TextField("git@github.com:you/password-store.git", text: $remote)
                        .keyboardType(.URL)
                    TextField("Branch (optional)", text: $branch)
                    Button("Scan QR Code", systemImage: "qrcode.viewfinder") { scanning = true }
                }

                if isSSH {
                    sshKeySection
                } else {
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
            .sheet(isPresented: $scanning) {
                QRScannerView(title: "Scan Repository") { code in
                    guard GitStoreConfig.isSSH(code) || code.hasPrefix("https://") else { return false }
                    remote = code
                    return true
                }
            }
            .alert(
                "Trust \(hostToTrust?.host ?? "")?", isPresented: Binding(get: { hostToTrust != nil }, set: { if !$0 { hostToTrust = nil } }),
                presenting: hostToTrust
            ) { key in
                Button("Trust and Connect") {
                    store.trust(key)
                    Task { await clone() }
                }
                Button("Cancel", role: .cancel) {}
            } message: { key in
                Text("This is the first connection to \(key.host). Check that its \(key.algorithm) key fingerprint matches what the server's operator publishes:\n\n\(key.fingerprint)")
            }
            .task(id: isSSH) {
                if isSSH { publicKey = try? store.deviceSSHKey().publicKeyLine(comment: "passage-ios") }
            }
        }
    }

    private var sshKeySection: some View {
        Section {
            if let publicKey {
                Text(publicKey)
                    .font(.caption.monospaced())
                    .lineLimit(1)
                    .truncationMode(.middle)
                HStack {
                    Button("Copy", systemImage: "doc.on.doc") { UIPasteboard.general.string = publicKey }
                    Spacer()
                    ShareLink(item: publicKey)
                }
                .buttonStyle(.borderless)
                if let repo = GitStoreConfig.gitHubRepository(trimmedRemote), let url = URL(string: "https://github.com/\(repo)/settings/keys/new") {
                    Button("Add as Deploy Key on GitHub", systemImage: "arrow.up.forward.app") {
                        UIPasteboard.general.string = publicKey
                        openURL(url)
                    }
                }
            }
        } header: {
            Text("This Device's SSH Key")
        } footer: {
            Text("The key lives in the Secure Enclave and can't be copied off this device. Add the public key to the server. On GitHub, a deploy key with write access limits it to this one repository; the button copies the key and opens the page.")
        }
    }

    private func clone() async {
        cloning = true
        error = nil
        defer { cloning = false }
        do {
            let trimmedBranch = branch.trimmingCharacters(in: .whitespaces)
            try await store.clone(
                remote: trimmedRemote, branch: trimmedBranch.isEmpty ? nil : trimmedBranch,
                username: username.trimmingCharacters(in: .whitespaces), password: password)
            dismiss()
        } catch let gitError as GitError {
            if case .unknownHostKey(let key) = gitError.kind {
                hostToTrust = key
            } else {
                error = gitError.localizedDescription
            }
        } catch {
            self.error = error.localizedDescription
        }
    }
}
