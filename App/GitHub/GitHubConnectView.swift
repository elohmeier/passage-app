import GitHubKit
import SwiftUI

struct GitHubConnectView: View {
    @Environment(StoreModel.self) private var store
    @Environment(\.dismiss) private var dismiss
    @Environment(\.openURL) private var openURL
    @State private var model: GitHubConnectModel
    @State private var confirmingPublic: GitHubAPI.Repository?
    @Environment(\.scenePhase) private var scenePhase

    init(clientID: String, appSlug: String) {
        _model = State(initialValue: GitHubConnectModel(clientID: clientID, appSlug: appSlug))
    }

    var body: some View {
        NavigationStack {
            content
                .navigationTitle("Connect GitHub")
                .navigationBarTitleDisplayMode(.inline)
                .toolbar {
                    ToolbarItem(placement: .cancellationAction) {
                        Button("Cancel", role: .cancel) {
                            model.finish()
                            dismiss()
                        }
                    }
                }
        }
        .interactiveDismissDisabled(isConnecting)
        // Coming back from GitHub (installation changed in Safari): refresh the list.
        .onChange(of: scenePhase) { _, phase in
            guard phase == .active else { return }
            switch model.step {
            case .pickRepository, .needsInstallation: Task { await model.loadRepositories() }
            default: break
            }
        }
        .onDisappear { model.finish() }
        #if DEBUG
            .onAppear { model.applyDebugStep() }
            .onChange(of: model.autoPicked) { _, repo in
                if let repo { Task { await connect(repo) } }
            }
        #endif
        .alert(
            "\(confirmingPublic?.fullName ?? "") is public", isPresented: Binding(get: { confirmingPublic != nil }, set: { if !$0 { confirmingPublic = nil } }),
            presenting: confirmingPublic
        ) { repo in
            Button("Use Anyway", role: .destructive) { Task { await connect(repo) } }
            Button("Cancel", role: .cancel) {}
        } message: { _ in
            Text("Entries are encrypted, but anyone can see file names (often site and user names) and the history. A private repository is strongly recommended.")
        }
    }

    private var isConnecting: Bool {
        if case .connecting = model.step { return true }
        return false
    }

    @ViewBuilder private var content: some View {
        switch model.step {
        case .start:
            Form {
                Section {
                    Label("Sign in to GitHub in the browser and approve access", systemImage: "1.circle")
                    Label("Choose the repository with your store", systemImage: "2.circle")
                    Label("Passage adds a key from this device's Secure Enclave as a deploy key for that one repository", systemImage: "3.circle")
                } footer: {
                    Text("Passage doesn't keep your GitHub sign-in. After setup it syncs only with the deploy key, which can't leave this device and can only reach the repository you pick. You can revoke it anytime under the repository's Deploy keys.")
                }
                Section {
                    Button("Continue with GitHub") { Task { await model.start() } }
                        .bold()
                }
            }

        case .waitingForApproval(let code):
            Form {
                Section {
                    VStack(spacing: 12) {
                        Text(code.userCode)
                            .font(.system(.largeTitle, design: .monospaced).bold())
                            .textSelection(.enabled)
                        Text("Copied to the clipboard. Paste it on GitHub and approve.")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                            .multilineTextAlignment(.center)
                    }
                    .frame(maxWidth: .infinity)
                    .padding(.vertical)
                }
                Section {
                    Button("Open GitHub", systemImage: "safari") { openURL(code.verificationURI) }
                        .bold()
                } footer: {
                    HStack(spacing: 8) {
                        ProgressView()
                        Text("Waiting for approval…")
                    }
                }
            }

        case .loading:
            ProgressView("Loading repositories…")
                .frame(maxWidth: .infinity, maxHeight: .infinity)

        case .needsInstallation:
            ContentUnavailableView {
                Label("No Repositories", systemImage: "lock.shield")
            } description: {
                Text("Install the Passage GitHub App on the repository that holds your store. Choose \"Only select repositories\" to share just that one.")
            } actions: {
                Button("Install on GitHub") { openURL(model.installURL) }
                    .buttonStyle(.borderedProminent)
                Button("I've Installed It") { Task { await model.loadRepositories() } }
            }

        case .pickRepository(let candidates):
            List {
                Section {
                    ForEach(candidates) { candidate in
                        Button {
                            if candidate.repository.private {
                                Task { await connect(candidate.repository) }
                            } else {
                                confirmingPublic = candidate.repository
                            }
                        } label: {
                            RepositoryRow(candidate: candidate)
                        }
                        .tint(.primary)
                    }
                }
                Section {
                    // A real Link: Markdown links with an interpolated URL aren't tappable.
                    Link(destination: model.installURL) {
                        Label("Add a Repository on GitHub", systemImage: "plus.circle")
                    }
                } footer: {
                    Text("Missing a repository? Add it to the Passage app's installation on GitHub. The list updates when you come back.")
                }
            }
            .refreshable { await model.loadRepositories() }

        case .connecting(let message):
            VStack(spacing: 16) {
                ProgressView()
                Text(message)
                if let progress = store.cloneProgress, progress.totalObjects > 0 {
                    ProgressView(value: progress.fraction)
                        .frame(maxWidth: 240)
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)

        case .failed(let message):
            ContentUnavailableView {
                Label("Couldn't Connect", systemImage: "exclamationmark.triangle")
            } description: {
                Text(message)
            } actions: {
                Button("Start Over") { Task { await model.start() } }
            }
        }
    }

    private func connect(_ repository: GitHubAPI.Repository) async {
        if await model.connect(repository, store: store) {
            dismiss()
        }
    }
}

private struct RepositoryRow: View {
    let candidate: GitHubConnectModel.Candidate

    var body: some View {
        HStack {
            VStack(alignment: .leading, spacing: 2) {
                Text(candidate.repository.fullName)
                HStack(spacing: 6) {
                    if candidate.looksLikeStore {
                        Label("passage store", systemImage: "key.horizontal")
                    }
                    if !candidate.repository.private {
                        Label("public", systemImage: "globe")
                            .foregroundStyle(.orange)
                    }
                }
                .font(.caption)
                .foregroundStyle(.secondary)
            }
            Spacer()
            Image(systemName: "chevron.right")
                .font(.caption)
                .foregroundStyle(.tertiary)
        }
    }
}
