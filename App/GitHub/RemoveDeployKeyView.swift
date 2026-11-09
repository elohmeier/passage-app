import GitHubKit
import SwiftUI

/// Closing a store connected through "Connect GitHub": sign in once more (device flow) to
/// delete its deploy key, so the closed store's key can't reach the repository anymore.
struct RemoveDeployKeyView: View {
    @Environment(StoreModel.self) private var store
    @Environment(\.dismiss) private var dismiss
    @Environment(\.openURL) private var openURL
    let link: GitStoreConfig.GitHubLink

    private enum Phase: Equatable {
        case start
        case code(DeviceFlow.Code)
        case working
        case done
        case failed(String)
    }

    @State private var phase = Phase.start
    @State private var task: Task<Void, Never>?

    var body: some View {
        NavigationStack {
            Form {
                switch phase {
                case .start:
                    Section {
                        Button("Sign In to GitHub", systemImage: "link") { start() }.bold()
                        Button("Close Without Removing", role: .destructive) { closeStore() }
                    } footer: {
                        Text("Removes the deploy key \"Passage on …\" from \(link.fullName), then closes the store. Signing in is only used for this and not kept.")
                    }
                case .code(let code):
                    Section {
                        Text(code.userCode).font(.system(.largeTitle, design: .monospaced).bold()).frame(maxWidth: .infinity)
                        Button("Open GitHub", systemImage: "safari") { openURL(code.verificationURI) }
                    } footer: {
                        Text("The code is on the clipboard. Approve on GitHub, then come back.")
                    }
                case .working:
                    ProgressView("Removing the deploy key…")
                case .done:
                    Label("Deploy key removed. The store is closed.", systemImage: "checkmark.circle")
                case .failed(let message):
                    Section {
                        Label(message, systemImage: "exclamationmark.triangle").foregroundStyle(.red)
                        Button("Close Anyway", role: .destructive) { closeStore() }
                    } footer: {
                        Text("You can remove the key yourself in the repository's Settings › Deploy keys.")
                    }
                }
            }
            .navigationTitle("Close Store")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button(phase == .done ? "Done" : "Cancel", role: .cancel) {
                        task?.cancel()
                        dismiss()
                    }
                }
            }
        }
    }

    private func start() {
        guard let clientID = AppConfig.gitHubClientID else { return }
        let flow = DeviceFlow(clientID: clientID)
        task = Task {
            do {
                let code = try await flow.requestCode()
                UIPasteboard.general.string = code.userCode
                phase = .code(code)
                let token = try await flow.waitForToken(code)
                phase = .working
                try await GitHubAPI(token: token).deleteDeployKey(link.deployKeyID, from: link.fullName)
                closeStore()
                phase = .done
            } catch is CancellationError {
            } catch GitHubError.http(status: 404, _) {
                // Already gone (removed on GitHub, or the app lost access).
                closeStore()
                phase = .done
            } catch {
                phase = .failed(error.localizedDescription)
            }
        }
    }

    private func closeStore() {
        store.close()
        if phase != .done && phase != .working { dismiss() }
    }
}
