import KeyStore
import PassStore
import SwiftUI

/// Offered at the top of an empty store (e.g. a new GitHub repository).
struct SetUpStoreSection: View {
    @Environment(StoreModel.self) private var store
    /// Presents `SetUpStoreView`; the sheet lives on the list, as sheets on list sections are
    /// unreliable.
    @Binding var settingUp: Bool

    var body: some View {
        if store.needsSetup {
            Section {
                Label("This store is empty", systemImage: "sparkles")
                    .font(.headline)
                Text("Set it up as a new password store, encrypted to this device and a recovery key you keep somewhere safe.")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                Button("Set Up This Store", systemImage: "plus.circle.fill") { settingUp = true }
            }
        }
    }
}

/// Creates a recovery key, shows it once, has the user confirm they saved it, then writes
/// `.age-recipients` and a README and pushes. The recovery key is never stored by the app.
struct SetUpStoreView: View {
    @Environment(AppModel.self) private var model
    @Environment(StoreModel.self) private var store
    @Environment(\.dismiss) private var dismiss

    private enum Step { case intro, key, confirm }

    @State private var step = Step.intro
    @State private var postQuantum = true
    @State private var kit: RecoveryKit?
    @State private var confirmation = ""
    @State private var exporting = false
    @State private var working = false
    @State private var error: String?

    var body: some View {
        NavigationStack {
            Form {
                switch step {
                case .intro: intro
                case .key: if let kit { key(kit) }
                case .confirm: if let kit { confirm(kit) }
                }
                if let error {
                    Section {
                        Label(error, systemImage: "exclamationmark.triangle").foregroundStyle(.red)
                    }
                }
            }
            .navigationTitle("New Store")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel", role: .cancel) { dismiss() }.disabled(working)
                }
                ToolbarItem(placement: .confirmationAction) { nextButton }
            }
            .interactiveDismissDisabled(kit != nil)
        }
    }

    // MARK: Steps

    private var intro: some View {
        Group {
            Section {
                Text("Entries will be encrypted to two keys:")
                Label("This device's key, in the Secure Enclave", systemImage: "iphone")
                Label("A recovery key, shown once for you to keep", systemImage: "key.viewfinder")
            } footer: {
                Text("If this device is lost, the recovery key is the only way to read the store. Use it on a computer with passage or age, or import it into Passage on a new device. Passage doesn't keep a copy.")
            }
            Section {
                Toggle("Post-Quantum Encryption", isOn: $postQuantum)
            } footer: {
                Text(postQuantum
                    ? "Protects against future quantum computers. Needs age 1.3 or later on other devices."
                    : "Classic X25519 keys, readable with any age version.")
            }
        }
    }

    private func key(_ kit: RecoveryKit) -> some View {
        Group {
            Section {
                QRCodeView(text: kit.identity)
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 8)
                Text(kit.identity)
                    .font(.caption.monospaced())
                    .textSelection(.enabled)
            } header: {
                Text("Recovery Key")
            } footer: {
                Text("Write it down, print it, or save it in another password manager. Anyone with this key can read every entry.")
            }
            .privacySensitive()
            Section {
                Button("Copy", systemImage: "doc.on.doc") { SecurePasteboard.copy(kit.identity, expiresAfter: 120) }
                Button("Save to Files…", systemImage: "folder") { exporting = true }
                Button("Print…", systemImage: "printer") { print(kit) }
            }
            .fileExporter(
                isPresented: $exporting, item: kit.file(store: store.name), contentTypes: [.plainText],
                defaultFilename: "passage-recovery-key.txt"
            ) { _ in }
        }
    }

    private func confirm(_ kit: RecoveryKit) -> some View {
        Section {
            TextField("Last 6 characters", text: $confirmation)
                .font(.body.monospaced())
                .textInputAutocapitalization(.characters)
                .autocorrectionDisabled()
        } header: {
            Text("Confirm You Saved It")
        } footer: {
            Text("Type the last 6 characters of the recovery key, from where you saved it.")
        }
    }

    private var nextButton: some View {
        Group {
            switch step {
            case .intro:
                Button("Next") {
                    do {
                        kit = try RecoveryKit(postQuantum: postQuantum)
                        step = .key
                    } catch {
                        self.error = error.localizedDescription
                    }
                }
            case .key:
                Button("I Saved It") { step = .confirm }
            case .confirm:
                Button(working ? "Creating…" : "Create", role: .confirm) { Task { await create() } }
                    .disabled(working || confirmation.trimmingCharacters(in: .whitespaces).uppercased() != kit?.confirmationSuffix)
            }
        }
    }

    // MARK: Actions

    private func create() async {
        guard let kit else { return }
        working = true
        error = nil
        defer { working = false }
        guard let device = model.deviceIdentity ?? model.createDeviceIdentity(name: UIDevice.current.name) else {
            error = model.errorMessage ?? "Couldn't create this device's key."
            return
        }
        do {
            if try await store.setUpNewStore(device: device, recovery: kit) {
                dismiss()
            } else {
                // Committed locally; the push is retried with the next sync.
                error = store.syncProblem.map { "Saved on this device, but couldn't push yet: \($0)" }
                if error == nil { dismiss() }
            }
        } catch {
            self.error = error.localizedDescription
        }
    }

    private func print(_ kit: RecoveryKit) {
        let formatter = UISimpleTextPrintFormatter(
            text: "Passage recovery key\n\n\(kit.file(store: store.name))\nKeep this page somewhere safe. Anyone with it can read the store.")
        formatter.font = .monospacedSystemFont(ofSize: 11, weight: .regular)
        formatter.perPageContentInsets = UIEdgeInsets(top: 72, left: 72, bottom: 72, right: 72)
        let info = UIPrintInfo.printInfo()
        info.outputType = .grayscale
        info.jobName = "Passage Recovery Key"
        let controller = UIPrintInteractionController.shared
        controller.printInfo = info
        controller.printFormatter = formatter
        controller.present(animated: true)
    }
}
