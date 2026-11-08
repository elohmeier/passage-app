import KeyStore
import SwiftUI

/// Reads a YubiKey's PIV keys and adds the chosen one as an identity.
struct AddYubiKeyView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @State private var serial: UInt32?
    @State private var keys: [YubiKeyService.SlotKey] = []
    @State private var scanning = false
    @State private var error: String?

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Button(scanning ? "Reading…" : "Read YubiKey", systemImage: "wave.3.right") { Task { await scan() } }
                        .disabled(scanning)
                } footer: {
                    Text("Hold the YubiKey near the top of your iPhone, or plug it in. Passage reads the public keys in the PIV slots age-plugin-yubikey uses. The private keys stay on the YubiKey.")
                }

                if let serial, !keys.isEmpty {
                    Section("YubiKey \(String(serial))") {
                        ForEach(keys) { key in
                            Button {
                                add(key, serial: serial)
                            } label: {
                                VStack(alignment: .leading) {
                                    Text("Slot \(String(format: "%02X", key.slot))")
                                    Text(key.needsPIN ? "PIN required" : "No PIN")
                                        .font(.caption).foregroundStyle(.secondary)
                                }
                            }
                            .tint(.primary)
                        }
                    }
                }

                if let error {
                    Section { Label(error, systemImage: "exclamationmark.triangle").foregroundStyle(.red) }
                }
            }
            .navigationTitle("Add YubiKey")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel", role: .cancel) { dismiss() } }
            }
        }
    }

    private func scan() async {
        scanning = true
        error = nil
        defer { scanning = false }
        do {
            (serial, keys) = try await YubiKeyService.shared.scan()
        } catch {
            self.error = error.localizedDescription
        }
    }

    private func add(_ key: YubiKeyService.SlotKey, serial: UInt32) {
        let ref = StoredIdentity.YubiKeyRef(serial: serial, slot: key.slot, publicKey: key.publicKey, needsPIN: key.needsPIN)
        if model.addYubiKey(ref, name: "YubiKey \(serial)") { dismiss() }
    }
}
