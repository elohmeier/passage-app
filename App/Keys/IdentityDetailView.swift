import KeyStore
import SwiftUI

struct IdentityDetailView: View {
    @Environment(AppModel.self) private var model
    let identity: StoredIdentity
    @State private var name = ""
    @State private var postQuantum = true

    private var recipient: String {
        let pq = identity.recipients.first { $0.hasPrefix("age1tagpq1") }
        let classic = identity.recipients.first { $0.hasPrefix("age1tag1") }
        return (postQuantum ? pq : classic) ?? identity.recipients[0]
    }

    private var hasBothTypes: Bool { identity.recipients.count > 1 }

    var body: some View {
        Form {
            Section("Name") {
                TextField("Name", text: $name)
                    .onSubmit { model.rename(identity, to: name) }
            }

            Section {
                if hasBothTypes {
                    Picker("Type", selection: $postQuantum) {
                        Text("Post-quantum").tag(true)
                        Text("Classic").tag(false)
                    }
                    .pickerStyle(.segmented)
                }
                QRCodeView(text: recipient)
                    .frame(maxWidth: .infinity)
                    .padding(.vertical)
                // One line: wrapping would insert hyphens that aren't part of the key.
                Text(recipient)
                    .font(.caption.monospaced())
                    .lineLimit(1)
                    .truncationMode(.middle)
                HStack {
                    Button("Copy", systemImage: "doc.on.doc") {
                        UIPasteboard.general.string = recipient
                    }
                    Spacer()
                    ShareLink(item: recipient)
                }
                .buttonStyle(.borderless)
            } header: {
                Text("Recipient")
            } footer: {
                if hasBothTypes {
                    Text("age can't mix post-quantum and classic recipients in one file. If your store's .age-recipients contains ordinary age1… keys, use Classic; if it uses age1pq1… keys, use Post-quantum. This key can decrypt both.")
                }
            }

            if identity.kind != .imported {
                Section("Add to Your Store") {
                    Text(verbatim: """
                        echo '\(recipient)' >> "${PASSAGE_DIR:-$HOME/.passage/store}/.age-recipients"
                        passage reencrypt
                        """)
                    .font(.caption.monospaced())
                    .textSelection(.enabled)
                }
            }

            Section("Details") {
                LabeledContent("Kind", value: String(localized: identity.kindDescription))
                LabeledContent("Protection", value: String(localized: identity.protection.title))
                LabeledContent("Created", value: identity.createdAt, format: .dateTime)
            }
        }
        .navigationTitle(identity.name)
        .onAppear { name = identity.name }
    }
}

extension KeyProtection {
    var title: LocalizedStringResource {
        switch self {
        case .biometryCurrentSet: "Face ID / Touch ID (current enrollment)"
        case .userPresence: "Face ID / Touch ID or passcode"
        case .unprotected: "None"
        }
    }
}
