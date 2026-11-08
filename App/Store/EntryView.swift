import PassStore
import SwiftUI

/// Decrypts and shows one entry. The plaintext lives only in this view's state and is dropped
/// when the view disappears or the app leaves the foreground.
struct EntryView: View {
    @Environment(AppModel.self) private var model
    @Environment(StoreModel.self) private var store
    @Environment(\.scenePhase) private var scenePhase
    let entry: EntryPath

    private enum Phase {
        case locked
        case decrypting
        case decrypted(Entry, text: String)
        case failed(String)
    }

    @State private var phase = Phase.locked
    @State private var copied: String?
    @State private var editing: EntryEditorView.Mode?
    @State private var confirmingDelete = false
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        Group {
            switch phase {
            case .locked, .decrypting:
                ProgressView()
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            case .decrypted(let e, _):
                EntryDetail(entry: e, copy: copy)
            case .failed(let message):
                ContentUnavailableView {
                    Label("Can't Decrypt", systemImage: "lock.trianglebadge.exclamationmark")
                } description: {
                    Text(message)
                } actions: {
                    Button("Try Again") { Task { await decrypt() } }
                }
            }
        }
        .navigationTitle(entry.name)
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            if case .decrypted(_, let text) = phase {
                ToolbarItem(placement: .topBarTrailing) {
                    Button("Edit") { editing = .edit(entry, text: text) }
                }
            }
            ToolbarItem(placement: .topBarTrailing) {
                Menu("More", systemImage: "ellipsis") {
                    Button("Delete", systemImage: "trash", role: .destructive) { confirmingDelete = true }
                }
            }
        }
        .sheet(item: $editing) { mode in
            EntryEditorView(mode: mode) { saved in
                if saved != entry { dismiss() }
                Task { await decrypt() }
            }
        }
        .confirmationDialog("Delete \(entry.name)?", isPresented: $confirmingDelete, titleVisibility: .visible) {
            Button("Delete", role: .destructive) {
                Task {
                    do {
                        try await store.delete(entry)
                        dismiss()
                    } catch {
                        phase = .failed(error.localizedDescription)
                    }
                }
            }
        } message: {
            Text(store.gitConfig != nil ? "The deletion is committed and synced. It stays in the git history." : "This deletes the file from the folder.")
        }
        .overlay(alignment: .bottom) {
            if let copied {
                Label("\(copied) copied, clears in \(model.clipboardSeconds) s", systemImage: "doc.on.doc")
                    .font(.footnote)
                    .padding(.horizontal, 14)
                    .padding(.vertical, 8)
                    .glassEffect()
                    .padding()
                    .transition(.move(edge: .bottom).combined(with: .opacity))
            }
        }
        .sensoryFeedback(.success, trigger: copied) { _, new in new != nil }
        .task(id: entry) { await decrypt() }
        .onChange(of: scenePhase) { _, newPhase in
            // Not on .inactive: the Face ID sheet itself makes the scene inactive.
            if newPhase == .background { phase = .locked }
            if newPhase == .active, case .locked = phase { Task { await decrypt() } }
        }
        .onDisappear { phase = .locked }
    }

    private func decrypt() async {
        guard scenePhase == .active else { return }
        phase = .decrypting
        do {
            let ciphertext = try await store.read(entry)
            let plaintext = try await model.decrypt(ciphertext)
            let text = String(decoding: plaintext, as: UTF8.self)
            phase = .decrypted(Entry(text), text: text)
        } catch {
            phase = .failed(error.localizedDescription)
        }
    }

    private func copy(_ label: String, _ value: String) {
        SecurePasteboard.copy(value, expiresAfter: model.clipboardSeconds)
        withAnimation { copied = label }
        Task {
            try? await Task.sleep(for: .seconds(2))
            withAnimation { if copied == label { copied = nil } }
        }
    }
}

private struct EntryDetail: View {
    let entry: Entry
    let copy: (String, String) -> Void

    var body: some View {
        List {
            Section {
                if let password = entry.password {
                    SecretRow(label: "Password", value: password, copy: copy)
                }
                if let username = entry.username {
                    ValueRow(label: "Username", value: username, copy: copy)
                }
                if let url = entry.url {
                    ValueRow(label: "Website", value: url, copy: copy)
                }
                if let otp = entry.otp {
                    OTPRow(otp: otp, copy: copy)
                }
            }

            let others = entry.fields.filter { f in
                !["username", "login", "user", "url"].contains(f.key?.lowercased() ?? "") || f.value != value(for: f.key)
            }
            if !others.isEmpty {
                Section("Fields") {
                    ForEach(others) { field in
                        let label = field.key ?? String(localized: "Note")
                        if field.isSensitive {
                            SecretRow(label: label, value: field.value, copy: copy)
                        } else {
                            ValueRow(label: label, value: field.value, copy: copy)
                        }
                    }
                }
            }
        }
    }

    /// The value shown in the top section for a well-known key, so it isn't repeated below.
    private func value(for key: String?) -> String? {
        switch key?.lowercased() {
        case "username", "login", "user": entry.username
        case "url": entry.url
        default: nil
        }
    }
}

private struct ValueRow: View {
    let label: String
    let value: String
    let copy: (String, String) -> Void

    var body: some View {
        Button {
            copy(label, value)
        } label: {
            VStack(alignment: .leading, spacing: 2) {
                Text(label).font(.caption).foregroundStyle(.secondary)
                Text(value).foregroundStyle(.primary)
            }
        }
        .tint(.primary)
        .contextMenu {
            Button("Copy", systemImage: "doc.on.doc") { copy(label, value) }
            if let url = URL(string: value), url.scheme == "https" || url.scheme == "http" {
                Link(destination: url) { Label("Open", systemImage: "safari") }
            }
        }
    }
}

private struct SecretRow: View {
    let label: String
    let value: String
    let copy: (String, String) -> Void
    @State private var revealed = false

    var body: some View {
        HStack {
            Button {
                copy(label, value)
            } label: {
                VStack(alignment: .leading, spacing: 2) {
                    Text(label).font(.caption).foregroundStyle(.secondary)
                    Text(revealed ? value : String(repeating: "•", count: 12))
                        .font(.body.monospaced())
                        .foregroundStyle(.primary)
                        .privacySensitive()
                }
            }
            .tint(.primary)
            Spacer()
            Button(revealed ? "Hide" : "Show", systemImage: revealed ? "eye.slash" : "eye") { revealed.toggle() }
                .labelStyle(.iconOnly)
                .buttonStyle(.borderless)
        }
        .contextMenu {
            Button("Copy", systemImage: "doc.on.doc") { copy(label, value) }
        }
    }
}

private struct OTPRow: View {
    let otp: OTP
    let copy: (String, String) -> Void

    var body: some View {
        TimelineView(.periodic(from: .now, by: 1)) { context in
            let code = otp.code(at: context.date)
            Button {
                copy(String(localized: "Code"), code)
            } label: {
                HStack {
                    VStack(alignment: .leading, spacing: 2) {
                        Text("One-Time Code").font(.caption).foregroundStyle(.secondary)
                        Text(code.count == 6 ? "\(code.prefix(3)) \(code.suffix(3))" : code)
                            .font(.title3.monospacedDigit())
                            .foregroundStyle(.primary)
                            .contentTransition(.numericText())
                            .privacySensitive()
                    }
                    Spacer()
                    if let remaining = otp.secondsRemaining(at: context.date), let period = otp.period {
                        Gauge(value: remaining, in: 0...Double(period)) {
                            Text(Int(remaining.rounded(.up)), format: .number)
                        }
                        .gaugeStyle(.accessoryCircularCapacity)
                        .tint(remaining < 6 ? .red : .accentColor)
                        .scaleEffect(0.6)
                        .frame(width: 36, height: 36)
                    }
                }
            }
            .tint(.primary)
        }
    }
}
