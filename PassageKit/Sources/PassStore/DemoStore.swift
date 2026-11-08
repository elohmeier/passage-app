import AgeCrypto
import Foundation

/// A small sample store, for App Review and for trying the app without a real store.
public enum DemoStore {
    public static let entries: [(path: String, content: String)] = [
        ("email/alice@example.com", "correct-horse-battery-staple\nusername: alice@example.com\nurl: https://mail.example.com\n"),
        ("email/work", "Tr0ub4dor&3\nusername: alice.smith\nurl: https://outlook.example.org\nrecovery codes: 1234-5678 9012-3456\n"),
        ("social/mastodon", "s3cure-but-memorable\nusername: @alice@example.social\nurl: https://example.social\notpauth://totp/example.social:alice?secret=JBSWY3DPEHPK3PXP&issuer=example.social\n"),
        ("finance/bank", "9f!Kq2#mZ7\nusername: 12345678\nurl: https://bank.example.com\nPIN: 4711\nnotes: |\n  Card ends in 4242.\n  Branch: Example Street\n"),
        ("home/wifi", "hunter2hunter2\nSSID: Example Home\n"),
    ]

    /// Writes the demo entries and an `.age-recipients` to `root`, encrypted to `recipients`.
    public static func create(at root: URL, recipients: [any AgeRecipient]) throws {
        let fm = FileManager.default
        try? fm.removeItem(at: root)
        try fm.createDirectory(at: root, withIntermediateDirectories: true)
        let recipientsFile = "# Demo store\n" + recipients.map { $0.encoded + "\n" }.joined()
        try Data(recipientsFile.utf8).write(to: root.appending(path: ".age-recipients"))
        for (path, content) in entries {
            let url = root.appending(path: path + ".age")
            try fm.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
            try Age.encrypt(Data(content.utf8), to: recipients).write(to: url, options: .atomic)
        }
    }
}
