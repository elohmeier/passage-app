import AgeCrypto
import Foundation

/// A small sample store, for App Review and for trying the app without a real store.
public enum DemoStore {
    public static let entries: [(path: String, content: String)] = [
        ("email/alice@example.com", "correct-horse-battery-staple\nusername: alice@example.com\nurl: https://mail.example.com\n"),
        ("email/work", "Tr0ub4dor&3\nusername: alice.smith\nurl: https://outlook.example.org\nrecovery codes: 1234-5678 9012-3456\n"),
        ("social/mastodon", "s3cure-but-memorable\nusername: @alice@example.social\nurl: https://example.social\notpauth://totp/example.social:alice?secret=JBSWY3DPEHPK3PXP&issuer=example.social\n"),
        ("social/forum.example.net", "plaid-otter-glimmer-82\nusername: alice\nurl: https://forum.example.net/login\n"),
        ("finance/bank", "9f!Kq2#mZ7\nusername: 12345678\nurl: https://bank.example.com\nPIN: 4711\nnotes: |\n  Card ends in 4242.\n  Branch: Example Street\n"),
        ("finance/brokerage", "w7$Lr9!vQ2pX\nusername: alice.s\nurl: https://invest.example.com\notpauth://totp/Invest:alice?secret=KRSXG5CTMVRXEZLU&issuer=Invest\n"),
        ("finance/tax-office", "ledger-maple-compass-17\nusername: 01 234 567 890\nurl: https://tax.example.gov\n"),
        ("home/wifi", "hunter2hunter2\nSSID: Example Home\n"),
        ("home/router", "Rt-4k9#Pz!m\nusername: admin\nurl: http://192.168.1.1\n"),
        ("home/alarm", "8642\nnotes: Code for the front door panel.\n"),
        ("shopping/bookshop.example", "quiet-lantern-harbor-5\nusername: alice@example.com\nurl: https://bookshop.example\n"),
        ("shopping/grocer.example", "Gr0c3r!es-2026\nusername: alice@example.com\nurl: https://grocer.example\n"),
        ("travel/airline.example", "jet-lag-sunrise-39\nusername: FF 1234 5678\nurl: https://airline.example\n"),
        ("work/git.example.com", "ghost-violin-ember-64\nusername: asmith\nurl: https://git.example.com\notpauth://totp/git.example.com:asmith?secret=MFRGGZDFMZTWQ2LK&issuer=git.example.com\n"),
        ("work/vpn", "V9n!x2Qe#7Lm\nusername: asmith\nurl: https://vpn.example.org\n"),
    ]

    /// Writes the demo entries and an `.age-recipients` to `root`, encrypted to `recipients`.
    /// Returns every entry with its plaintext, e.g. to index them for AutoFill.
    @discardableResult
    public static func create(at root: URL, recipients: [any AgeRecipient]) throws -> [(path: EntryPath, content: String)] {
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
        // A passkey, as Passage stores them (KeePassXC fields).
        let passkey = Passkey.create(relyingParty: "example.com", userName: "alice", userHandle: Data("alice".utf8))
        let url = root.appending(path: passkey.suggestedPath.path + ".age")
        try fm.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        try Age.encrypt(Data(passkey.entryText.utf8), to: recipients).write(to: url, options: .atomic)
        return entries.map { (EntryPath($0.path), $0.content) } + [(passkey.suggestedPath, passkey.entryText)]
    }
}
