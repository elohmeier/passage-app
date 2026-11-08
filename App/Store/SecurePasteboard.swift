import UIKit
import UniformTypeIdentifiers

enum SecurePasteboard {
    /// Copies a secret: device-local (no Universal Clipboard), expiring, and marked as
    /// concealed so clipboard managers that honor the convention skip it.
    static func copy(_ string: String, expiresAfter seconds: Int) {
        UIPasteboard.general.setItems(
            [[UTType.utf8PlainText.identifier: string, "org.nspasteboard.ConcealedType": string]],
            options: [.localOnly: true, .expirationDate: Date.now.addingTimeInterval(TimeInterval(seconds))])
    }
}
