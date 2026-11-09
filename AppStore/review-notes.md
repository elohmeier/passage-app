# Notes for App Review (draft)

Passage is a client for "passage" password stores (age-encrypted files in a git repository or a Files folder). It needs no account; the reviewer doesn't need GitHub or any server.

To review without setup:
1. On the welcome screen, tap "Try Demo Store".
2. Passage creates a key for this device (Face ID/passcode prompt) and a sample store with five entries, encrypted to it.
3. Open an entry (e.g. social/mastodon) to see the password and a one-time code. Copy, edit and create entries.

AutoFill: Settings ▸ General ▸ AutoFill & Passwords ▸ enable Passage, then open a login page (for example https://mail.example.com is in the demo store) in Safari.

Optional features that need the reviewer's own resources and can be skipped:
- Connect GitHub: signs in with the GitHub device flow to add a deploy key to a repository of the user's choice.
- YubiKey (NFC): only used for decrypting entries encrypted to a YubiKey.

Encryption: the app uses standard encryption (age: X25519, ML-KEM-768, ChaCha20-Poly1305, via Apple CryptoKit) only to protect the user's own data; it qualifies for the exemption under Category 5 Part 2 (ITSAppUsesNonExemptEncryption = NO).

Camera: only for scanning QR codes (one-time code setup, keys, repository addresses).
