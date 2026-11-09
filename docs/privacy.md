---
title: Privacy Policy
permalink: /privacy/
---

# Passage — Privacy Policy

*Last updated: November 9, 2026*

Passage is a password manager for [passage](https://github.com/FiloSottile/passage) stores. It is built so that its developer never receives your data.

## What Passage collects

Nothing. Passage has no accounts, no analytics, no crash reporting, no advertising and no third-party SDKs. The developer has no server and receives no data from the app.

## Where your data goes

- **Your passwords** stay in your password store: a folder you choose in the Files app, or a git repository you clone. Entries are encrypted with [age](https://age-encryption.org) before they're written. Passage only talks to the git server you configure (for example GitHub), to sync the encrypted files.
- **Your keys** are created in this device's Secure Enclave or stored encrypted in its keychain, and are never synced to iCloud. Imported keys are encrypted to a Secure Enclave key. YubiKey keys never leave the YubiKey.
- **GitHub sign-in** (optional) is only used during setup to add a deploy key to the repository you pick. Passage doesn't keep the sign-in token.
- **AutoFill** keeps an index of entry names, websites and usernames on this device so it can suggest logins. It contains no passwords.

## Permissions

- **Face ID / Touch ID** unlocks your keys. Biometric data never leaves the Secure Enclave and Passage never sees it.
- **Camera** (optional) scans QR codes for one-time codes, keys and repository addresses. Images are not stored or sent anywhere.
- **NFC** (optional) talks to your YubiKey.

## Contact

Questions: open an issue at <https://github.com/elohmeier/passage-app/issues>.
