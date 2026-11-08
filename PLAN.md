# passage for iOS: implementation plan

An iOS client for a [passage](https://github.com/FiloSottile/passage) password store. Passage is
the [pass](https://www.passwordstore.org/) layout with [age](https://age-encryption.org) instead
of GPG. The reference app is [mssun/passforios](https://github.com/mssun/passforios) (commit
`cb836aa`). This plan keeps its feature set and file-format compatibility, but replaces its
architecture and security model.

## 1. Lessons from passforios

| Area | passforios | What we do instead |
| --- | --- | --- |
| Crypto | gopenpgp built with gomobile from a fork, with ObjectivePGP as a fallback; errors matched by string | One age implementation in pure Swift on CryptoKit. No Go toolchain. |
| Keys | Armored private keys and passphrases kept as plain keychain strings (`.whenUnlockedThisDeviceOnly`, no `SecAccessControl`). The passphrase can be "remembered" forever. | The private key is created in the Secure Enclave by default. Imported keys use biometric access control. Unlock sessions are time-limited. |
| Recipients | `.gpg-id` gives one key ID and quietly falls back to the only loaded key | Full `.age-recipients` semantics: nearest file walking up the tree, several recipients, mixed types |
| Git | ObjectiveGit, which is unmaintained. No conflict handling; the only recovery is a hard reset. | libgit2 behind a small Swift actor. Explicit conflict resolution that understands encrypted files. |
| UI | UIKit storyboards, iOS 13, singletons, prompts that block on semaphores | SwiftUI, Swift 6 strict concurrency, `@Observable`, async/await |
| Index | Core Data rebuilt on every pull; `fatalError` if it can't load | In-memory tree built from the file system (cheap). No persistent store. |
| AutoFill | Fills passwords only. Identity store filled lazily, one entry at a time. Matching is a token substring check. | Identity store filled in bulk, eTLD+1 matching from the `url:` field, one-time-code credentials, text insertion |
| App lock | Passcode stored as plaintext in the keychain and compared with `==`. Biometrics only checked through `LAContext`. | The lock is a keychain item with an access-control policy, so the OS enforces it |
| Clipboard | Cleared after 45 s by a background task, with an `endBackgroundTask(.invalid)` bug | `UIPasteboard` with the `.localOnly` and `.expirationDate` options, marked as concealed |
| Shortcuts | One legacy SiriKit intent | App Intents, with a Control Center control |

Parts we can port as they are (rewritten in modern Swift):

- The entry parser (`passKit/Parser/*`): first line is the password, then `key: value` fields, `|`/`>` multiline values, `otpauth://`, and the `otp_*` fields.
- The password generator, including the EFF word lists.
- The app-group layout for sharing data with the extensions.

## 2. Platform and tooling

- **Minimum iOS 26.** CryptoKit on iOS 26 adds ML-KEM-768, X-Wing, and ML-KEM keys stored in the Secure Enclave. We need these for post-quantum recipients. This is a personal or enthusiast app, so dropping older iOS versions is acceptable.
- Swift 6 language mode with strict concurrency. SwiftUI only, using the Liquid Glass design system.
- Supported platforms: iPhone, iPad, and Mac ("Designed for iPad" or Catalyst; Macs also have a Secure Enclave).
- Project layout: an Xcode project for the app and extension targets, plus a local Swift package `PassageKit`. All logic lives in the package, so it can be tested with `swift test` on macOS without a simulator.
- `justfile` with recipes for build, test, lint (`swift-format`), and interop tests.
- Dependencies, kept to a minimum:
  - libgit2 + libssh2 + OpenSSL/mbedTLS, as a prebuilt xcframework. Candidates: [SwiftGitX](https://github.com/ibrahimcetin/SwiftGitX), or our own build script pinned to libgit2 1.9.
  - Everything else is first-party: age, Bech32, scrypt, TOTP, the parser, and the public suffix list (bundled data file).
  - YubiKit only in a later phase (M8).

```
PassageKit/
  AgeCrypto     age v1 format: header, STREAM payload, recipient types, Bech32, armor
  KeyStore      Secure Enclave/keychain identities, SecAccessControl, unlock sessions
  PassStore     store tree, .age-recipients resolution, entry parser, OTP, generator
  GitSync       libgit2 actor: clone/fetch/merge/commit/push, credentials, conflicts
  AutoFillCore  domain matching, building the identity store
App/            SwiftUI app
AutoFill/       ASCredentialProviderViewController extension
Intents/        App Intents (in-app plus extension for the Control Center control)
```

## 3. Crypto layer (`AgeCrypto`)

A Swift implementation of [C2SP age](https://github.com/C2SP/C2SP/blob/main/age.md), built only on
CryptoKit.

- **Format.**
  - Header: parse and serialize the version line, stanzas wrapped at 64 columns, and the HMAC-SHA256 header MAC computed with an HKDF-derived key.
  - Payload: 16-byte nonce, HKDF payload key, then the STREAM construction with ChaCha20-Poly1305 over 64 KiB chunks, with the last-chunk flag.
  - ASCII armor on read; binary on write (passage writes binary).
- **Recipient and identity types:**

  | Type | Encoding | Read | Write | Notes |
  | --- | --- | --- | --- | --- |
  | X25519 | `age1…` / `AGE-SECRET-KEY-1…` | ✓ | ✓ | The usual passage desktop key |
  | X-Wing (PQ) | `age1pq…` / `AGE-SECRET-KEY-PQ-1…` | ✓ | ✓ | HPKE with the MLKEM768-X25519 KEM |
  | p256tag | `age1tag…` (also accepts `age1se1…`) | ✓ (SE) | ✓ | Hardware recipients |
  | mlkem768p256tag | `age1tagpq…` | ✓ (SE) | ✓ | Post-quantum hardware recipients |
  | ssh-ed25519 / ssh-rsa | `ssh-…` lines in `.age-recipients` | — | M5 | Passage users often list SSH keys. ssh-ed25519 needs an Edwards→Montgomery conversion. ssh-rsa needs RSA-OAEP with a label, which Security.framework lacks, so it needs its own small OAEP padding on top of raw RSA. |
  | piv-p256 | `age1yubikey1…`, `age1se1…` | M8 | ✓ | The stanza used by age-plugin-yubikey and age-plugin-se. Writing works natively, so stores that list Mac SE or YubiKey recipients stay writable. |
  | scrypt | passphrase | ✓ | — | Only for decrypting a passphrase-protected identities file on import |
  | other plugins | `age1<name>1…` | ✗ | ✗ | Folders using them are **read-only** in the app, with an explanation |

- **HPKE.** CryptoKit HPKE covers DHKEM(P-256) and X-Wing. The hybrid ML-KEM-768+P-256 KEM is not in CryptoKit, so we write a small combiner. remko/age-plugin-se (MIT) already contains `HPKE.swift` and `Bech32.swift` built on CryptoKit for exactly these stanzas; we adapt them with attribution.
- **Spec rules we must follow:**
  - Check the body length before decrypting (to prevent partitioning oracles).
  - An scrypt stanza must be the only stanza in a file.
  - Warn when a folder's recipients mix PQ and non-PQ types (the spec says files SHOULD NOT be encrypted to both).
- **Tests.**
  - All 147 vectors from [C2SP/CCTV/age/testdata](https://github.com/C2SP/CCTV/tree/main/age).
  - Round-trip interop with the `age` CLI in both directions, in CI.
  - Fixtures generated by `passage` (multi-recipient folders, nested `.age-recipients`).

## 4. Identities and device security (`KeyStore`)

**Default identity: a key in the Secure Enclave.**

- During onboarding the app generates an SE P-256 key, plus an SE ML-KEM-768 key for `age1tagpq`, which is the default. The private key never leaves the chip.
- The app shows the recipient string as text, a QR code, and a share sheet, with ready-to-paste commands:
  ```sh
  echo age1tagpq1… >> ~/.passage/store/.age-recipients
  passage reencrypt
  ```
  Desktop `age` 1.3 and later encrypts to `age1tag*` recipients natively, with no plugin.
- Access control is `[.privateKeyUsage, .biometryCurrentSet]`, with `.userPresence` as an option. Enrolling a new fingerprint or face invalidates the key, which defends against Stolen Device Protection bypasses.
- The SE key's `dataRepresentation` blob is stored in the shared keychain access group with `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly`. If the passcode is removed, the key is destroyed. The AutoFill extension can use it too.
- **Recovery is mandatory.** A device key cannot be backed up. Onboarding refuses to finish until `.age-recipients` contains at least one other recipient besides this device, and a health check in the app warns about any folder where this device is the only recipient.

**Imported software identities** (`AGE-SECRET-KEY-1…`, `AGE-SECRET-KEY-PQ-1…`, a passage `identities` file, or a scrypt-encrypted identities file):

- Import from paste, file, or QR code (VisionKit `DataScannerViewController`).
- Stored as a keychain generic password with `SecAccessControl(.biometryCurrentSet or .userPresence)` and `ThisDeviceOnly`, never synchronizable.
- Optional hardening: wrap the stored key with the SE key (ECIES), so a keychain extraction alone is useless.

**Unlock sessions**

- Each decrypt goes through an `LAContext`. The setting "Require Face ID: every time / 1 min / 5 min / until locked" maps to `touchIDAuthenticationAllowableReuseDuration`, or to keeping one `LAContext` alive for that window and invalidating it when the app moves to the background or the device locks.
- Unwrapped file keys and plaintext are never cached to disk. Plaintext `Data` buffers are zeroed after use where Swift allows it. That's best effort, and the docs will say so.
- There's no separate app passcode. The app lock is simply "unlock to see the store tree". It is optional, because file names are already plaintext in git.

**Other hardening**

- Every file in the app group uses `NSFileProtectionComplete`. The git working tree uses `completeUntilFirstUserAuthentication`, so background fetch still works; the files are encrypted anyway.
- A privacy cover in the app switcher. Revealed secrets are blurred when `sceneCaptureState` reports recording or mirroring. Secret views use `.privacySensitive()`.
- Clipboard: `setItems(_:options: [.localOnly: true, .expirationDate: …])` plus the `org.nspasteboard.ConcealedType` marker, with a configurable expiry (default 30 s).
- No network access except to git remotes: no favicon fetching, no analytics, no third-party SDKs. Declared in `PrivacyInfo.xcprivacy`.
- No Spotlight indexing, no `NSUserActivity` with entry names, and no widgets that show secrets on the Lock Screen.

## 5. Store model (`PassStore`)

- Store layout follows passage: `**/*.age` entries and `.age-recipients` in any folder (`#` comments and blank lines allowed). The nearest file walking up from the entry wins.
- Entry format is pass-compatible. The parser is a port of passforios's parser:
  - The username comes from `username`, `login`, or `user`, and falls back to the file name.
  - `url:` holds the URL.
  - OTP comes from an `otpauth://` URI or the `otp_*` fields.
- TOTP/HOTP use a small CryptoKit HMAC implementation instead of the OneTimePassword fork. An HOTP counter bump re-encrypts the entry and commits it.
- The index is an immutable tree snapshot rebuilt by enumerating files. A few thousand files takes milliseconds, so no Core Data. It is published through an `@Observable` `StoreModel`.
- Writes:
  1. Find the recipients for the target path.
  2. Encrypt to all of them.
  3. Write atomically.
  4. `git add`, then commit with a pass-style message (`Add given password for X to store.`).
- Moving or renaming across folders with different recipients **re-encrypts** the entry, like `passage mv` does. Decryption needs our identity to be among the old recipients.
- "Re-encrypt folder" action: for the case where the device was just added to `.age-recipients`, only if a current identity can decrypt the files.
- **Two storage backends in v1**, behind a `StoreBackend` protocol:
  - **Git**: a repo cloned into the app group container (see §6).
  - **Files folder**: a folder picked in the Files app (iCloud Drive, Working Copy, Syncthing apps, …), kept as a security-scoped bookmark stored in the app group so the AutoFill extension can resolve it too. Changes are watched with `NSFilePresenter`/`NSFileCoordinator`, every read and write is coordinated, and there is no commit step. iCloud placeholders (`.icloud` files) are downloaded on demand with `startDownloadingUbiquitousItem`.

## 6. Git (`GitSync`)

- A Swift `actor` wraps libgit2: clone (shallow is optional), fetch, merge, commit, push, and status/ahead-behind. Progress is reported through `AsyncStream`.
- **Authentication:**
  - HTTPS with a token (keychain item with `userPresence`).
  - SSH with an Ed25519 key generated on the device (CryptoKit). The app shows the public key to add as a deploy key.
  - Stretch goal: an SSH key in the Secure Enclave (`ecdsa-sha2-nistp256`) via libgit2's `git_credential_ssh_custom_new` sign callback, so the git credential is hardware-bound too. This depends on how libssh2 is built.
  - Host-key verification uses TOFU (trust on first use), with an editable known_hosts list. passforios skips this check.
- **Sync** is fetch, then fast-forward or merge, then push.
  - Conflicts are per file. Both sides are decrypted and compared field by field in a SwiftUI sheet. The choices are keep mine, keep theirs, keep both (`name (conflict YYYY-MM-DD).age`), or edit a merge.
  - Conflicts in `.age-recipients` are always resolved by hand, never automatically.
  - Abort is always possible, so there is no forced hard reset.
- Triggers: pull to refresh, an auto-sync option on foreground, background refresh with `BGAppRefreshTask` (fetch only, no secrets needed), and the App Intent.

## 7. UI (SwiftUI)

- `NavigationSplitView`: a folder tree or flat list in the sidebar, the entry in the detail column. Compact width collapses to a stack.
- `.searchable` with fuzzy matching on the path, and search scopes ("This folder" / "All").
- Entry view:
  - Masked password with tap-to-reveal (requires auth) and long-press to copy.
  - Fields as rows. URLs are tappable.
  - A TOTP code with a countdown ring (`TimelineView`).
  - "Last modified" from git log, not blame.
- Editor:
  - Generator presets (random or passphrase).
  - Strength meter.
  - "Encrypted to" chips listing the resolved recipients, so the user can see who can read the entry.
- Settings:
  - Identities (SE keys, imported keys)
  - Recipients health check
  - Git remote and credentials
  - Unlock policy
  - Clipboard timeout
  - Field visibility
- Onboarding: create the device key, then clone or open the store, then a recipient health check with instructions.
- Accessibility (Dynamic Type, VoiceOver labels on masked fields) and localization from the start (string catalogs).

## 8. Extensions and system integration

- **AutoFill (`ASCredentialProviderViewController`):**
  - After each sync, bulk-replace the `ASCredentialIdentityStore` with password identities (domain from `url:` or the path, user from `username:` or the file name) and one-time-code identities for entries with OTP.
  - QuickType suggestions show only metadata. Decryption happens on selection, after Face ID.
  - `provideCredentialWithoutUserInteraction` always returns `userInteractionRequired`, because every decrypt needs biometrics. The SE key is accessible to the extension through the shared access group.
  - Matching uses eTLD+1 from a bundled public suffix list, with an exact-host bonus. Results are split into Suggested and All.
  - Text insertion (`prepareInterfaceForUserChoosingTextToInsert`) for arbitrary fields.
  - Passkeys are out of scope for v1. Storing passkeys as age-encrypted entries is a possible later experiment.
- **App Intents:**
  - Sync Store
  - Open Entry (an `AppEntity` over paths)
  - Copy Password / Copy OTP, requiring device authentication (`authenticationPolicy = .requiresLocalDeviceAuthentication`)
  - A Control Center `ControlWidget` for Sync and Search.
- **Share and import:** opening a `.age` file shows a decrypt preview. `otpauth://` QR codes can be added to an entry from the camera.

## 9. Milestones

| # | Deliverable | Exit criteria |
| --- | --- | --- |
| M0 ✅ | Repo skeleton: Xcode project, `PassageKit` package, justfile, CI (macOS runner, `swift test`, build) | CI green on an empty app |
| M1 ✅ | `AgeCrypto`: X25519, X-Wing, scrypt, armor, STREAM, plus the tag and piv-p256 stanzas (pulled forward from M2) | All 147 CCTV vectors pass, `age` CLI interop in both directions including `age -r age1tag…` |
| M2 🟡 | `KeyStore`: SE tagged keys (p256tag, mlkem768p256tag), imported keys, unlock sessions | Encrypt to `age1tagpq` with `age` on a Mac, decrypt on a device |
| M3 🟡 | Read-only app with the Files folder backend: open a store folder, tree, search, entry view, copy, TOTP | Daily use for reading a real passage store from iCloud Drive |
| M4 | `GitSync`: clone/fetch/merge (read-only), HTTPS + SSH Ed25519, known_hosts | Clone a private GitHub repo over SSH |
| M5 | Writing: create, edit, move, delete, multi-recipient encryption, commit/push, conflict UI, re-encrypt | Round trip with desktop `passage` including conflicts |
| M6 | AutoFill extension: bulk identity store, OTP credentials, text insertion | Safari login plus 2FA fill |
| M7 | App Intents, Control Center control, generator presets, recipient health check, polish | — |
| M8 | YubiKey via YubiKit (NFC/USB-C), `piv-p256` stanza (age-plugin-yubikey identities), in both the app and AutoFill | Decrypt with a YubiKey 5 over NFC |
| M9 | Hardening review, privacy manifest, App Store submission (§11) | Approved on the App Store |

M2/M3 status: the code is done and tested on the Mac (`swift test`, including its Secure Enclave). On-device verification is pending the first TestFlight build (checklist below). No iOS Simulator runtime is installed, so the UI has only been compiled, not run.

v1 = M0 through M9. All three of git, Files folder and YubiKey ship in v1.

### On-device checklist (next TestFlight build)

Things `swift test` on the Mac can't cover:

- [ ] Create a device key on the iPhone. The QR code is scannable and Copy/Share work.
- [ ] `age -r <age1tag…> | age -r <age1tagpq…>` on the Mac, open the file via "Decrypt a File": exactly one Face ID prompt, plaintext shown.
- [ ] Unlock policy: "After 1 Minute" doesn't prompt again within the window, "Every Time" does. Backgrounding the app locks.
- [ ] A file not encrypted to any of our keys fails without a Face ID prompt.
- [ ] Cancelling Face ID shows "Authentication was cancelled" and nothing else.
- [ ] Import an `AGE-SECRET-KEY-1…`, decrypt a file for it (one prompt for the wrapping Secure Enclave key).
- [ ] Enroll a new appearance in Face ID: `biometryCurrentSet` keys stop working, with a clear error.
- [ ] Keys survive an app update (keychain access group and App Group are registered correctly).
- [ ] App switcher shows the privacy cover.
- [ ] Open a passage store folder in iCloud Drive, and one from another File Provider (e.g. Working Copy). The folder reopens after an app restart.
- [ ] Entries evicted from iCloud ("Remove Download") download on open.
- [ ] A change made on the Mac shows up without a manual refresh (NSFilePresenter); pull-to-refresh works.
- [ ] Copy password → paste in another app works; it's gone after the timeout and doesn't appear on the Mac via Universal Clipboard.
- [ ] TOTP code matches `oathtool`/another authenticator; the countdown ring advances.
- [ ] Face ID prompt while opening an entry doesn't cause a re-prompt loop.

## 10. Risks and open questions

- **Building libgit2 for iOS** (with SSH and TLS) is the biggest integration cost. If SwiftGitX doesn't fit, the fallback is our own xcframework script. HTTPS-only for v1 is an acceptable reduced scope.
- ~~**CryptoKit X-Wing vs. age's `mlkem768x25519`**~~: resolved. CryptoKit's `XWingMLKEM768X25519` with `seedRepresentation` passes all the hybrid CCTV vectors and round-trips with `age -pq`.
- **Post-quantum and classic recipients can't be mixed in one file** (age refuses). A store whose `.age-recipients` holds desktop X25519 keys therefore needs the device's `age1tag` recipient, not `age1tagpq`. The SE identity always has both a P-256 and an ML-KEM key, so it can decrypt either stanza type. Onboarding offers whichever recipient matches the store's existing recipients.
- **SE-only users lose everything if they lose the device.** This is mitigated by the mandatory second recipient (§4).
- **Plugin recipients** (other than `se`, `tag`, `yubikey`) can't run on iOS. Those folders are read-only, which needs clear UX.
- **YubiKey in AutoFill**: NFC sessions work in extensions, but the UI is tight. This needs a prototype early in M8.

## 11. Decisions

- **Distribution: App Store.** Consequences:
  - Export compliance: the app only uses standard algorithms (age = X25519/ML-KEM/ChaCha20-Poly1305), so it qualifies for the exemption. Set `ITSAppUsesNonExemptEncryption = NO` once this is confirmed.
  - Review notes must provide a demo store and a demo identity, because reviewers can't set up git or a desktop key. Ship a "Try with demo store" button in onboarding that generates a local store.
  - App group, keychain access group and AutoFill capabilities on the paid team `D7DW22G9T5`. Bundle ID `de.nerdworks.passage`; extensions use `de.nerdworks.passage.<name>`, the App Group is `group.de.nerdworks.passage`, and the keychain access group is `D7DW22G9T5.de.nerdworks.passage.shared`.
  - Licensing: adapted code from age-plugin-se (MIT) and the CCTV test vectors (CC0) need acknowledgements. libgit2 is GPLv2 with a linking exception, which is App Store compatible. libssh2 is BSD.
- **Storage: both git and Files folder ship in v1** (§5).
- **YubiKey ships in v1** (M8).
- **Device testing goes through TestFlight.** There's no iPhone for local runs, so on-device checks (Secure Enclave, Face ID, AutoFill, NFC) are batched into TestFlight builds. Until then, Secure Enclave code is tested with `swift test` on an Apple-silicon Mac, which has a Secure Enclave too.
