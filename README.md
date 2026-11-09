# Passage for iOS

An iOS client for [passage](https://github.com/FiloSottile/passage), the
[pass](https://www.passwordstore.org/) layout with [age](https://age-encryption.org) encryption.
Its keys live in the Secure Enclave, and it syncs through git or a Files-app folder.

See [PLAN.md](PLAN.md) for the design and milestones.

## Layout

- `PassageKit/`: Swift package holding all non-UI logic, testable with `swift test` on macOS.
  - `AgeCrypto`: age v1 in pure Swift on CryptoKit. Supports X25519, post-quantum
    MLKEM768-X25519, scrypt (decrypt only), p256tag / mlkem768p256tag (hardware keys),
    piv-p256 (`age1se` / `age1yubikey` recipients), and ASCII armor. Tested against all
    [C2SP/CCTV](https://github.com/C2SP/CCTV/tree/main/age) vectors and the `age` CLI.
  - `KeyStore`: Secure Enclave identities, imported keys, unlock sessions.
  - `PassStore`: entry parser, OTP, store scanning and search, Files-folder access.
  - `GitSync`: libgit2 (vendored upstream, built with SwiftPM): clone, fetch, fast-forward pull.
- `App/`, `AutoFill/`, `Controls/`, `Shared/`: the SwiftUI app and its extensions.
- `docs/`: the website (GitHub Pages): privacy policy and support.
- `AppStore/`: App Store metadata and review notes.

## Development

Requires Xcode 27 (iOS 26 SDK or later). `age` 1.3+ on `PATH` enables the interop tests.
libgit2 is a submodule pinned to upstream v1.9.2: clone with `--recursive` or run
`git submodule update --init`.

    just test    # package tests
    just build   # iOS app, simulator, unsigned

## License

MIT, see [LICENSE](LICENSE). libgit2 is GPLv2 with a linking exception.

## Acknowledgements

- The HPKE and tag code in `AgeCrypto/Tag.swift` follows
  [age-plugin-se](https://github.com/remko/age-plugin-se) (MIT, © Remko Tronçon).
- Test vectors from [C2SP/CCTV](https://github.com/C2SP/CCTV).
- Passphrase words from the [EFF large wordlist](https://www.eff.org/dice) (CC BY 3.0 US).
