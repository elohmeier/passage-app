import Foundation
import LocalAuthentication
import Synchronization

/// How long one Face ID / Touch ID authentication keeps keys usable.
public enum UnlockPolicy: Codable, Hashable, Sendable {
    /// Authenticate for every decryption.
    case everyTime
    /// Reuse an authentication for this many seconds while the app stays in the foreground.
    case reuse(seconds: Int)
    /// Reuse until the app goes to the background or the device locks.
    case untilBackground
}

/// Evaluates a LocalAuthentication policy. Abstracted so tests don't need a human.
public protocol Authenticator: Sendable {
    func evaluate(_ context: LAContext, policy: LAPolicy, reason: String) async throws(KeyStoreError)
}

public struct LocalAuthenticator: Authenticator {
    public init() {}

    public func evaluate(_ context: LAContext, policy: LAPolicy, reason: String) async throws(KeyStoreError) {
        do {
            _ = try await context.evaluatePolicy(policy, localizedReason: reason)
        } catch let error as LAError {
            switch error.code {
            case .userCancel, .appCancel, .systemCancel: throw .cancelled
            case .notInteractive: throw .notInteractive
            default: throw .authenticationFailed(error.localizedDescription)
            }
        } catch {
            throw .authenticationFailed(error.localizedDescription)
        }
    }
}

/// Owns the `LAContext` passed to key operations and decides when to authenticate again.
///
/// The app asks for a context before decrypting, then passes it to `IdentityStore.unlock`. A
/// context that has been evaluated satisfies the Secure Enclave and keychain access control of
/// keys with a compatible protection, so the user sees one prompt per session.
public final class UnlockSessionManager: Sendable {
    private struct State: @unchecked Sendable {
        // LAContext is thread-safe but not marked Sendable.
        var context: LAContext?
        var policy: LAPolicy?
        var authenticatedAt: Date?
    }

    private let state = Mutex(State())
    private let _policy: Mutex<UnlockPolicy>
    private let authenticator: any Authenticator
    private let now: @Sendable () -> Date

    public init(
        policy: UnlockPolicy, authenticator: any Authenticator = LocalAuthenticator(), now: @escaping @Sendable () -> Date = { .now }
    ) {
        _policy = Mutex(policy)
        self.authenticator = authenticator
        self.now = now
    }

    public var policy: UnlockPolicy {
        get { _policy.withLock { $0 } }
        set {
            _policy.withLock { $0 = newValue }
            lock()
        }
    }

    /// True while a previous authentication can still be reused.
    public var isUnlocked: Bool {
        state.withLock { current(in: $0) != nil }
    }

    /// Returns an authenticated context for keys with the given protections, prompting if
    /// needed. Returns nil if none of them require authentication.
    public func context(for protections: some Sequence<KeyProtection>, reason: String) async throws(KeyStoreError) -> LAContext? {
        // Biometry-only keys need a biometric evaluation; a passcode one wouldn't satisfy them.
        let policies = Set(protections.compactMap(\.policy))
        guard !policies.isEmpty else { return nil }
        let policy: LAPolicy = policies.contains(.deviceOwnerAuthenticationWithBiometrics)
            ? .deviceOwnerAuthenticationWithBiometrics : .deviceOwnerAuthentication

        if let reusable = state.withLock({ s -> State? in
            guard let ctx = current(in: s), s.policy == policy || s.policy == .deviceOwnerAuthenticationWithBiometrics else { return nil }
            return State(context: ctx)
        }) {
            return reusable.context
        }

        let context = LAContext()
        context.touchIDAuthenticationAllowableReuseDuration = 0
        try await authenticator.evaluate(context, policy: policy, reason: reason)
        if self.policy != .everyTime {
            let fresh = State(context: context, policy: policy, authenticatedAt: now())
            let old = state.withLock { s -> State in
                let old = s
                s = fresh
                return old
            }
            old.context?.invalidate()
        }
        return context
    }

    /// Forgets the current authentication. Call when the app moves to the background.
    public func lock() {
        let old = state.withLock { s -> State in
            let old = s
            s = State()
            return old
        }
        old.context?.invalidate()
    }

    private func current(in s: State) -> LAContext? {
        guard let ctx = s.context, let at = s.authenticatedAt else { return nil }
        switch policy {
        case .everyTime: return nil
        case .reuse(let seconds): return now().timeIntervalSince(at) < Double(seconds) ? ctx : nil
        case .untilBackground: return ctx
        }
    }
}
