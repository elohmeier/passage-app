import AppIntents
import KeyStore
import PassStore
import SwiftUI

/// Where the app should navigate when an intent opens it.
enum PendingRoute: Equatable {
    case entry(EntryPath)
    case search

    /// Hands a route to the app across processes: an intent run by the Controls extension
    /// can't reach the app's models, so it leaves the route in the App Group and the app takes
    /// it when it becomes active. (iOS 27's allowedExecutionTargets would make this moot.)
    @MainActor static func post(_ route: PendingRoute) {
        let value = switch route {
        case .search: "search"
        case .entry(let entry): "entry:" + entry.path
        }
        AppModel.sharedDefaults.set([value, Date.now.timeIntervalSince1970] as [Any], forKey: "pendingRoute")
    }

    /// The posted route, if any and recent; clears it.
    @MainActor static func take() -> PendingRoute? {
        let defaults = AppModel.sharedDefaults
        guard let stored = defaults.array(forKey: "pendingRoute"), let value = stored.first as? String,
            let time = stored.last as? Double, Date.now.timeIntervalSince1970 - time < 60
        else { return nil }
        defaults.removeObject(forKey: "pendingRoute")
        if value == "search" { return .search }
        if value.hasPrefix("entry:") { return .entry(EntryPath(String(value.dropFirst(6)))) }
        return nil
    }
}

// Intents run in the app and the Controls extension, not in AutoFill.
#if !AUTOFILL_EXTENSION

/// The models shared by the app's UI and its intents, so an intent run in the app process
/// sees the same unlock session and store as the UI.
@MainActor
enum PassageEnvironment {
    static let model = AppModel.live()
    static let store = StoreModel(
        defaults: AppModel.sharedDefaults,
        secrets: KeychainSecretStore(service: AppConfig.keychainService + ".git", accessGroup: AppConfig.keychainAccessGroup))

    /// The store, opened and scanned (intents can run before any UI has appeared).
    static func loadedStore() async throws -> StoreModel {
        store.restore()
        guard store.store != nil else { throw IntentError.noStore }
        if store.snapshot.entries.isEmpty { await store.refresh() }
        return store
    }
}

enum IntentError: Error, CustomLocalizedStringResourceConvertible {
    case noStore
    case noPassword
    case noOneTimeCode

    var localizedStringResource: LocalizedStringResource {
        switch self {
        case .noStore: "Set up a password store in Passage first."
        case .noPassword: "This entry has no password."
        case .noOneTimeCode: "This entry has no one-time code."
        }
    }
}


// MARK: Entities

struct PasswordEntity: AppEntity {
    static let typeDisplayRepresentation: TypeDisplayRepresentation = "Password"
    static let defaultQuery = PasswordQuery()

    let id: String

    var displayRepresentation: DisplayRepresentation {
        let entry = EntryPath(id)
        return DisplayRepresentation(
            title: "\(entry.name)", subtitle: entry.folder.isEmpty ? nil : "\(entry.folder)", image: .init(systemName: "key.horizontal"))
    }
}

struct PasswordQuery: EntityStringQuery {
    @MainActor
    func entities(for identifiers: [String]) async throws -> [PasswordEntity] {
        let store = try await PassageEnvironment.loadedStore()
        let known = Set(store.snapshot.entries.map(\.path))
        return identifiers.filter(known.contains).map(PasswordEntity.init)
    }

    @MainActor
    func entities(matching string: String) async throws -> [PasswordEntity] {
        try await PassageEnvironment.loadedStore().snapshot.search(string).prefix(50).map { PasswordEntity(id: $0.path) }
    }

    @MainActor
    func suggestedEntities() async throws -> [PasswordEntity] {
        try await PassageEnvironment.loadedStore().snapshot.entries.prefix(50).map { PasswordEntity(id: $0.path) }
    }
}

// MARK: Intents

struct SyncPasswordsIntent: AppIntent {
    static let title: LocalizedStringResource = "Sync Passwords"
    static let description = IntentDescription("Pulls changes from the store's git remote and pushes local changes.")
    static let supportedModes: IntentModes = .background

    @MainActor
    func perform() async throws -> some IntentResult & ProvidesDialog {
        let store = try await PassageEnvironment.loadedStore()
        guard store.gitConfig != nil else { return .result(dialog: "This store isn't synced with git.") }
        await store.sync(.user)
        if let problem = store.syncProblem { return .result(dialog: "Couldn't sync: \(problem)") }
        return .result(dialog: "Passwords are up to date.")
    }
}

/// Copies a password. Needs Face ID, so it runs with the app in front.
struct CopyPasswordIntent: AppIntent {
    static let title: LocalizedStringResource = "Copy Password"
    static let description = IntentDescription("Copies a password to the clipboard. It's cleared automatically.")
    static let supportedModes: IntentModes = .foreground(.immediate)
    static let authenticationPolicy: IntentAuthenticationPolicy = .requiresLocalDeviceAuthentication

    @Parameter(title: "Password") var entry: PasswordEntity

    @MainActor
    func perform() async throws -> some IntentResult & ProvidesDialog {
        let content = try await decrypt(entry)
        guard let password = content.password else { throw IntentError.noPassword }
        let seconds = PassageEnvironment.model.clipboardSeconds
        SecurePasteboard.copy(password, expiresAfter: seconds)
        return .result(dialog: "Copied. The clipboard clears in \(seconds) seconds.")
    }
}

struct CopyOneTimeCodeIntent: AppIntent {
    static let title: LocalizedStringResource = "Copy One-Time Code"
    static let description = IntentDescription("Copies the current one-time code of an entry.")
    static let supportedModes: IntentModes = .foreground(.immediate)
    static let authenticationPolicy: IntentAuthenticationPolicy = .requiresLocalDeviceAuthentication

    @Parameter(title: "Password") var entry: PasswordEntity

    @MainActor
    func perform() async throws -> some IntentResult & ProvidesDialog & ReturnsValue<String> {
        let content = try await decrypt(entry)
        guard let otp = content.otp else { throw IntentError.noOneTimeCode }
        let code = otp.code()
        SecurePasteboard.copy(code, expiresAfter: PassageEnvironment.model.clipboardSeconds)
        return .result(value: code, dialog: "Copied \(code).")
    }
}

struct OpenPasswordIntent: OpenIntent {
    static let title: LocalizedStringResource = "Open Password"
    @Parameter(title: "Password") var target: PasswordEntity

    @MainActor
    func perform() async throws -> some IntentResult {
        route(.entry(EntryPath(target.id)))
        return .result()
    }
}

struct SearchPasswordsIntent: AppIntent {
    static let title: LocalizedStringResource = "Search Passwords"
    static let supportedModes: IntentModes = .foreground(.immediate)

    @MainActor
    func perform() async throws -> some IntentResult {
        route(.search)
        return .result()
    }
}

/// Navigates the app: directly when running in the app, via the App Group otherwise.
@MainActor
private func route(_ route: PendingRoute) {
    #if CONTROLS_EXTENSION
        PendingRoute.post(route)
    #else
        PassageEnvironment.model.pendingRoute = route
    #endif
}

@MainActor
private func decrypt(_ entity: PasswordEntity) async throws -> Entry {
    let store = try await PassageEnvironment.loadedStore()
    let plaintext = try await PassageEnvironment.model.decrypt(store.read(EntryPath(entity.id)))
    return Entry(String(decoding: plaintext, as: UTF8.self))
}

// The App Shortcuts provider belongs to the app only.
#if !CONTROLS_EXTENSION
struct PassageShortcuts: AppShortcutsProvider {
    static var appShortcuts: [AppShortcut] {
        AppShortcut(
            intent: SearchPasswordsIntent(), phrases: ["Search \(.applicationName)", "Find a password in \(.applicationName)"],
            shortTitle: "Search", systemImageName: "magnifyingglass")
        AppShortcut(
            intent: CopyPasswordIntent(), phrases: ["Copy a password from \(.applicationName)"], shortTitle: "Copy Password",
            systemImageName: "doc.on.doc")
        AppShortcut(
            intent: CopyOneTimeCodeIntent(), phrases: ["Copy a code from \(.applicationName)"], shortTitle: "Copy Code",
            systemImageName: "number")
        AppShortcut(
            intent: SyncPasswordsIntent(), phrases: ["Sync \(.applicationName)"], shortTitle: "Sync",
            systemImageName: "arrow.triangle.2.circlepath")
    }
}
#endif

#endif
