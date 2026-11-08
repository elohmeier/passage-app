import AuthenticationServices
import KeyStore
import PassStore
import SwiftUI

/// The AutoFill extension. It reads the store the app already has (git clone or Files folder)
/// and never syncs; decryption asks for Face ID inside the extension.
final class CredentialProviderViewController: ASCredentialProviderViewController {
    private let model = AppModel.live()
    private let store: StoreModel = {
        let store = StoreModel(
            defaults: AppModel.sharedDefaults,
            secrets: KeychainSecretStore(service: AppConfig.keychainService + ".git", accessGroup: AppConfig.keychainAccessGroup))
        store.updatesAutoFill = false
        return store
    }()

    // MARK: Requests

    override func prepareCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier]) {
        show(.password, services: serviceIdentifiers)
    }

    override func prepareOneTimeCodeCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier]) {
        show(.oneTimeCode, services: serviceIdentifiers)
    }

    override func prepareInterfaceForUserChoosingTextToInsert() {
        show(.text, services: [])
    }

    /// Every credential needs Face ID, so QuickType selections always come back with UI.
    override func provideCredentialWithoutUserInteraction(for credentialRequest: any ASCredentialRequest) {
        extensionContext.cancelRequest(withError: ASExtensionError(.userInteractionRequired))
    }

    /// A QuickType suggestion was picked: decrypt that entry directly.
    override func prepareInterfaceToProvideCredential(for credentialRequest: any ASCredentialRequest) {
        let kind: PickerKind = credentialRequest.type == .oneTimeCode ? .oneTimeCode : .password
        guard let path = credentialRequest.credentialIdentity.recordIdentifier else {
            show(kind, services: [credentialRequest.credentialIdentity.serviceIdentifier])
            return
        }
        show(kind, services: [credentialRequest.credentialIdentity.serviceIdentifier], autoSelect: EntryPath(path))
    }

    // MARK: UI

    private func show(_ kind: PickerKind, services: [ASCredentialServiceIdentifier], autoSelect: EntryPath? = nil) {
        store.restore()
        let picker = CredentialPickerView(
            kind: kind, services: services.map(\.identifier), autoSelect: autoSelect,
            cancel: { [weak self] in
                self?.extensionContext.cancelRequest(withError: ASExtensionError(.userCanceled))
            },
            complete: { [weak self] completion in
                self?.complete(completion)
            })
            .environment(model)
            .environment(store)
        let host = UIHostingController(rootView: picker)
        for child in children {
            child.view.removeFromSuperview()
            child.removeFromParent()
        }
        addChild(host)
        host.view.frame = view.bounds
        host.view.autoresizingMask = [.flexibleWidth, .flexibleHeight]
        view.addSubview(host.view)
        host.didMove(toParent: self)
    }

    private func complete(_ completion: PickerCompletion) {
        switch completion {
        case .password(let user, let password):
            extensionContext.completeRequest(withSelectedCredential: ASPasswordCredential(user: user, password: password))
        case .oneTimeCode(let code):
            extensionContext.completeOneTimeCodeRequest(using: ASOneTimeCodeCredential(code: code))
        case .text(let text):
            extensionContext.completeRequest(withTextToInsert: text)
        }
    }
}
