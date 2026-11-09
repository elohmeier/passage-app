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

    /// A site asks for a passkey (and possibly passwords): offer our passkeys for its RP ID.
    override func prepareCredentialList(
        for serviceIdentifiers: [ASCredentialServiceIdentifier], requestParameters: ASPasskeyCredentialRequestParameters
    ) {
        let request = PasskeyRequest(
            relyingParty: requestParameters.relyingPartyIdentifier, clientDataHash: requestParameters.clientDataHash,
            allowedCredentials: requestParameters.allowedCredentials)
        show(.passkey(request), services: serviceIdentifiers)
    }

    /// A site wants to create a passkey: generate it, save it to the store (commit and push), and
    /// return the attestation.
    override func prepareInterface(forPasskeyRegistration registrationRequest: any ASCredentialRequest) {
        guard let request = registrationRequest as? ASPasskeyCredentialRequest,
            let identity = request.credentialIdentity as? ASPasskeyCredentialIdentity
        else {
            extensionContext.cancelRequest(withError: ASExtensionError(.failed))
            return
        }
        guard request.supportedAlgorithms.contains(ASCOSEAlgorithmIdentifier.ES256) else {
            extensionContext.cancelRequest(withError: ASExtensionError(.failed))
            return
        }
        store.restore()
        // The site already has one of our passkeys for this account.
        let excluded = Set((request.excludedCredentials ?? []).map(\.credentialID))
        let ours = AutoFillMatcher.passkeys(AutoFillStore.load().items, relyingParty: identity.relyingPartyIdentifier)
        if ours.contains(where: { excluded.contains($0.passkey!.credentialID) }) {
            extensionContext.cancelRequest(withError: ASExtensionError(.matchedExcludedCredential))
            return
        }
        let registration = PasskeyRegistrationView(
            relyingParty: identity.relyingPartyIdentifier, userName: identity.userName, userHandle: identity.userHandle,
            cancel: { [weak self] in self?.extensionContext.cancelRequest(withError: ASExtensionError(.userCanceled)) },
            complete: { [weak self] passkey in
                self?.extensionContext.completeRegistrationRequest(using: ASPasskeyRegistrationCredential(
                    relyingParty: passkey.relyingParty, clientDataHash: request.clientDataHash, credentialID: passkey.credentialID,
                    attestationObject: passkey.attestationObject()))
            })
            .environment(model)
            .environment(store)
        host(registration)
    }

    override func prepareOneTimeCodeCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier]) {
        show(.oneTimeCode, services: serviceIdentifiers)
    }

    override func prepareInterfaceForUserChoosingTextToInsert() {
        show(.text, services: [])
    }

    /// A credential picked in QuickType or the system passkey sheet. Serve it directly: the
    /// system Face ID prompt is allowed here (it isn't extension UI). Passkey sign-ins in
    /// particular aren't retried with UI if this answers "user interaction required"; the
    /// website just gets an error. So that answer is only for entries that need our UI, e.g.
    /// a YubiKey tap.
    override func provideCredentialWithoutUserInteraction(for credentialRequest: any ASCredentialRequest) {
        guard let path = credentialRequest.credentialIdentity.recordIdentifier else {
            extensionContext.cancelRequest(withError: ASExtensionError(.credentialIdentityNotFound))
            return
        }
        Task { @MainActor in
            store.restore()
            let entry = EntryPath(path)
            let content: Entry
            do {
                let plaintext = try await model.decrypt(store.read(entry))
                content = Entry(String(decoding: plaintext, as: UTF8.self))
            } catch KeyStoreError.cancelled {
                extensionContext.cancelRequest(withError: ASExtensionError(.userCanceled))
                return
            } catch {
                extensionContext.cancelRequest(withError: ASExtensionError(.userInteractionRequired))
                return
            }
            await AutoFillStore.learn(entry, from: content)

            if let request = credentialRequest as? ASPasskeyCredentialRequest {
                guard let passkey = Passkey(entry: content),
                    let (authenticatorData, signature) = try? passkey.assertion(clientDataHash: request.clientDataHash)
                else {
                    extensionContext.cancelRequest(withError: ASExtensionError(.credentialIdentityNotFound))
                    return
                }
                complete(.passkey(passkey, authenticatorData: authenticatorData, signature: signature, clientDataHash: request.clientDataHash))
            } else if credentialRequest.type == .oneTimeCode {
                guard let otp = content.otp else {
                    extensionContext.cancelRequest(withError: ASExtensionError(.credentialIdentityNotFound))
                    return
                }
                complete(.oneTimeCode(otp.code()))
            } else {
                guard let password = content.password, !password.isEmpty else {
                    extensionContext.cancelRequest(withError: ASExtensionError(.credentialIdentityNotFound))
                    return
                }
                complete(.password(user: content.username ?? entry.name, password: password))
            }
        }
    }

    /// A QuickType suggestion was picked: decrypt that entry directly.
    override func prepareInterfaceToProvideCredential(for credentialRequest: any ASCredentialRequest) {
        if let request = credentialRequest as? ASPasskeyCredentialRequest,
            let identity = request.credentialIdentity as? ASPasskeyCredentialIdentity
        {
            let passkey = PasskeyRequest(
                relyingParty: identity.relyingPartyIdentifier, clientDataHash: request.clientDataHash,
                allowedCredentials: [identity.credentialID])
            show(.passkey(passkey), services: [], autoSelect: identity.recordIdentifier.map(EntryPath.init))
            return
        }
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
        host(picker)
    }

    private func host(_ root: some View) {
        let host = UIHostingController(rootView: root)
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
        case .passkey(let passkey, let authenticatorData, let signature, let clientDataHash):
            extensionContext.completeAssertionRequest(using: ASPasskeyAssertionCredential(
                userHandle: passkey.userHandle, relyingParty: passkey.relyingParty, signature: signature,
                clientDataHash: clientDataHash, authenticatorData: authenticatorData, credentialID: passkey.credentialID))
        }
    }
}
