import Foundation
import SwiftUI

/// Drives the first-launch flow: identity creation → backup passphrase →
/// first contact. There is no account server; each step is explicit about that.
@MainActor
final class OnboardingViewModel: ObservableObject {
    enum Step: Int, CaseIterable {
        case welcome
        case identity
        case backup
        case addContact

        var title: String {
            switch self {
            case .welcome: return "Welcome to Aegis"
            case .identity: return "Your identity"
            case .backup: return "Back up your identity"
            case .addContact: return "Add your first contact"
            }
        }
    }

    @Published var step: Step = .welcome
    @Published var displayName = ""
    @Published var isGenerating = false
    @Published var generationError: String?
    @Published var createdIdentity: LocalIdentity?

    // Backup
    @Published var passphrase = ""
    @Published var confirmPassphrase = ""
    @Published var isBackingUp = false
    @Published var backupError: String?
    @Published var backupComplete = false

    // First contact
    @Published var inviteInput = ""
    @Published var isAddingContact = false
    @Published var addContactError: String?
    @Published var addedContactName: String?

    private let appState: AppState

    init(appState: AppState) {
        self.appState = appState
    }

    var passphraseStrength: PassphraseStrength {
        appState.crypto.backupPassphraseStrength(passphrase)
    }

    var backupReady: Bool {
        !passphrase.isEmpty && passphrase == confirmPassphrase
            && passphraseStrength != .weak
    }

    func next() {
        Haptics.selection()
        if let next = Step(rawValue: step.rawValue + 1) {
            step = next
        }
    }

    func back() {
        if let prev = Step(rawValue: step.rawValue - 1) {
            step = prev
        }
    }

    // MARK: - Identity

    func generateIdentity() async {
        let name = displayName.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !name.isEmpty else {
            generationError = "Enter a display name — it's how contacts will recognize you."
            return
        }
        isGenerating = true
        generationError = nil
        defer { isGenerating = false }
        // Small delay so the generation animation reads as deliberate, not instant.
        try? await Task.sleep(nanoseconds: 600_000_000)
        do {
            createdIdentity = try await appState.crypto.createIdentity(displayName: name)
            Haptics.notification(.success)
        } catch {
            generationError = error.localizedDescription
            Haptics.notification(.error)
        }
    }

    // MARK: - Backup

    func createBackup() async {
        guard backupReady else { return }
        isBackingUp = true
        backupError = nil
        defer { isBackingUp = false }
        do {
            _ = try await appState.crypto.exportEncryptedBackup(passphrase: passphrase)
            backupComplete = true
            Haptics.notification(.success)
        } catch {
            backupError = error.localizedDescription
            Haptics.notification(.error)
        }
    }

    // MARK: - First contact

    func addContactFromCode() async {
        let code = inviteInput.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !code.isEmpty else {
            addContactError = "Paste an invite code or scan a QR code."
            return
        }
        isAddingContact = true
        addContactError = nil
        defer { isAddingContact = false }
        do {
            let remote = try await appState.crypto.remoteIdentity(fromInvitePayload: code)
            let contact = Contact(
                displayName: remote.displayName ?? "New contact",
                identityKey: remote.publicKey
            )
            try await appState.store.saveContact(contact)
            // Open a DM immediately so the empty state never greets them.
            let conversation = Conversation(
                kind: .direct,
                title: contact.displayName,
                memberIDs: [contact.id]
            )
            try await appState.store.saveConversation(conversation)
            addedContactName = contact.displayName
            inviteInput = ""
            Haptics.notification(.success)
        } catch {
            addContactError = error.localizedDescription
            Haptics.notification(.error)
        }
    }

    // MARK: - Finish

    func finish() {
        guard let identity = createdIdentity else { return }
        appState.completeOnboarding(identity: identity)
    }
}
