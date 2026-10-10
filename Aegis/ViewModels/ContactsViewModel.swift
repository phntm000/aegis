import Foundation

/// The address book: verified contacts, blocked list, safety-number checks.
/// Adding is always explicit (QR / invite code) — there is no discovery.
@MainActor
final class ContactsViewModel: ObservableObject {
    @Published private(set) var contacts: [Contact] = []
    @Published var searchText = ""
    @Published private(set) var isLoading = true
    @Published var error: String?
    @Published var showingBlocked = false

    private let appState: AppState

    init(appState: AppState) {
        self.appState = appState
    }

    var visible: [Contact] {
        let list = contacts.filter { !$0.isBlocked }
        return filtered(list)
    }

    var blocked: [Contact] {
        filtered(contacts.filter { $0.isBlocked })
    }

    var isEmpty: Bool { contacts.isEmpty }

    private func filtered(_ list: [Contact]) -> [Contact] {
        let query = searchText.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !query.isEmpty else { return list }
        return list.filter { $0.displayName.lowercased().contains(query) }
    }

    func load() async {
        isLoading = true
        error = nil
        defer { isLoading = false }
        do {
            contacts = try await appState.store.fetchContacts()
        } catch {
            self.error = error.localizedDescription
        }
    }

    func contact(id: UUID) -> Contact? {
        contacts.first { $0.id == id }
    }

    // MARK: - Adding

    /// Parse an invite code / QR payload and create the contact + DM.
    func addFromInviteCode(_ code: String, displayName: String?) async throws -> Contact {
        let remote = try await appState.crypto.remoteIdentity(fromInvitePayload: code)
        if contacts.contains(where: { $0.identityKey == remote.publicKey }) {
            throw ContactsError.alreadyAdded
        }
        let contact = Contact(
            displayName: displayName?.trimmingCharacters(in: .whitespacesAndNewlines)
                .nilIfEmpty ?? remote.displayName ?? "New contact",
            identityKey: remote.publicKey
        )
        try await appState.store.saveContact(contact)
        let conversation = Conversation(kind: .direct, title: contact.displayName, memberIDs: [contact.id])
        try await appState.store.saveConversation(conversation)
        contacts.append(contact)
        contacts.sort { $0.displayName < $1.displayName }
        Haptics.notification(.success)
        return contact
    }

    func rename(_ contact: Contact, to name: String) async {
        let trimmed = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return }
        var updated = contact
        updated.displayName = trimmed
        do {
            try await appState.store.saveContact(updated)
            replace(updated)
        } catch {
            self.error = error.localizedDescription
        }
    }

    func delete(_ contact: Contact) async {
        do {
            try await appState.store.deleteContact(id: contact.id)
            contacts.removeAll { $0.id == contact.id }
            Haptics.impact(.medium)
        } catch {
            self.error = error.localizedDescription
        }
    }

    // MARK: - Blocking

    func toggleBlock(_ contact: Contact) async {
        var updated = contact
        updated.isBlocked.toggle()
        do {
            try await appState.store.saveContact(updated)
            replace(updated)
            Haptics.impact(.medium)
        } catch {
            self.error = error.localizedDescription
        }
    }

    // MARK: - Verification

    func fingerprint(for contact: Contact) -> String {
        appState.crypto.fingerprint(of: contact.identityKey)
    }

    func safetyNumber(for contact: Contact) -> String {
        guard let me = appState.identity else { return "" }
        return appState.crypto.safetyNumber(local: me.publicKey, remote: contact.identityKey)
    }

    /// The user compared safety numbers out-of-band and they match.
    func markVerified(_ contact: Contact) async {
        var updated = contact
        updated.verification = .verified
        do {
            try await appState.store.saveContact(updated)
            replace(updated)
            Haptics.notification(.success)
        } catch {
            self.error = error.localizedDescription
        }
    }

    /// The user verified the NEW key after an identity change: adopt it as
    /// the contact's key and mark verified. The old key is superseded.
    /// Callers clear the conversation's pending identity-change state after.
    func confirmIdentityChange(_ contact: Contact, newIdentityKey: Data) async {
        var updated = contact
        updated.identityKey = newIdentityKey
        updated.verification = .verified
        do {
            try await appState.store.saveContact(updated)
            replace(updated)
            Haptics.notification(.success)
        } catch {
            self.error = error.localizedDescription
        }
    }

    /// The key changed: surface the warning until the user re-verifies.
    func flagIdentityChanged(_ contact: Contact) async {
        var updated = contact
        updated.verification = .identityChanged
        try? await appState.store.saveContact(updated)
        replace(updated)
    }

    // MARK: - Private

    private func replace(_ contact: Contact) {
        if let idx = contacts.firstIndex(where: { $0.id == contact.id }) {
            contacts[idx] = contact
        }
    }
}

enum ContactsError: Error, LocalizedError {
    case alreadyAdded

    var errorDescription: String? {
        "That contact is already in your list."
    }
}

private extension String {
    var nilIfEmpty: String? { isEmpty ? nil : self }
}
