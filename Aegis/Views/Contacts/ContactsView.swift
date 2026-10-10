import SwiftUI

/// The address book. Every row shows the verification shield; tapping opens
/// detail with rename, safety-number verification, calls, block, and delete.
struct ContactsView: View {
    @StateObject private var viewModel: ContactsViewModel
    @EnvironmentObject private var appState: AppState

    @State private var showingAddContact = false
    @State private var selectedContact: Contact?
    @State private var navigationPath = NavigationPath()

    init(appState: AppState) {
        _viewModel = StateObject(wrappedValue: ContactsViewModel(appState: appState))
    }

    var body: some View {
        NavigationStack(path: $navigationPath) {
            Group {
                if viewModel.isLoading {
                    LoadingOverlayView(label: "Loading contacts…")
                } else if viewModel.isEmpty {
                    EmptyStateView(
                        icon: "person.2",
                        title: "No contacts yet",
                        message: "Add people with a QR code or invite code. No one can find you by searching — that's intentional.",
                        actionTitle: "Add contact",
                        action: { showingAddContact = true }
                    )
                } else {
                    contactList
                }
            }
            .background(AegisColors.background.ignoresSafeArea())
            .navigationTitle("Contacts")
            .navigationBarTitleDisplayMode(.large)
            .searchable(text: $viewModel.searchText, prompt: "Search contacts")
            .toolbar {
                ToolbarItem(placement: .primaryAction) {
                    Button {
                        showingAddContact = true
                    } label: {
                        Image(systemName: "person.badge.plus")
                            .accessibilityLabel("Add contact")
                    }
                }
            }
            .sheet(isPresented: $showingAddContact) {
                AddContactView(appState: appState) { _ in
                    Task { @MainActor in await viewModel.load() }
                }
            }
            .sheet(item: $selectedContact) { contact in
                ContactDetailView(contact: contact, viewModel: viewModel)
            }
            .navigationDestination(for: BlockedListDestination.self) { _ in
                BlockedListView(viewModel: viewModel)
            }
            .onAppear {
                Task { @MainActor in
                    await viewModel.load()
                }
            }
            .refreshable { @MainActor in
                await viewModel.load()
            }
        }
    }

    private var contactList: some View {
        List {
            if viewModel.visible.isEmpty && !viewModel.searchText.isEmpty {
                EmptyStateView(
                    icon: "magnifyingglass",
                    title: "No results",
                    message: "No contacts match \"\(viewModel.searchText)\"."
                )
            } else {
                Section {
                    ForEach(viewModel.visible) { contact in
                        Button {
                            selectedContact = contact
                        } label: {
                            ContactRowView(contact: contact)
                        }
                        .accessibilityLabel("\(contact.displayName), \(verificationText(contact.verification))")
                    }
                }

                if !viewModel.blocked.isEmpty {
                    Section {
                        NavigationLink(value: BlockedListDestination()) {
                            Label("Blocked", systemImage: "slash.circle")
                                .badge(viewModel.blocked.count)
                        }
                    }
                }
            }
        }
        .listStyle(.insetGrouped)
        .scrollContentBackground(.hidden)
    }

    private func verificationText(_ state: VerificationState) -> String {
        switch state {
        case .unverified: return "not verified"
        case .verified: return "verified"
        case .identityChanged: return "safety number changed"
        }
    }
}

private struct BlockedListDestination: Hashable {}

struct ContactRowView: View {
    let contact: Contact

    var body: some View {
        HStack(spacing: AegisLayout.m) {
            AvatarView(displayName: contact.displayName, hue: contact.avatarHue, size: AegisLayout.avatarM)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 2) {
                Text(contact.displayName)
                    .font(AegisType.body)
                    .foregroundStyle(AegisColors.textPrimary)
                if let lastSeen = contact.lastSeenAt {
                    Text("Last seen \(Formatters.chatListTimestamp(lastSeen))")
                        .font(AegisType.caption)
                        .foregroundStyle(AegisColors.textTertiary)
                }
            }
            Spacer()
            VerificationShieldView(state: contact.verification)
        }
        .padding(.vertical, AegisLayout.xs)
    }
}

/// Detail sheet for one contact: rename, verify, call, block, delete.
struct ContactDetailView: View {
    let contact: Contact
    @ObservedObject var viewModel: ContactsViewModel
    @EnvironmentObject private var appState: AppState
    @Environment(\.dismiss) private var dismiss

    @State private var showingSafetyNumber = false
    @State private var showingRename = false
    @State private var newName = ""
    @State private var showingDeleteConfirm = false
    @State private var showingBlockConfirm = false

    var body: some View {
        NavigationStack {
            List {
                Section {
                    HStack(spacing: AegisLayout.m) {
                        AvatarView(displayName: contact.displayName, hue: contact.avatarHue, size: AegisLayout.avatarL)
                        VStack(alignment: .leading, spacing: 4) {
                            Text(contact.displayName)
                                .font(AegisType.titleSmall)
                                .foregroundStyle(AegisColors.textPrimary)
                            Text(verificationLabel)
                                .font(AegisType.caption)
                                .foregroundStyle(AegisColors.textSecondary)
                        }
                        Spacer()
                        Button("Rename") { newName = contact.displayName; showingRename = true }
                            .font(AegisType.callout)
                            .foregroundStyle(AegisColors.accent)
                    }
                    .padding(.vertical, AegisLayout.s)
                }

                Section("Verification") {
                    Button {
                        showingSafetyNumber = true
                    } label: {
                        HStack {
                            VerificationShieldView(state: contact.verification)
                            Text("Verify safety number")
                                .foregroundStyle(AegisColors.textPrimary)
                            Spacer()
                            Image(systemName: "chevron.right")
                                .font(AegisType.caption)
                                .foregroundStyle(AegisColors.textTertiary)
                        }
                    }
                }

                Section("Communicate") {
                    Button {
                        Task { @MainActor in await appState.placeCall(to: contact, kind: .audio); dismiss() }
                    } label: {
                        Label("Voice call", systemImage: "phone.fill")
                    }
                    Button {
                        Task { @MainActor in await appState.placeCall(to: contact, kind: .video); dismiss() }
                    } label: {
                        Label("Video call", systemImage: "video.fill")
                    }
                }

                Section {
                    Button(role: contact.isBlocked ? nil : .destructive) {
                        if contact.isBlocked {
                            Task { @MainActor in await viewModel.toggleBlock(contact); dismiss() }
                        } else {
                            showingBlockConfirm = true
                        }
                    } label: {
                        Label(contact.isBlocked ? "Unblock" : "Block", systemImage: "slash.circle")
                    }
                    Button(role: .destructive) {
                        showingDeleteConfirm = true
                    } label: {
                        Label("Delete contact", systemImage: "trash")
                    }
                }
            }
            .navigationTitle("Contact")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") { dismiss() }
                }
            }
            .sheet(isPresented: $showingSafetyNumber) {
                SafetyNumberView(contact: contact, appState: appState)
            }
            .alert("Rename contact", isPresented: $showingRename) {
                TextField("Name", text: $newName)
                Button("Save") {
                    Task { @MainActor in await viewModel.rename(contact, to: newName); dismiss() }
                }
                Button("Cancel", role: .cancel) {}
            }
            .confirmationDialog("Block this contact?", isPresented: $showingBlockConfirm, titleVisibility: .visible) {
                Button("Block", role: .destructive) {
                    Task { @MainActor in await viewModel.toggleBlock(contact); dismiss() }
                }
                Button("Cancel", role: .cancel) {}
            } message: {
                Text("Blocked contacts can't message or call you.")
            }
            .confirmationDialog("Delete this contact?", isPresented: $showingDeleteConfirm, titleVisibility: .visible) {
                Button("Delete", role: .destructive) {
                    Task { @MainActor in await viewModel.delete(contact); dismiss() }
                }
                Button("Cancel", role: .cancel) {}
            }
        }
        .presentationDetents([.medium, .large])
    }

    private var verificationLabel: String {
        switch contact.verification {
        case .unverified: return "Not yet verified"
        case .verified: return "Verified"
        case .identityChanged: return "Safety number changed"
        }
    }
}

#Preview {
    let appState = AppState(factory: PreviewServiceFactory())
    return ContactsView(appState: appState)
        .environmentObject(appState)
}
