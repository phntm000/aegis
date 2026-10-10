import SwiftUI

/// Safety-number verification: the out-of-band trust ceremony. The user
/// compares these numbers with the contact (in person or over a trusted
/// channel) and marks the contact verified only when they match.
struct SafetyNumberView: View {
    let contact: Contact
    @StateObject private var viewModel: ContactsViewModel
    @Environment(\.dismiss) private var dismiss

    @State private var showingMismatchConfirm = false

    init(contact: Contact, appState: AppState) {
        self.contact = contact
        _viewModel = StateObject(wrappedValue: ContactsViewModel(appState: appState))
    }

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: AegisLayout.l) {
                    header

                    VStack(alignment: .leading, spacing: AegisLayout.s) {
                        Text("Safety number")
                            .font(AegisType.captionStrong)
                            .foregroundStyle(AegisColors.textSecondary)
                        Text(Formatters.groupedFingerprint(viewModel.safetyNumber(for: contact)))
                            .font(AegisType.fingerprintLarge)
                            .foregroundStyle(AegisColors.textPrimary)
                            .textSelection(.enabled)
                            .lineSpacing(6)
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(AegisLayout.l)
                    .background(AegisColors.surface)
                    .clipShape(RoundedRectangle(cornerRadius: AegisLayout.radiusL))

                    VStack(alignment: .leading, spacing: AegisLayout.s) {
                        Text("\(contact.displayName)'s fingerprint")
                            .font(AegisType.captionStrong)
                            .foregroundStyle(AegisColors.textSecondary)
                        Text(Formatters.groupedFingerprint(viewModel.fingerprint(for: contact)))
                            .font(AegisType.fingerprint)
                            .foregroundStyle(AegisColors.textPrimary)
                            .textSelection(.enabled)
                            .lineSpacing(6)
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(AegisLayout.l)
                    .background(AegisColors.surface)
                    .clipShape(RoundedRectangle(cornerRadius: AegisLayout.radiusL))

                    Text("Compare these numbers with \(contact.displayName) directly — in person or over a call you trust. If they match, your conversation is protected against interception.")
                        .font(AegisType.callout)
                        .foregroundStyle(AegisColors.textSecondary)

                    if contact.verification != .verified {
                        Button {
                            Task { @MainActor in
                                await viewModel.markVerified(contact)
                                dismiss()
                            }
                        } label: {
                            Label("They match — mark as verified", systemImage: "checkmark.shield.fill")
                                .frame(maxWidth: .infinity, minHeight: AegisLayout.minTapTarget)
                        }
                        .buttonStyle(.borderedProminent)
                        .tint(AegisColors.accent)
                        .accessibilityLabel("Mark contact as verified")
                    }

                    Button(role: .destructive) {
                        showingMismatchConfirm = true
                    } label: {
                        Label("They don't match", systemImage: "exclamationmark.shield.fill")
                            .frame(maxWidth: .infinity, minHeight: AegisLayout.minTapTarget)
                    }
                    .buttonStyle(.bordered)
                    .tint(AegisColors.danger)
                    .accessibilityLabel("Report safety number mismatch")
                }
                .padding(.horizontal, AegisLayout.l)
                .padding(.vertical, AegisLayout.m)
            }
            .navigationTitle("Safety number")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") { dismiss() }
                }
            }
            .confirmationDialog("Safety numbers don't match?", isPresented: $showingMismatchConfirm, titleVisibility: .visible) {
                Button("Flag and block", role: .destructive) {
                    Task { @MainActor in
                        await viewModel.flagIdentityChanged(contact)
                        await viewModel.toggleBlock(contact)
                        dismiss()
                    }
                }
                Button("Cancel", role: .cancel) {}
            } message: {
                Text("Someone may be intercepting your messages. The contact will be flagged and blocked until you resolve this.")
            }
        }
        .presentationDetents([.medium, .large])
    }

    private var header: some View {
        HStack(spacing: AegisLayout.m) {
            AvatarView(displayName: contact.displayName, hue: contact.avatarHue, size: AegisLayout.avatarL)
            VStack(alignment: .leading, spacing: 4) {
                Text(contact.displayName)
                    .font(AegisType.titleSmall)
                    .foregroundStyle(AegisColors.textPrimary)
                HStack(spacing: AegisLayout.xs) {
                    VerificationShieldView(state: contact.verification, size: 14)
                    Text(verificationLabel)
                        .font(AegisType.caption)
                        .foregroundStyle(AegisColors.textSecondary)
                }
            }
            Spacer()
        }
    }

    private var verificationLabel: String {
        switch contact.verification {
        case .unverified: return "Not yet verified"
        case .verified: return "Verified"
        case .identityChanged: return "Key changed — verify again"
        }
    }
}

/// The blocked list with one-tap unblock.
struct BlockedListView: View {
    @ObservedObject var viewModel: ContactsViewModel

    var body: some View {
        Group {
            if viewModel.blocked.isEmpty {
                EmptyStateView(
                    icon: "slash.circle",
                    title: "No blocked contacts",
                    message: "Blocked contacts can't message or call you."
                )
            } else {
                List {
                    ForEach(viewModel.blocked) { contact in
                        HStack {
                            AvatarView(displayName: contact.displayName, hue: contact.avatarHue, size: AegisLayout.avatarM)
                                .accessibilityHidden(true)
                            Text(contact.displayName)
                                .font(AegisType.body)
                                .foregroundStyle(AegisColors.textPrimary)
                            Spacer()
                            Button("Unblock") {
                                Task { @MainActor in await viewModel.toggleBlock(contact) }
                            }
                            .font(AegisType.callout)
                            .foregroundStyle(AegisColors.accent)
                            .accessibilityLabel("Unblock \(contact.displayName)")
                        }
                        .padding(.vertical, AegisLayout.xs)
                    }
                }
                .listStyle(.insetGrouped)
                .scrollContentBackground(.hidden)
            }
        }
        .background(AegisColors.background.ignoresSafeArea())
        .navigationTitle("Blocked")
        .navigationBarTitleDisplayMode(.inline)
    }
}

#Preview {
    let appState = AppState(factory: PreviewServiceFactory())
    return SafetyNumberView(contact: SampleData.previewContact(name: "Maya Chen"), appState: appState)
        .environmentObject(appState)
}
