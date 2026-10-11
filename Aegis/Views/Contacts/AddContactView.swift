import SwiftUI
import UIKit

/// Add a contact: scan their QR, paste an invite code, or share your own.
/// Adding creates the contact and an empty DM so the chat list never greets
/// you with a dead end.
struct AddContactView: View {
    @EnvironmentObject private var appState: AppState
    @Environment(\.dismiss) private var dismiss
    var onAdded: (Conversation?) -> Void

    @StateObject private var viewModel: ContactsViewModel

    @State private var inviteCode = ""
    @State private var displayName = ""
    @State private var isAdding = false
    @State private var error: String?
    @State private var showingScanner = false
    @State private var myInvitePayload: String?
    @State private var myInviteCode: String?
    @FocusState private var codeFocused: Bool

    init(appState: AppState, onAdded: @escaping (Conversation?) -> Void) {
        _viewModel = StateObject(wrappedValue: ContactsViewModel(appState: appState))
        self.onAdded = onAdded
    }

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: AegisLayout.l) {
                    // Their code
                    VStack(alignment: .leading, spacing: AegisLayout.s) {
                        Text("Add by invite code")
                            .font(AegisType.titleSmall)
                            .foregroundStyle(AegisColors.textPrimary)

                        Button {
                            showingScanner = true
                        } label: {
                            Label("Scan QR code", systemImage: "qrcode.viewfinder")
                                .frame(maxWidth: .infinity, minHeight: AegisLayout.minTapTarget)
                        }
                        .buttonStyle(.borderedProminent)
                        .tint(AegisColors.accent)
                        .accessibilityLabel("Scan QR code")

                        TextField("Paste invite code", text: $inviteCode, axis: .vertical)
                            .textFieldStyle(.roundedBorder)
                            .autocorrectionDisabled()
                            .textInputAutocapitalization(.never)
                            .focused($codeFocused)
                            .accessibilityLabel("Invite code")
                        TextField("Name them (optional)", text: $displayName)
                            .textFieldStyle(.roundedBorder)
                            .autocorrectionDisabled()
                            .accessibilityLabel("Contact display name, optional")

                        if let error {
                            ErrorBannerView(message: error, onDismiss: { self.error = nil })
                        }

                        Button {
                            Task { @MainActor in await add() }
                        } label: {
                            HStack {
                                if isAdding { ProgressView().tint(AegisColors.textOnAccent) }
                                Text(isAdding ? "Adding…" : "Add contact")
                            }
                            .frame(maxWidth: .infinity, minHeight: AegisLayout.minTapTarget)
                        }
                        .buttonStyle(.bordered)
                        .tint(AegisColors.accent)
                        .disabled(isAdding || inviteCode.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                        .accessibilityLabel("Add contact")
                    }

                    Divider()

                    // Your code
                    VStack(alignment: .leading, spacing: AegisLayout.s) {
                        Text("Share your invite")
                            .font(AegisType.titleSmall)
                            .foregroundStyle(AegisColors.textPrimary)
                        Text("Let them scan this, or send them your code.")
                            .font(AegisType.callout)
                            .foregroundStyle(AegisColors.textSecondary)
                        if let payload = myInvitePayload {
                            HStack {
                                Spacer()
                                QRCodeView(payload: payload, size: 180)
                                Spacer()
                            }
                            if let code = myInviteCode {
                                HStack {
                                    Text(code)
                                        .font(AegisType.caption)
                                        .foregroundStyle(AegisColors.textSecondary)
                                        .lineLimit(1)
                                        .truncationMode(.middle)
                                    Spacer()
                                    Button("Copy") {
                                        UIPasteboard.general.string = code
                                        Haptics.selection()
                                    }
                                    .font(AegisType.callout)
                                    .foregroundStyle(AegisColors.accent)
                                    .aegisMinimumTapTarget()
                                    .accessibilityLabel("Copy my invite code")
                                }
                                .padding(AegisLayout.m)
                                .background(AegisColors.backgroundSecondary)
                                .clipShape(RoundedRectangle(cornerRadius: AegisLayout.radiusM))
                            }
                        } else if appState.identity != nil {
                            HStack {
                                Spacer()
                                ProgressView().tint(AegisColors.textSecondary)
                                Spacer()
                            }
                            .accessibilityLabel("Preparing invite code")
                        } else {
                            // Identity not loaded (defensive): never a blank section.
                            Text("Your invite isn't available yet — your identity is still loading.")
                                .font(AegisType.caption)
                                .foregroundStyle(AegisColors.textSecondary)
                                .multilineTextAlignment(.center)
                                .frame(maxWidth: .infinity)
                                .padding(.vertical, AegisLayout.m)
                        }
                    }
                }
                .padding(.horizontal, AegisLayout.l)
                .padding(.vertical, AegisLayout.m)
            }
            .navigationTitle("Add contact")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
            }
            .sheet(isPresented: $showingScanner) {
                ScannerView { payload in
                    inviteCode = payload
                    Task { @MainActor in await add() }
                }
            }
            .task { @MainActor in
                await viewModel.load()
                if let identity = appState.identity {
                    myInvitePayload = try? await appState.crypto.qrPayload(for: identity)
                    myInviteCode = try? await appState.crypto.inviteCode(for: identity)
                }
            }
        }
        .presentationDetents([.medium, .large])
    }

    private func add() async {
        let code = inviteCode.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !code.isEmpty else { return }
        isAdding = true
        error = nil
        defer { isAdding = false }
        do {
            let contact = try await viewModel.addFromInviteCode(code, displayName: displayName)
            // Find the DM the view model created and open it.
            let conversations = try await appState.store.fetchConversations()
            let dm = conversations.first {
                $0.kind == .direct && $0.memberIDs.contains(contact.id)
            }
            dismiss()
            onAdded(dm)
        } catch {
            self.error = error.localizedDescription
            Haptics.notification(.error)
        }
    }
}

#Preview {
    let appState = AppState(factory: PreviewServiceFactory())
    return AddContactView(appState: appState) { _ in }
        .environmentObject(appState)
}
