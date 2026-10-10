import SwiftUI

/// Step 4 — add the first contact via invite code or QR scan. Skippable: the
/// user can always add contacts later from the Contacts tab.
struct AddFirstContactView: View {
    @ObservedObject var viewModel: OnboardingViewModel
    @State private var showingScanner = false
    @FocusState private var codeFocused: Bool

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: AegisLayout.l) {
                Text("Ask a friend to open their identity QR in Aegis, then scan it — or paste the invite code they sent you.")
                    .font(AegisType.callout)
                    .foregroundStyle(AegisColors.textSecondary)

                Button {
                    showingScanner = true
                } label: {
                    HStack {
                        Image(systemName: "qrcode.viewfinder")
                        Text("Scan QR code")
                    }
                    .frame(maxWidth: .infinity, minHeight: AegisLayout.minTapTarget)
                }
                .buttonStyle(.borderedProminent)
                .tint(AegisColors.accent)
                .accessibilityLabel("Scan a contact's QR code")

                HStack {
                    Divider()
                    Text("or paste an invite code")
                        .font(AegisType.caption)
                        .foregroundStyle(AegisColors.textTertiary)
                    Divider()
                }

                TextField("aegis-invite-…", text: $viewModel.inviteInput, axis: .vertical)
                    .textFieldStyle(.roundedBorder)
                    .autocorrectionDisabled()
                    .textInputAutocapitalization(.never)
                    .focused($codeFocused)
                    .accessibilityLabel("Invite code")

                if let error = viewModel.addContactError {
                    ErrorBannerView(message: error, onDismiss: { viewModel.addContactError = nil })
                        .padding(.horizontal, -AegisLayout.l)
                }

                if let name = viewModel.addedContactName {
                    HStack {
                        Image(systemName: "checkmark.circle.fill")
                            .foregroundStyle(AegisColors.success)
                            .accessibilityHidden(true)
                        Text("\(name) added — say hello from your chats.")
                            .font(AegisType.callout)
                            .foregroundStyle(AegisColors.textPrimary)
                    }
                    .accessibilityLabel("\(name) added successfully")
                }

                Button {
                    Task { @MainActor in await viewModel.addContactFromCode() }
                } label: {
                    HStack {
                        if viewModel.isAddingContact {
                            ProgressView().tint(AegisColors.textOnAccent)
                        }
                        Text(viewModel.isAddingContact ? "Adding…" : "Add contact")
                    }
                    .frame(maxWidth: .infinity, minHeight: AegisLayout.minTapTarget)
                }
                .buttonStyle(.bordered)
                .tint(AegisColors.accent)
                .disabled(viewModel.isAddingContact || viewModel.inviteInput.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                .accessibilityLabel("Add contact from invite code")

                Text("No one can find you by searching. Contacts are only ever added explicitly — that's why there's no spam here.")
                    .font(AegisType.caption)
                    .foregroundStyle(AegisColors.textTertiary)
            }
            .padding(.horizontal, AegisLayout.l)
            .padding(.vertical, AegisLayout.m)
        }
        .sheet(isPresented: $showingScanner) {
            ScannerView { payload in
                viewModel.inviteInput = payload
                Task { @MainActor in await viewModel.addContactFromCode() }
            }
        }
    }
}

#Preview {
    let appState = AppState(factory: PreviewServiceFactory())
    return AddFirstContactView(viewModel: OnboardingViewModel(appState: appState))
        .environmentObject(appState)
}
