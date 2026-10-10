import SwiftUI

/// Step 2 — display name + keypair generation, then the identity card:
/// fingerprint and QR shown prominently, as required.
struct IdentityGenerationView: View {
    @ObservedObject var viewModel: OnboardingViewModel
    @EnvironmentObject private var appState: AppState
    @FocusState private var nameFocused: Bool
    @State private var qrPayload: String?

    var body: some View {
        ScrollView {
            VStack(spacing: AegisLayout.l) {
                if let identity = viewModel.createdIdentity {
                    identityCard(identity)
                } else {
                    generationForm
                }
            }
            .padding(.horizontal, AegisLayout.l)
            .padding(.vertical, AegisLayout.m)
        }
        .onAppear { nameFocused = true }
    }

    // MARK: - Form

    private var generationForm: some View {
        VStack(alignment: .leading, spacing: AegisLayout.m) {
            Text("Choose how contacts will see you. This name is stored only on your device and shared with people you add.")
                .font(AegisType.callout)
                .foregroundStyle(AegisColors.textSecondary)

            TextField("Display name", text: $viewModel.displayName)
                .textFieldStyle(.roundedBorder)
                .textContentType(.name)
                .autocorrectionDisabled()
                .focused($nameFocused)
                .submitLabel(.go)
                .onSubmit { Task { @MainActor in await viewModel.generateIdentity() } }
                .accessibilityLabel("Display name")

            if let error = viewModel.generationError {
                ErrorBannerView(message: error, onDismiss: { viewModel.generationError = nil })
                    .padding(.horizontal, -AegisLayout.l)
            }

            Button {
                Task { @MainActor in await viewModel.generateIdentity() }
            } label: {
                HStack {
                    if viewModel.isGenerating {
                        ProgressView().tint(AegisColors.textOnAccent)
                    } else {
                        Image(systemName: "key.fill")
                    }
                    Text(viewModel.isGenerating ? "Generating secure identity…" : "Generate my identity")
                }
                .frame(maxWidth: .infinity, minHeight: AegisLayout.minTapTarget)
            }
            .buttonStyle(.borderedProminent)
            .tint(AegisColors.accent)
            .disabled(viewModel.isGenerating || viewModel.displayName.trimmingCharacters(in: .whitespaces).isEmpty)
            .accessibilityLabel("Generate my identity")

            Text("Generation happens entirely on this device using your secure enclave. No network call is made.")
                .font(AegisType.caption)
                .foregroundStyle(AegisColors.textTertiary)
        }
    }

    // MARK: - Identity card

    private func identityCard(_ identity: LocalIdentity) -> some View {
        VStack(spacing: AegisLayout.l) {
            HStack {
                Image(systemName: "checkmark.circle.fill")
                    .foregroundStyle(AegisColors.success)
                Text("Identity created")
                    .font(AegisType.bodyStrong)
                    .foregroundStyle(AegisColors.textPrimary)
                Spacer()
            }
            .accessibilityLabel("Identity created successfully")

            VStack(spacing: AegisLayout.s) {
                AvatarView(displayName: identity.displayName, hue: 0.58, size: AegisLayout.avatarXL)
                Text(identity.displayName)
                    .font(AegisType.titleSmall)
                    .foregroundStyle(AegisColors.textPrimary)
                Text(identity.shortHandle)
                    .font(AegisType.caption)
                    .foregroundStyle(AegisColors.textTertiary)
            }

            VStack(alignment: .leading, spacing: AegisLayout.s) {
                Text("Identity fingerprint")
                    .font(AegisType.captionStrong)
                    .foregroundStyle(AegisColors.textSecondary)
                Text(Formatters.groupedFingerprint(appState.crypto.fingerprint(of: identity.publicKey)))
                    .font(AegisType.fingerprint)
                    .foregroundStyle(AegisColors.textPrimary)
                    .textSelection(.enabled)
                    .padding(AegisLayout.m)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(AegisColors.backgroundSecondary)
                    .clipShape(RoundedRectangle(cornerRadius: AegisLayout.radiusM))
            }

            if let payload = qrPayload {
                VStack(spacing: AegisLayout.s) {
                    Text("Share this QR to connect")
                        .font(AegisType.captionStrong)
                        .foregroundStyle(AegisColors.textSecondary)
                    QRCodeView(payload: payload, size: 200)
                }
            } else {
                ProgressView()
                    .tint(AegisColors.textSecondary)
                    .accessibilityLabel("Preparing QR code")
            }

            Text("There is no username to recover and no password to reset. Your backup phrase (next step) is the only recovery path.")
                .font(AegisType.caption)
                .foregroundStyle(AegisColors.textTertiary)
                .multilineTextAlignment(.center)
        }
        .padding(AegisLayout.l)
        .background(AegisColors.surface)
        .clipShape(RoundedRectangle(cornerRadius: AegisLayout.radiusL))
        .shadow(color: AegisLayout.cardShadow.color, radius: AegisLayout.cardShadow.radius,
                x: AegisLayout.cardShadow.x, y: AegisLayout.cardShadow.y)
        .task(id: identity.id) {
            qrPayload = try? await appState.crypto.qrPayload(for: identity)
        }
    }
}

#Preview {
    let appState = AppState(factory: PreviewServiceFactory())
    let vm = OnboardingViewModel(appState: appState)
    return IdentityGenerationView(viewModel: vm)
        .environmentObject(appState)
}
