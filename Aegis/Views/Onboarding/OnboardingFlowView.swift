import SwiftUI

/// First-launch pager: welcome → identity → backup → first contact.
/// A slim progress header keeps the flow honest about its length.
struct OnboardingFlowView: View {
    @StateObject private var viewModel: OnboardingViewModel
    @EnvironmentObject private var appState: AppState

    init(appState: AppState) {
        _viewModel = StateObject(wrappedValue: OnboardingViewModel(appState: appState))
    }

    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                progressHeader
                    .padding(.horizontal, AegisLayout.l)
                    .padding(.top, AegisLayout.s)

                Group {
                    switch viewModel.step {
                    case .welcome:
                        WelcomeView(onContinue: viewModel.next)
                    case .identity:
                        IdentityGenerationView(viewModel: viewModel)
                    case .backup:
                        BackupPassphraseView(viewModel: viewModel)
                    case .addContact:
                        AddFirstContactView(viewModel: viewModel)
                    }
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)

                footerControls
                    .padding(.horizontal, AegisLayout.l)
                    .padding(.bottom, AegisLayout.l)
            }
            .background(AegisColors.background.ignoresSafeArea())
            .navigationTitle(viewModel.step.title)
            .navigationBarTitleDisplayMode(.large)
            .alert("Couldn't load identity", isPresented: .constant(appState.bootstrapError != nil)) {
                Button("Start fresh", role: .destructive) {
                    appState.bootstrapError = nil
                }
            } message: {
                Text(appState.bootstrapError ?? "")
            }
        }
    }

    private var progressHeader: some View {
        HStack(spacing: AegisLayout.xs) {
            ForEach(OnboardingViewModel.Step.allCases, id: \.self) { step in
                Capsule()
                    .fill(step.rawValue <= viewModel.step.rawValue ? AegisColors.accent : AegisColors.surfacePressed)
                    .frame(height: 4)
                    .accessibilityHidden(true)
            }
        }
        .accessibilityLabel("Step \(viewModel.step.rawValue + 1) of \(OnboardingViewModel.Step.allCases.count)")
    }

    @ViewBuilder
    private var footerControls: some View {
        switch viewModel.step {
        case .welcome:
            EmptyView() // WelcomeView owns its Continue button.
        case .identity:
            HStack {
                Button("Back", action: viewModel.back)
                    .buttonStyle(.bordered)
                    .tint(AegisColors.accent)
                Spacer()
                Button("Continue") { viewModel.next() }
                    .buttonStyle(.borderedProminent)
                    .tint(AegisColors.accent)
                    .disabled(viewModel.createdIdentity == nil)
            }
        case .backup:
            HStack {
                Button("Back", action: viewModel.back)
                    .buttonStyle(.bordered)
                    .tint(AegisColors.accent)
                Spacer()
                if viewModel.backupComplete {
                    Button("Continue") { viewModel.next() }
                        .buttonStyle(.borderedProminent)
                        .tint(AegisColors.accent)
                } else {
                    Button("I'll do this later") { viewModel.next() }
                        .buttonStyle(.bordered)
                        .tint(AegisColors.accent)
                }
            }
        case .addContact:
            Button("Done") { viewModel.finish() }
                .buttonStyle(.borderedProminent)
                .tint(AegisColors.accent)
                .frame(maxWidth: .infinity, minHeight: AegisLayout.minTapTarget)
                .disabled(viewModel.createdIdentity == nil)
        }
    }
}

#Preview {
    let appState = AppState(factory: PreviewServiceFactory())
    return OnboardingFlowView(appState: appState)
        .environmentObject(appState)
}
