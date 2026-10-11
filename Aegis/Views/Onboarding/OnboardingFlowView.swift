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
            .alert("Couldn't load identity", isPresented: bootstrapErrorPresented) {
                Button("Start fresh", role: .destructive) {
                    appState.bootstrapError = nil
                }
            } message: {
                Text(appState.bootstrapError ?? "")
            }
        }
    }

    /// Explicit binding (not `.constant`): the alert must be able to dismiss
    /// itself and stay in sync with the published error.
    private var bootstrapErrorPresented: Binding<Bool> {
        Binding(
            get: { appState.bootstrapError != nil },
            set: { if !$0 { appState.bootstrapError = nil } }
        )
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
                    .frame(minHeight: AegisLayout.minTapTarget)
                Spacer()
                Button("Continue") { viewModel.next() }
                    .buttonStyle(.borderedProminent)
                    .tint(AegisColors.accent)
                    .frame(minHeight: AegisLayout.minTapTarget)
                    .disabled(viewModel.createdIdentity == nil)
            }
        case .backup:
            HStack {
                Button("Back", action: viewModel.back)
                    .buttonStyle(.bordered)
                    .tint(AegisColors.accent)
                    .frame(minHeight: AegisLayout.minTapTarget)
                Spacer()
                if viewModel.backupComplete {
                    Button("Continue") { viewModel.next() }
                        .buttonStyle(.borderedProminent)
                        .tint(AegisColors.accent)
                        .frame(minHeight: AegisLayout.minTapTarget)
                } else {
                    Button("I'll do this later") { viewModel.next() }
                        .buttonStyle(.bordered)
                        .tint(AegisColors.accent)
                        .frame(minHeight: AegisLayout.minTapTarget)
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
