import SwiftUI

/// Settings hub: identity, privacy, appearance, notifications, security,
/// storage, relay, and about. Each row pushes a focused screen — no dead ends.
struct SettingsView: View {
    @StateObject private var viewModel: SettingsViewModel
    @EnvironmentObject private var appState: AppState

    init(appState: AppState) {
        _viewModel = StateObject(wrappedValue: SettingsViewModel(appState: appState))
    }

    var body: some View {
        NavigationStack {
            List {
                // Identity card
                Section {
                    NavigationLink {
                        IdentitySettingsView(appState: appState)
                    } label: {
                        HStack(spacing: AegisLayout.m) {
                            if let identity = viewModel.identity {
                                AvatarView(displayName: identity.displayName, hue: 0.58, size: AegisLayout.avatarM)
                                    .accessibilityHidden(true)
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(identity.displayName)
                                        .font(AegisType.bodyStrong)
                                        .foregroundStyle(AegisColors.textPrimary)
                                    Text(identity.shortHandle)
                                        .font(AegisType.caption)
                                        .foregroundStyle(AegisColors.textTertiary)
                                }
                            } else {
                                ProgressView().tint(AegisColors.accent)
                            }
                        }
                        .padding(.vertical, AegisLayout.xs)
                    }
                    .accessibilityLabel("Identity settings")
                }

                Section {
                    settingsRow(icon: "lock.shield.fill", title: "Privacy", color: AegisColors.accent, destination: AnyView(PrivacySettingsView()))
                    settingsRow(icon: "paintbrush.fill", title: "Appearance", color: Color.purple, destination: AnyView(AppearanceSettingsView()))
                    settingsRow(icon: "bell.badge.fill", title: "Notifications", color: AegisColors.danger, destination: AnyView(NotificationsSettingsView(appState: appState)))
                    settingsRow(icon: "faceid", title: "App lock", color: AegisColors.success, destination: AnyView(AppLockSettingsView()))
                } header: {
                    Text("Preferences")
                } footer: {
                    EmptyView()
                }

                Section {

                    settingsRow(icon: "internaldrive.fill", title: "Storage", color: AegisColors.textSecondary, destination: AnyView(StorageSettingsView(appState: appState)))
                    settingsRow(icon: "server.rack", title: "Relay", color: AegisColors.warning, destination: AnyView(RelaySettingsView(appState: appState)))
                } header: {
                    Text("Data & network")
                } footer: {
                    EmptyView()
                }

                Section {
                    settingsRow(icon: "info.circle.fill", title: "About Aegis", color: AegisColors.textSecondary, destination: AnyView(AboutView()))
                } header: {
                    Text("About")
                } footer: {
                    EmptyView()
                }
            }
            .listStyle(.insetGrouped)
            .scrollContentBackground(.hidden)
            .background(AegisColors.background.ignoresSafeArea())
            .navigationTitle("Settings")
            .navigationBarTitleDisplayMode(.large)
            .task { @MainActor in
                await viewModel.load()
            }
        }
    }

    private func settingsRow(
        icon: String,
        title: String,
        color: Color,
        destination: AnyView
    ) -> some View {
        NavigationLink(destination: destination) {
            HStack(spacing: AegisLayout.m) {
                Image(systemName: icon)
                    .font(.system(size: 15))
                    .foregroundStyle(.white)
                    .frame(width: 30, height: 30)
                    .background(color)
                    .clipShape(RoundedRectangle(cornerRadius: 7))
                    .accessibilityHidden(true)
                Text(title)
                    .font(AegisType.body)
                    .foregroundStyle(AegisColors.textPrimary)
            }
            .padding(.vertical, 2)
        }
        .accessibilityLabel("\(title) settings")
    }
}

#Preview {
    let appState = AppState(factory: PreviewServiceFactory())
    return SettingsView(appState: appState)
        .environmentObject(appState)
}
