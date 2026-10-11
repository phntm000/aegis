import SwiftUI

/// Privacy controls. Every toggle is persisted immediately and explained in
/// plain language — no dark patterns, no buried settings.
struct PrivacySettingsView: View {
    @AppStorage(SettingsKeys.sealedSender) private var sealedSender = true
    @AppStorage(SettingsKeys.readReceiptsDefault) private var readReceiptsDefault = true
    @AppStorage(SettingsKeys.typingIndicatorsDefault) private var typingIndicatorsDefault = true
    @AppStorage(SettingsKeys.screenshotAlerts) private var screenshotAlerts = false
    @AppStorage(SettingsKeys.disappearingDefault) private var disappearingDefault = 0

    var body: some View {
        List {
            Section {
                Toggle(isOn: $sealedSender) {
                    settingLabel(
                        title: "Sealed sender",
                        body: "Hide who messages are from, even from the relay. The relay sees only that *someone* sent *something*."
                    )
                }
                .accessibilityLabel("Sealed sender")
            } header: {
                EmptyView()
            } footer: {
                Text("Metadata resistance. Slightly more bandwidth, meaningfully more privacy.")
            }

            Section {
                Toggle(isOn: $readReceiptsDefault) {
                    settingLabel(
                        title: "Read receipts",
                        body: "Send read receipts in new conversations. You can override this per chat."
                    )
                }
                Toggle(isOn: $typingIndicatorsDefault) {
                    settingLabel(
                        title: "Typing indicators",
                        body: "Show when you're typing in new conversations. Per-chat override available."
                    )
                }

                Picker("Disappearing messages", selection: $disappearingDefault) {
                    Text("Off").tag(0)
                    Text("24 hours").tag(86400)
                    Text("7 days").tag(604800)
                }
                .accessibilityLabel("Default disappearing message timer for new chats")
            } header: {
                Text("Defaults for new chats")
            } footer: {
                Text("Existing conversations keep their own settings — these apply to new ones.")
            }

            Section {
                Toggle(isOn: $screenshotAlerts) {
                    settingLabel(
                        title: "Screenshot alerts",
                        body: "Notify the chat when you take a screenshot, and show a notice when a contact does."
                    )
                }
                .accessibilityLabel("Screenshot alerts")
            } header: {
                EmptyView()
            } footer: {
                Text("Screenshots can't be prevented — but they shouldn't be silent either.")
            }
        }
        .navigationTitle("Privacy")
        .navigationBarTitleDisplayMode(.inline)
    }

    private func settingLabel(title: String, body: String) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(title)
                .font(AegisType.body)
                .foregroundStyle(AegisColors.textPrimary)
            Text(body)
                .font(AegisType.caption)
                .foregroundStyle(AegisColors.textSecondary)
        }
    }
}

/// Appearance: system / light / dark. Applied at the root via RootView.
struct AppearanceSettingsView: View {
    @AppStorage(SettingsKeys.appearance) private var appearanceRaw: String = AppearanceMode.system.rawValue

    var body: some View {
        List {
            Section {
                ForEach(AppearanceMode.allCases, id: \.self) { mode in
                    Button {
                        appearanceRaw = mode.rawValue
                        Haptics.selection()
                    } label: {
                        HStack {
                            Label(mode.displayName, systemImage: icon(for: mode))
                                .foregroundStyle(AegisColors.textPrimary)
                            Spacer()
                            if appearanceRaw == mode.rawValue {
                                Image(systemName: "checkmark")
                                    .foregroundStyle(AegisColors.accent)
                                    .accessibilityHidden(true)
                            }
                        }
                    }
                    .accessibilityLabel("\(mode.displayName) appearance")
                    .accessibilityAddTraits(appearanceRaw == mode.rawValue ? .isSelected : [])
                }
            } header: {
                EmptyView()
            } footer: {
                Text("Aegis is designed dark-first, but both themes are first-class.")
            }
        }
        .navigationTitle("Appearance")
        .navigationBarTitleDisplayMode(.inline)
    }

    private func icon(for mode: AppearanceMode) -> String {
        switch mode {
        case .system: return "circle.lefthalf.filled"
        case .light: return "sun.max.fill"
        case .dark: return "moon.fill"
        }
    }
}

#Preview {
    NavigationStack {
        PrivacySettingsView()
    }
}
