import SwiftUI

/// Messaging preferences: the edit window for sent messages and the
/// local-only custom emoji packs used by the reaction picker.
struct MessagingSettingsView: View {
    private let editWindowOptions: [(label: String, seconds: TimeInterval)] = [
        ("Off", 0),
        ("1 hour", 3600),
        ("24 hours", 24 * 3600),
        ("48 hours", 48 * 3600),
        ("7 days", 7 * 24 * 3600),
    ]

    @State private var editWindow: TimeInterval = defaultEditWindowSeconds
    @State private var packCount = 0

    var body: some View {
        List {
            Section {
                Picker("Edit window", selection: $editWindow) {
                    ForEach(editWindowOptions, id: \.seconds) { option in
                        Text(option.label).tag(option.seconds)
                    }
                }
                .accessibilityLabel("How long sent messages can be edited")
                .onChange(of: editWindow) { _, newValue in
                    UserDefaults.standard.set(newValue, forKey: SettingsKeys.editWindowSeconds)
                    Haptics.selection()
                }
            } header: {
                Text("Edits")
            } footer: {
                Text("How long after sending you can edit a message. Edits are sent to everyone in the chat, and the previous versions stay in the local edit history.")
            }

            Section {
                NavigationLink(destination: CustomEmojiPacksView()) {
                    HStack {
                        Label("Custom emoji packs", systemImage: "face.smiling")
                            .foregroundStyle(AegisColors.textPrimary)
                        Spacer()
                        Text(packCount == 1 ? "1 pack" : "\(packCount) packs")
                            .font(AegisType.caption)
                            .foregroundStyle(AegisColors.textSecondary)
                    }
                }
                .accessibilityLabel("Custom emoji packs")
                .accessibilityHint("\(packCount) packs. Packs stay on this device only.")
            } header: {
                Text("Reactions")
            } footer: {
                Text("Custom emoji render as images in reactions and the reaction picker. Packs never sync — they're local to this device.")
            }
        }
        .navigationTitle("Messaging")
        .navigationBarTitleDisplayMode(.inline)
        .task {
            if UserDefaults.standard.object(forKey: SettingsKeys.editWindowSeconds) != nil {
                editWindow = UserDefaults.standard.double(forKey: SettingsKeys.editWindowSeconds)
            }
            packCount = await EmojiPackStore.shared.allPacks().count
        }
    }
}

#Preview {
    NavigationStack {
        MessagingSettingsView()
    }
}
