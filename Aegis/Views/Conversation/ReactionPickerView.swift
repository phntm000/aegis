import SwiftUI

/// Long-press reaction picker: quick emoji row plus the user's custom
/// emoji packs. Custom emoji render as images only (never as text).
struct ReactionPickerView: View {
    var onPick: (String) -> Void

    @State private var packs: [CustomEmojiPack] = []
    @State private var customImages: [String: UIImage] = [:]
    @State private var isLoading = true

    private let quickEmojis = ["❤️", "👍", "😂", "😮", "😢", "🙏"]

    var body: some View {
        VStack(spacing: AegisLayout.s) {
            if isLoading {
                ProgressView()
                    .tint(AegisColors.accent)
                    .frame(minHeight: AegisLayout.minTapTarget)
                    .accessibilityLabel("Loading emoji")
            } else {
                quickRow
                if !customImages.isEmpty {
                    Divider()
                    customGrid
                }
            }
        }
        .padding(AegisLayout.s)
        .background(AegisColors.surfaceElevated)
        .clipShape(RoundedRectangle(cornerRadius: AegisLayout.radiusL))
        .shadow(radius: 12)
        .task {
            await loadPacks()
        }
    }

    private var quickRow: some View {
        HStack(spacing: 2) {
            ForEach(quickEmojis, id: \.self) { emoji in
                Button {
                    onPick(emoji)
                } label: {
                    Text(emoji)
                        .font(.system(size: 30))
                        .frame(minWidth: AegisLayout.minTapTarget, minHeight: AegisLayout.minTapTarget)
                }
                .accessibilityLabel("React with \(emoji)")
            }
        }
    }

    private var customGrid: some View {
        LazyVGrid(
            columns: [GridItem(.adaptive(minimum: AegisLayout.minTapTarget), spacing: 2)],
            spacing: 2
        ) {
            ForEach(customImages.keys.sorted(), id: \.self) { key in
                if let image = customImages[key] {
                    Button {
                        onPick(key)
                    } label: {
                        Image(uiImage: image)
                            .resizable()
                            .scaledToFit()
                            .frame(width: 30, height: 30)
                            .frame(minWidth: AegisLayout.minTapTarget, minHeight: AegisLayout.minTapTarget)
                    }
                    .accessibilityLabel("React with custom emoji")
                }
            }
        }
        .frame(maxHeight: 180)
    }

    private func loadPacks() async {
        let loaded = await EmojiPackStore.shared.allPacks()
        var images: [String: UIImage] = [:]
        for pack in loaded {
            for emoji in pack.emojis {
                let key = ReactionKey.customEmoji(packID: pack.id, emojiID: emoji.id)
                if let image = await EmojiPackStore.shared.image(forReactionKey: key) {
                    images[key] = image
                }
            }
        }
        packs = loaded
        customImages = images
        isLoading = false
    }
}

#Preview {
    ReactionPickerView { _ in }
        .padding()
}
