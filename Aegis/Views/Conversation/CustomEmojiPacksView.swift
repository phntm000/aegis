import PhotosUI
import SwiftUI

/// Manages local-only custom emoji packs: create/rename/delete packs,
/// add emoji from the photo library (normalized to small PNGs), delete
/// emoji. Packs never sync — they're this device's private sticker shelf
/// for reactions.
struct CustomEmojiPacksView: View {
    @Environment(\.dismiss) private var dismiss

    @State private var packs: [CustomEmojiPack] = []
    @State private var isLoading = true
    @State private var loadError: String?
    @State private var showingCreatePack = false
    @State private var newPackName = ""
    @State private var actionError: String?
    @State private var photoItem: PhotosPickerItem?
    @State private var pendingPackID: UUID?

    var body: some View {
        NavigationStack {
            Group {
                if isLoading {
                    LoadingOverlayView(label: "Loading emoji packs…")
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                } else if let loadError {
                    EmptyStateView(
                        icon: "exclamationmark.triangle",
                        title: "Couldn't load packs",
                        message: loadError,
                        actionTitle: "Retry",
                        action: { Task { await load() } }
                    )
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                } else if packs.isEmpty {
                    EmptyStateView(
                        icon: "face.smiling",
                        title: "No custom emoji yet",
                        message: "Create a pack, add images from your photo library, and they'll show up in the reaction picker.",
                        actionTitle: "Create a pack",
                        action: { showingCreatePack = true }
                    )
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                } else {
                    packList
                }
            }
            .background(AegisColors.background.ignoresSafeArea())
            .navigationTitle("Custom emoji")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Done") { dismiss() }
                }
                ToolbarItem(placement: .primaryAction) {
                    Button {
                        showingCreatePack = true
                    } label: {
                        Image(systemName: "plus")
                            .accessibilityLabel("Create emoji pack")
                    }
                }
            }
            .alert("New emoji pack", isPresented: $showingCreatePack) {
                TextField("Pack name", text: $newPackName)
                Button("Create") { createPack() }
                Button("Cancel", role: .cancel) { newPackName = "" }
            }
            .photosPicker(isPresented: Binding(
                get: { pendingPackID != nil },
                set: { if !$0 { pendingPackID = nil } }
            ), selection: $photoItem, matching: .images)
            .onChange(of: photoItem) { _, item in addEmoji(from: item) }
            .task { await load() }
            .alert("Couldn't save", isPresented: Binding(
                get: { actionError != nil },
                set: { if !$0 { actionError = nil } }
            )) {
                Button("OK", role: .cancel) {}
            } message: {
                Text(actionError ?? "")
            }
        }
    }

    // MARK: - List

    private var packList: some View {
        List {
            ForEach(packs) { pack in
                Section {
                    emojiGrid(for: pack)
                    Button {
                        pendingPackID = pack.id
                    } label: {
                        Label("Add emoji", systemImage: "plus.circle")
                    }
                    .frame(minHeight: AegisLayout.minTapTarget)
                    .accessibilityLabel("Add emoji to \(pack.name)")
                } header: {
                    HStack {
                        Text(pack.name)
                        Spacer()
                        Text("\(pack.emojis.count)")
                            .font(AegisType.caption)
                            .foregroundStyle(AegisColors.textSecondary)
                    }
                }
            }
            .onDelete(perform: deletePack)
        }
        .listStyle(.insetGrouped)
    }

    private func emojiGrid(for pack: CustomEmojiPack) -> some View {
        Group {
            if pack.emojis.isEmpty {
                Text("Empty — add your first emoji below.")
                    .font(AegisType.caption)
                    .foregroundStyle(AegisColors.textSecondary)
                    .padding(.vertical, AegisLayout.s)
            } else {
                LazyVGrid(columns: [GridItem(.adaptive(minimum: 56), spacing: 8)], spacing: 8) {
                    ForEach(pack.emojis) { emoji in
                        EmojiCell(packID: pack.id, emoji: emoji) {
                            Task { await deleteEmoji(packID: pack.id, emojiID: emoji.id) }
                        }
                    }
                }
                .padding(.vertical, AegisLayout.s)
            }
        }
    }

    // MARK: - Actions

    private func load() async {
        isLoading = true
        loadError = nil
        defer { isLoading = false }
        packs = await EmojiPackStore.shared.allPacks()
    }

    private func createPack() {
        let name = newPackName
        newPackName = ""
        Task {
            do {
                _ = try await EmojiPackStore.shared.createPack(name: name)
                await load()
            } catch {
                actionError = error.localizedDescription
            }
        }
    }

    private func addEmoji(from item: PhotosPickerItem?) {
        guard let item, let packID = pendingPackID else {
            pendingPackID = nil
            return
        }
        pendingPackID = nil
        photoItem = nil
        Task {
            do {
                guard let data = try await item.loadTransferable(type: Data.self) else {
                    actionError = "Couldn't read that image."
                    return
                }
                _ = try await EmojiPackStore.shared.addEmoji(
                    packID: packID,
                    name: "emoji",
                    imageData: data
                )
                await load()
            } catch {
                actionError = error.localizedDescription
            }
        }
    }

    private func deleteEmoji(packID: UUID, emojiID: String) async {
        do {
            try await EmojiPackStore.shared.deleteEmoji(packID: packID, emojiID: emojiID)
            await load()
        } catch {
            actionError = error.localizedDescription
        }
    }

    func deletePack(at offsets: IndexSet) {
        for index in offsets {
            let pack = packs[index]
            Task {
                do {
                    try await EmojiPackStore.shared.deletePack(id: pack.id)
                    await load()
                } catch {
                    actionError = error.localizedDescription
                }
            }
        }
    }
}

/// One emoji cell with its decoded image and a delete affordance.
private struct EmojiCell: View {
    let packID: UUID
    let emoji: CustomEmoji
    var onDelete: () -> Void

    @State private var image: UIImage?

    var body: some View {
        ZStack(alignment: .topTrailing) {
            Group {
                if let image {
                    Image(uiImage: image)
                        .resizable()
                        .scaledToFit()
                        .frame(width: 44, height: 44)
                } else {
                    ProgressView()
                        .frame(width: 44, height: 44)
                }
            }
            .frame(width: 56, height: 56)
            .background(AegisColors.surfaceElevated)
            .clipShape(RoundedRectangle(cornerRadius: 10))
            .accessibilityLabel("Custom emoji \(emoji.id)")

            Button(role: .destructive, action: onDelete) {
                Image(systemName: "xmark.circle.fill")
                    .font(.system(size: 18))
                    .foregroundStyle(AegisColors.danger)
                    .background(Circle().fill(AegisColors.background))
            }
            .frame(minWidth: AegisLayout.minTapTarget, minHeight: AegisLayout.minTapTarget)
            .offset(x: 10, y: -10)
            .accessibilityLabel("Delete emoji \(emoji.id)")
        }
        .task {
            let key = ReactionKey.customEmoji(packID: packID, emojiID: emoji.id)
            image = await EmojiPackStore.shared.image(forReactionKey: key)
        }
    }
}

#Preview {
    CustomEmojiPacksView()
}
