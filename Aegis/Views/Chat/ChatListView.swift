import SwiftUI

/// The chat list: pinned / recents sections, search, archived, swipe actions,
/// and the new-conversation menu. Pull-to-refresh reloads from the store.
struct ChatListView: View {
    @ObservedObject var viewModel: ChatListViewModel
    @EnvironmentObject private var appState: AppState

    @State private var navigationPath = NavigationPath()
    @State private var showingNewGroup = false
    @State private var showingNewChannel = false
    @State private var showingJoinGroup = false
    @State private var showingAddContact = false
    @State private var conversationToDelete: Conversation?

    var body: some View {
        NavigationStack(path: $navigationPath) {
            mainContent
        }
        .background(AegisColors.background.ignoresSafeArea())
        .navigationTitle("Chats")
        .navigationBarTitleDisplayMode(.large)
            .searchable(text: $viewModel.searchText, prompt: "Search conversations")
            .toolbar {
                toolbarContent
            }
            .navigationDestination(for: Conversation.self) { conversation in
                ConversationView(
                    conversation: conversation,
                    contact: viewModel.contact(for: conversation),
                    appState: appState
                )
            }
            .navigationDestination(for: ArchivedDestination.self) { _ in
                ArchivedChatsView(viewModel: viewModel, navigationPath: $navigationPath)
            }
            .sheet(isPresented: $showingNewGroup) {
                NewGroupView(onCreated: { conversation in
                    Task { @MainActor in
                        await viewModel.load()
                        navigationPath.append(conversation)
                    }
                })
            }
            .sheet(isPresented: $showingNewChannel) {
                NewChannelView(onCreated: { conversation in
                    Task { @MainActor in
                        await viewModel.load()
                        navigationPath.append(conversation)
                    }
                })
            }
            .sheet(isPresented: $showingAddContact) {
                AddContactView(appState: appState, onAdded: { conversation in
                    Task { @MainActor in
                        await viewModel.load()
                        if let conversation { navigationPath.append(conversation) }
                    }
                })
            }
            .sheet(isPresented: $showingJoinGroup) {
                JoinGroupView()
            }
            .confirmationDialog(
                "Delete this conversation?",
                isPresented: Binding(
                    get: { conversationToDelete != nil },
                    set: { if !$0 { conversationToDelete = nil } }
                ),
                titleVisibility: .visible
            ) {
                Button("Delete", role: .destructive) {
                    if let conversation = conversationToDelete {
                        Task { @MainActor in await viewModel.delete(conversation) }
                    }
                }
            } message: {
                Text("Message history on this device will be removed. This can't be undone.")
            }
            .onAppear {
                // Reload on every appearance so previews, unread counts, and
                // ordering stay fresh when returning from a conversation.
                Task { @MainActor in
                    await viewModel.load()
                }
            }
            .refreshable { @MainActor in
                await viewModel.load()
            }
        }

    // MARK: - List

    @MainActor
    private var mainContent: some View {
        VStack(spacing: 0) {
            ConnectionBannerView()
            listStateContent
        }
    }

    @MainActor
    private var listStateContent: some View {
        Group {
            if viewModel.isLoading {
                LoadingOverlayView(label: "Loading conversations…")
            } else if viewModel.isEmpty && viewModel.searchText.isEmpty {
                EmptyStateView(
                    icon: "bubble.left.and.bubble.right",
                    title: "No conversations yet",
                    message: "Add a contact to start your first end-to-end encrypted conversation.",
                    actionTitle: "Add contact",
                    action: { showingAddContact = true }
                )
            } else if viewModel.pinned.isEmpty && viewModel.recents.isEmpty
                        && viewModel.archived.isEmpty && !viewModel.searchText.isEmpty {
                EmptyStateView(
                    icon: "magnifyingglass",
                    title: "No results",
                    message: "No conversations match \"\(viewModel.searchText)\"."
                )
            } else {
                chatList
            }
        }
    }

    @ToolbarContentBuilder
    private var toolbarContent: some ToolbarContent {
        ToolbarItem(placement: .primaryAction) {
            Menu {
                Button {
                    showingAddContact = true
                } label: {
                    Label("New direct message", systemImage: "person.fill.badge.plus")
                }
                Button {
                    showingNewGroup = true
                } label: {
                    Label("New group", systemImage: "person.2.fill")
                }
                Button {
                    showingNewChannel = true
                } label: {
                    Label("New channel", systemImage: "megaphone.fill")
                }
                Button {
                    showingJoinGroup = true
                } label: {
                    Label("Join with invite code", systemImage: "qrcode.viewfinder")
                }
            } label: {
                Image(systemName: "square.and.pencil")
                    .accessibilityLabel("New conversation")
            }
        }
    }

    private var chatList: some View {
        List {
            if !viewModel.pinned.isEmpty {
                Section("Pinned") {
                    ForEach(viewModel.pinned) { conversation in
                        row(for: conversation)
                    }
                }
            }

            Section {
                ForEach(viewModel.recents) { conversation in
                    row(for: conversation)
                }
            } header: {
                if !viewModel.pinned.isEmpty { Text("Chats") }
            } footer: {
                EmptyView()
            }

            if !viewModel.archived.isEmpty {
                Section {
                    NavigationLink(value: ArchivedDestination()) {
                        Label("Archived", systemImage: "archivebox.fill")
                            .badge(viewModel.archived.count)
                    }
                }
            }
        }
        .listStyle(.insetGrouped)
        .scrollContentBackground(.hidden)
    }

    private func row(for conversation: Conversation) -> some View {
        NavigationLink(value: conversation) {
            ConversationRowView(
                conversation: conversation,
                contact: viewModel.contact(for: conversation)
            )
        }
        .swipeActions(edge: .leading) {
            Button {
                Task { @MainActor in await viewModel.togglePin(conversation) }
            } label: {
                Label(conversation.isPinned ? "Unpin" : "Pin",
                      systemImage: conversation.isPinned ? "pin.slash.fill" : "pin.fill")
            }
            .tint(AegisColors.accent)
        }
        .swipeActions(edge: .trailing) {
            Button(role: .destructive) {
                conversationToDelete = conversation
            } label: {
                Label("Delete", systemImage: "trash.fill")
            }
            Button {
                Task { @MainActor in await viewModel.toggleArchive(conversation) }
            } label: {
                Label("Archive", systemImage: "archivebox.fill")
            }
            .tint(AegisColors.warning)
            Button {
                Task { @MainActor in await viewModel.toggleMute(conversation) }
            } label: {
                Label(conversation.isMuted ? "Unmute" : "Mute",
                      systemImage: conversation.isMuted ? "bell.fill" : "bell.slash.fill")
            }
            .tint(AegisColors.textTertiary)
        }
        .contextMenu {
            Button {
                Task { @MainActor in await viewModel.togglePin(conversation) }
            } label: {
                Label(conversation.isPinned ? "Unpin" : "Pin",
                      systemImage: conversation.isPinned ? "pin.slash" : "pin")
            }
            Button {
                Task { @MainActor in await viewModel.toggleMute(conversation) }
            } label: {
                Label(conversation.isMuted ? "Unmute" : "Mute",
                      systemImage: conversation.isMuted ? "bell" : "bell.slash")
            }
            if conversation.unreadCount > 0 {
                Button {
                    Task { @MainActor in await viewModel.markAsRead(conversation) }
                } label: {
                    Label("Mark as read", systemImage: "envelope.open")
                }
            }
            Button(role: .destructive) {
                conversationToDelete = conversation
            } label: {
                Label("Delete", systemImage: "trash")
            }
        }
    }
}

/// Marker type for the archived-chats navigation destination.
private struct ArchivedDestination: Hashable {}

/// Archived conversations with restore.
private struct ArchivedChatsView: View {
    @ObservedObject var viewModel: ChatListViewModel
    @Binding var navigationPath: NavigationPath

    var body: some View {
        Group {
            if viewModel.archived.isEmpty {
                EmptyStateView(
                    icon: "archivebox",
                    title: "Nothing archived",
                    message: "Archived conversations will appear here."
                )
            } else {
                List {
                    ForEach(viewModel.archived) { conversation in
                        NavigationLink(value: conversation) {
                            ConversationRowView(
                                conversation: conversation,
                                contact: viewModel.contact(for: conversation)
                            )
                        }
                        .swipeActions(edge: .trailing) {
                            Button {
                                Task { @MainActor in await viewModel.toggleArchive(conversation) }
                            } label: {
                                Label("Unarchive", systemImage: "archivebox.fill")
                            }
                            .tint(AegisColors.accent)
                        }
                    }
                }
                .listStyle(.insetGrouped)
                .scrollContentBackground(.hidden)
            }
        }
        .background(AegisColors.background.ignoresSafeArea())
        .navigationTitle("Archived")
        .navigationBarTitleDisplayMode(.inline)
    }
}

#Preview {
    let appState = AppState(factory: PreviewServiceFactory())
    return ChatListView(viewModel: ChatListViewModel(appState: appState))
        .environmentObject(appState)
}
