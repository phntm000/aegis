import SwiftUI

/// The four-tab shell: Chats, Contacts, Calls, Settings.
/// The chats tab badge reflects the live unread count.
struct MainTabView: View {
    @EnvironmentObject private var appState: AppState
    @StateObject private var chatListViewModel: ChatListViewModel

    @State private var selection: Tab = .chats

    enum Tab: Hashable {
        case chats
        case contacts
        case calls
        case settings
    }

    init(appState: AppState) {
        _chatListViewModel = StateObject(wrappedValue: ChatListViewModel(appState: appState))
    }

    var body: some View {
        TabView(selection: $selection) {
            ChatListView(viewModel: chatListViewModel)
                .tabItem {
                    Label("Chats", systemImage: "bubble.left.and.bubble.right.fill")
                }
                .tag(Tab.chats)
                .badge(badgeText)

            ContactsView(appState: appState)
                .tabItem {
                    Label("Contacts", systemImage: "person.2.fill")
                }
                .tag(Tab.contacts)

            CallHistoryView(appState: appState)
                .tabItem {
                    Label("Calls", systemImage: "phone.fill")
                }
                .tag(Tab.calls)

            SettingsView(appState: appState)
                .tabItem {
                    Label("Settings", systemImage: "gearshape.fill")
                }
                .tag(Tab.settings)
        }
        .tint(AegisColors.accent)
    }

    /// Unread badge; nil hides the badge entirely.
    private var badgeText: Text? {
        chatListViewModel.totalUnread > 0 ? Text("\(chatListViewModel.totalUnread)") : nil
    }
}

#Preview {
    let appState = AppState(factory: PreviewServiceFactory())
    return MainTabView(appState: appState)
        .environmentObject(appState)
}
