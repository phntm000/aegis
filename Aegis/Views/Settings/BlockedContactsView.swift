import AegisModeration
import SwiftUI

/// Blocked identities. Blocking is local and silent: blocked senders are
/// never told, their messages are dropped on receipt, and they get no
/// presence signals. Unblocking restores normal delivery for future
/// messages (nothing sent while blocked is recovered).
struct BlockedContactsView: View {
    @EnvironmentObject private var appState: AppState

    @State private var blocked: [(fingerprint: Data, name: String)] = []
    @State private var isLoading = true
    @State private var fingerprintToUnblock: Data?

    var body: some View {
        Group {
            if isLoading {
                LoadingOverlayView(label: "Loading blocked list…")
            } else if blocked.isEmpty {
                EmptyStateView(
                    icon: "person.slash",
                    title: "Nobody blocked",
                    message: "Blocked senders appear here. Blocking is local and silent — they are never told, and their messages are dropped without a trace."
                )
            } else {
                List {
                    Section {
                        ForEach(blocked, id: \.fingerprint) { entry in
                            HStack {
                                AvatarView(displayName: entry.name, size: AegisLayout.avatarS)
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(entry.name)
                                        .font(AegisType.body)
                                        .foregroundStyle(AegisColors.textPrimary)
                                        .lineLimit(1)
                                    Text("···" + entry.fingerprint.suffix(8).hexString)
                                        .font(AegisType.fingerprint)
                                        .foregroundStyle(AegisColors.textTertiary)
                                }
                                Spacer()
                                Button("Unblock") {
                                    fingerprintToUnblock = entry.fingerprint
                                }
                                .buttonStyle(.bordered)
                                .tint(AegisColors.accent)
                            }
                            .padding(.vertical, AegisLayout.xs)
                            .accessibilityLabel("Blocked: \(entry.name)")
                        }
                    } footer: {
                        Text("Unblocking restores delivery for future messages. Messages sent while blocked were dropped and are not recovered.")
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
            }
        }
        .background(AegisColors.background.ignoresSafeArea())
        .navigationTitle("Blocked")
        .navigationBarTitleDisplayMode(.inline)
        .task { await load() }
        .confirmationDialog(
            "Unblock this sender?",
            isPresented: Binding(
                get: { fingerprintToUnblock != nil },
                set: { if !$0 { fingerprintToUnblock = nil } }
            ),
            titleVisibility: .visible
        ) {
            Button("Unblock") {
                if let fp = fingerprintToUnblock {
                    appState.unblock(fingerprint: fp)
                    Task { await load() }
                }
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("They'll be able to message you again. Nothing notifies them either way.")
        }
    }

    @MainActor
    private func load() async {
        isLoading = true
        defer { isLoading = false }
        let fingerprints = appState.blockedFingerprints()
        // Resolve names via contacts where possible.
        let contacts = (try? await appState.store.fetchContacts()) ?? []
        blocked = fingerprints.map { fp in
            let name = contacts.first {
                AppState.fingerprint(ofSerializedIdentity: $0.identityKey) == fp
                    || $0.identityKey == fp
            }?.displayName ?? "Unknown contact"
            return (fingerprint: fp, name: name)
        }
    }
}

#Preview {
    let appState = AppState(factory: PreviewServiceFactory())
    return NavigationStack {
        BlockedContactsView()
            .environmentObject(appState)
    }
}
