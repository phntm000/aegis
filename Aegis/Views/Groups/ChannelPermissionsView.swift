import AegisModeration
import SwiftUI

/// Per-channel permission matrix: which roles may do what in this
/// group/channel. Every change is a signed group event — replicated to
/// members and appended to the hash-chained audit log. Owners/admins only.
struct ChannelPermissionsView: View {
    @StateObject private var viewModel: ChannelPermissionsViewModel
    @EnvironmentObject private var appState: AppState

    @State private var roleForReset: MemberRole?
    @State private var showingSlowMode = false

    init(viewModel: ChannelPermissionsViewModel) {
        _viewModel = StateObject(wrappedValue: viewModel)
    }

    init(conversation: Conversation, appState: AppState) {
        _viewModel = StateObject(wrappedValue: ChannelPermissionsViewModel(
            conversation: conversation, appState: appState
        ))
    }

    var body: some View {
        Group {
            if viewModel.isLoading {
                LoadingOverlayView(label: "Loading permissions…")
            } else if viewModel.snapshot != nil {
                permissionsContent
            } else {
                EmptyStateView(
                    icon: "exclamationmark.triangle",
                    title: "Couldn't load permissions",
                    message: viewModel.error ?? "Something went wrong.",
                    actionTitle: "Retry",
                    action: { Task { @MainActor in await viewModel.load() } }
                )
            }
        }
        .background(AegisColors.background.ignoresSafeArea())
        .navigationTitle("Permissions")
        .navigationBarTitleDisplayMode(.inline)
        .task { @MainActor in await viewModel.load() }
        .sheet(isPresented: $showingSlowMode) {
            SlowModeSheet(viewModel: viewModel)
        }
        .confirmationDialog(
            "Reset \(roleForReset?.displayName ?? "role") permissions?",
            isPresented: Binding(
                get: { roleForReset != nil },
                set: { if !$0 { roleForReset = nil } }
            ),
            titleVisibility: .visible
        ) {
            Button("Reset to defaults", role: .destructive) {
                if let role = roleForReset {
                    Task { @MainActor in await viewModel.resetPermissions(for: role) }
                }
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("Clears this channel's custom permissions for the role and restores the defaults. This is a signed group event.")
        }
        .alert("Permissions", isPresented: Binding(
            get: { viewModel.error != nil },
            set: { if !$0 { viewModel.error = nil } }
        )) {
            Button("OK", role: .cancel) {}
        } message: {
            Text(viewModel.error ?? "")
        }
    }

    // MARK: - Content

    private var permissionsContent: some View {
        List {
            slowModeSection

            ForEach(viewModel.editableRoles, id: \.self) { role in
                roleSection(role)
            }

            Section {
                VStack(alignment: .leading, spacing: AegisLayout.s) {
                    Text("How enforcement works")
                        .font(AegisType.bodyStrong)
                        .foregroundStyle(AegisColors.textPrimary)
                    Text("Every honest client enforces these permissions from the signed group state — there is no server to appeal to. A modified client can ignore them locally, but cannot forge another member's signature to escalate itself; its unauthorized actions are rejected as invalid events and recorded in the audit log.")
                        .font(AegisType.callout)
                        .foregroundStyle(AegisColors.textSecondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                .padding(.vertical, AegisLayout.xs)
            }
        }
        .disabled(!viewModel.canEdit || viewModel.isWorking)
    }

    private var slowModeSection: some View {
        Section {
            Button {
                showingSlowMode = true
            } label: {
                HStack {
                    Label("Slow mode", systemImage: "timer")
                        .foregroundStyle(AegisColors.textPrimary)
                    Spacer()
                    Text(viewModel.slowModeInterval.map(SlowModeEnforcer.label) ?? "Off")
                        .font(AegisType.callout)
                        .foregroundStyle(AegisColors.textSecondary)
                    Image(systemName: "chevron.right")
                        .font(AegisType.caption)
                        .foregroundStyle(AegisColors.textTertiary)
                }
            }
            .accessibilityLabel("Slow mode, \(viewModel.slowModeInterval.map(SlowModeEnforcer.label) ?? "off")")
            .accessibilityHint("Set how often members may post")
        } header: {
            Text("Rate limiting")
        } footer: {
            Text("Owners, admins, and moderators are exempt from slow mode.")
        }
    }

    private func roleSection(_ role: MemberRole) -> some View {
        Section {
            ForEach(GroupPermission.allCases, id: \.self) { permission in
                let granted = viewModel.grants(for: role).contains(permission)
                Toggle(isOn: Binding(
                    get: { granted },
                    set: { newValue in
                        Task { @MainActor in
                            await viewModel.setPermission(permission, granted: newValue, for: role)
                        }
                    }
                )) {
                    VStack(alignment: .leading, spacing: 2) {
                        Text(permission.displayName)
                            .font(AegisType.body)
                            .foregroundStyle(AegisColors.textPrimary)
                        Text(permission.description)
                            .font(AegisType.caption)
                            .foregroundStyle(AegisColors.textSecondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    .padding(.vertical, 2)
                }
                .accessibilityLabel("\(permission.displayName) for \(role.displayName)")
            }
            if viewModel.isOverridden(role) {
                Button(role: .destructive) {
                    roleForReset = role
                } label: {
                    Label("Reset to role defaults", systemImage: "arrow.counterclockwise")
                }
            }
        } header: {
            HStack {
                Text(role.displayName)
                if viewModel.isOverridden(role) {
                    Text("customized")
                        .font(AegisType.caption)
                        .foregroundStyle(AegisColors.accent)
                        .padding(.horizontal, AegisLayout.s)
                        .padding(.vertical, 2)
                        .background(AegisColors.accentSoft)
                        .clipShape(Capsule())
                        .accessibilityLabel("Customized from role defaults")
                }
            }
        }
    }
}

#Preview {
    let appState = AppState(factory: PreviewServiceFactory())
    return NavigationStack {
        ChannelPermissionsView(
            conversation: SampleData.previewConversation(title: "Design sync"),
            appState: appState
        )
        .environmentObject(appState)
    }
}
