import SwiftUI
import UIKit

/// Identity management: fingerprint, QR, invite code, display name, encrypted
/// backup export, and the danger zone. The fingerprint is prominent — it's
/// the root of trust for every safety-number check.
struct IdentitySettingsView: View {
    @StateObject private var viewModel: SettingsViewModel
    @EnvironmentObject private var appState: AppState
    @Environment(\.dismiss) private var dismiss

    @State private var showingRename = false
    @State private var newName = ""
    @State private var showingBackupSheet = false
    @State private var showingDeleteConfirm = false
    @State private var backupData: Data?
    @State private var copied = false

    init(appState: AppState) {
        _viewModel = StateObject(wrappedValue: SettingsViewModel(appState: appState))
    }

    var body: some View {
        List {
            if viewModel.identity == nil, let loadError = viewModel.error {
                // Identity failed to load: surface the failure with a retry
                // instead of an empty header.
                Section {
                    ErrorBannerView(message: loadError, onDismiss: { viewModel.error = nil })
                    Button("Retry") {
                        Task { @MainActor in await viewModel.load() }
                    }
                    .accessibilityLabel("Retry loading identity")
                }
            }

            Section {
                VStack(spacing: AegisLayout.m) {
                    if let identity = viewModel.identity {
                        AvatarView(displayName: identity.displayName, hue: 0.58, size: AegisLayout.avatarXL)
                        HStack(spacing: AegisLayout.xs) {
                            Text(identity.displayName)
                                .font(AegisType.titleSmall)
                                .foregroundStyle(AegisColors.textPrimary)
                            Button("Edit") {
                                newName = identity.displayName
                                showingRename = true
                            }
                            .font(AegisType.callout)
                            .foregroundStyle(AegisColors.accent)
                            .aegisMinimumTapTarget()
                            .accessibilityLabel("Edit display name")
                        }
                        Text(identity.shortHandle)
                            .font(AegisType.caption)
                            .foregroundStyle(AegisColors.textTertiary)
                    }
                    if !viewModel.qrPayload.isEmpty {
                        QRCodeView(payload: viewModel.qrPayload, size: 200)
                    }
                }
                .frame(maxWidth: .infinity)
                .padding(.vertical, AegisLayout.m)
            }

            Section {
                Text(Formatters.groupedFingerprint(viewModel.fingerprint))
                    .font(AegisType.fingerprint)
                    .foregroundStyle(AegisColors.textPrimary)
                    .textSelection(.enabled)
                    .padding(.vertical, AegisLayout.xs)
                    // No label override: the section header says "Fingerprint",
                    // and VoiceOver should read the actual value.
            } header: {
                Text("Fingerprint")
            } footer: {
                Text("Your identity fingerprint. Contacts compare this against what they see for you.")
            }

            Section("Invite code") {
                HStack {
                    Text(viewModel.inviteCode)
                        .font(AegisType.caption)
                        .foregroundStyle(AegisColors.textSecondary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                    Spacer()
                    Button(copied ? "Copied" : "Copy") {
                        UIPasteboard.general.string = viewModel.inviteCode
                        copied = true
                        Haptics.selection()
                        Task { @MainActor in
                            try? await Task.sleep(nanoseconds: 1_500_000_000)
                            await MainActor.run { copied = false }
                        }
                    }
                    .font(AegisType.callout)
                    .foregroundStyle(AegisColors.accent)
                    .aegisMinimumTapTarget()
                    .accessibilityLabel("Copy invite code")
                }
                if !viewModel.inviteCode.isEmpty {
                    ShareLink(item: viewModel.inviteCode, subject: Text("Add me on Aegis")) {
                        Label("Share invite code", systemImage: "square.and.arrow.up")
                    }
                    .accessibilityLabel("Share invite code")
                }
            }

            Section {
                Button {
                    showingBackupSheet = true
                } label: {
                    Label("Export encrypted backup", systemImage: "externaldrive.fill.badge.checkmark")
                }
                .accessibilityHint("Exports your identity encrypted with a passphrase")
            } header: {
                Text("Backup")
            } footer: {
                Text("The backup is encrypted with a passphrase you choose. Without it, the file is useless — to anyone.")
            }

            if let backupData {
                Section {
                    ShareLink(item: backupData,
                              preview: SharePreview("Aegis encrypted backup",
                                                    image: Image(systemName: "lock.fill"))) {
                        Label("Save backup file", systemImage: "square.and.arrow.up")
                    }
                }
            }

            Section {
                Button(role: .destructive) {
                    showingDeleteConfirm = true
                } label: {
                    Label("Delete identity", systemImage: "trash.fill")
                }
            } header: {
                Text("Danger zone")
            } footer: {
                Text("Deletes your identity key and all local data, then returns to onboarding. Export a backup first if you want to keep anything.")
            }
        }
        .navigationTitle("Identity")
        .navigationBarTitleDisplayMode(.inline)
        .task { @MainActor in
            await viewModel.load()
        }
        .alert("Edit display name", isPresented: $showingRename) {
            TextField("Display name", text: $newName)
            Button("Save") {
                Task { @MainActor in
                    let trimmed = newName.trimmingCharacters(in: .whitespacesAndNewlines)
                    if !trimmed.isEmpty {
                        _ = try? await appState.crypto.updateDisplayName(trimmed)
                        await viewModel.load()
                    }
                }
            }
            Button("Cancel", role: .cancel) {}
        }
        .sheet(isPresented: $showingBackupSheet) {
            BackupExportSheet { passphrase in
                backupData = await viewModel.exportBackup(passphrase: passphrase)
                showingBackupSheet = false
            }
        }
        .confirmationDialog("Delete your identity?", isPresented: $showingDeleteConfirm, titleVisibility: .visible) {
            Button("Delete everything", role: .destructive) {
                Task { @MainActor in await viewModel.deleteIdentity() }
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("This wipes your key, conversations, and contacts from this device. It can't be undone without a backup.")
        }
    }
}

/// Passphrase prompt for the encrypted backup export.
private struct BackupExportSheet: View {
    var onExport: (String) async -> Void
    @State private var passphrase = ""
    @State private var isWorking = false
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    SecureField("Backup passphrase", text: $passphrase)
                        .textContentType(.newPassword)
                        .accessibilityLabel("Backup passphrase")
                } header: {
                    EmptyView()
                } footer: {
                    Text("Choose a strong passphrase. You'll need it to restore this backup.")
                }
                Section {
                    Button {
                        Task { @MainActor in
                            isWorking = true
                            await onExport(passphrase)
                            isWorking = false
                        }
                    } label: {
                        HStack {
                            if isWorking { ProgressView() }
                            Text(isWorking ? "Encrypting…" : "Export backup")
                        }
                    }
                    .disabled(passphrase.count < 8 || isWorking)
                }
            }
            .navigationTitle("Encrypted backup")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
            }
        }
        .presentationDetents([.medium])
    }
}

#Preview {
    let appState = AppState(factory: PreviewServiceFactory())
    return NavigationStack {
        IdentitySettingsView(appState: appState)
            .environmentObject(appState)
    }
}
