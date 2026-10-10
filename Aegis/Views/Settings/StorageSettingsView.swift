import SwiftUI

/// Storage management: usage breakdown and cache clearing. Messages are
/// never deleted by "clear caches" — only derived data (thumbnails, staged
/// ciphertext, downloaded blobs that can be re-fetched).
struct StorageSettingsView: View {
    @StateObject private var viewModel: SettingsViewModel
    @EnvironmentObject private var appState: AppState
    @State private var showingClearConfirm = false

    init(appState: AppState) {
        _viewModel = StateObject(wrappedValue: SettingsViewModel(appState: appState))
    }

    var body: some View {
        List {
            Section("Usage") {
                if viewModel.isLoadingStorage {
                    HStack {
                        ProgressView().tint(AegisColors.accent)
                        Text("Measuring…")
                            .font(AegisType.callout)
                            .foregroundStyle(AegisColors.textSecondary)
                    }
                } else if let usage = viewModel.storageUsage {
                    usageBar(usage)
                    usageRow(label: "Messages", bytes: usage.messagesBytes, color: AegisColors.accent)
                    usageRow(label: "Attachments", bytes: usage.attachmentsBytes, color: Color.purple)
                    usageRow(label: "Voice notes", bytes: usage.voiceNotesBytes, color: AegisColors.success)
                    HStack {
                        Text("Total")
                            .font(AegisType.bodyStrong)
                            .foregroundStyle(AegisColors.textPrimary)
                        Spacer()
                        Text(Formatters.bytes(usage.totalBytes))
                            .font(AegisType.bodyStrong)
                            .foregroundStyle(AegisColors.textPrimary)
                            .accessibilityLabel("Total storage: \(Formatters.bytes(usage.totalBytes))")
                    }
                } else {
                    Text("Couldn't measure storage.")
                        .font(AegisType.callout)
                        .foregroundStyle(AegisColors.textSecondary)
                }
            }

            Section {
                Button {
                    showingClearConfirm = true
                } label: {
                    Label("Clear caches", systemImage: "trash")
                }
                .accessibilityHint("Removes thumbnails and temporary files. Messages are kept.")
            } header: {
                EmptyView()
            } footer: {
                Text("Clears thumbnails, staged uploads, and downloaded files that can be re-fetched. Your messages, contacts, and identity are untouched.")
            }
        }
        .navigationTitle("Storage")
        .navigationBarTitleDisplayMode(.inline)
        .task { @MainActor in
            await viewModel.loadStorage()
        }
        .confirmationDialog("Clear caches?", isPresented: $showingClearConfirm, titleVisibility: .visible) {
            Button("Clear caches", role: .destructive) {
                Task { @MainActor in await viewModel.clearCaches() }
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("Frees space without deleting messages, contacts, or your identity.")
        }
    }

    private func usageBar(_ usage: StorageUsage) -> some View {
        GeometryReader { geometry in
            let total = max(1, usage.totalBytes)
            HStack(spacing: 2) {
                RoundedRectangle(cornerRadius: 3)
                    .fill(AegisColors.accent)
                    .frame(width: geometry.size.width * CGFloat(usage.messagesBytes) / CGFloat(total))
                RoundedRectangle(cornerRadius: 3)
                    .fill(Color.purple)
                    .frame(width: geometry.size.width * CGFloat(usage.attachmentsBytes) / CGFloat(total))
                RoundedRectangle(cornerRadius: 3)
                    .fill(AegisColors.success)
                    .frame(width: geometry.size.width * CGFloat(usage.voiceNotesBytes) / CGFloat(total))
            }
        }
        .frame(height: 10)
        .padding(.vertical, AegisLayout.xs)
        .accessibilityHidden(true)
    }

    private func usageRow(label: String, bytes: Int64, color: Color) -> some View {
        HStack {
            Circle().fill(color).frame(width: 10, height: 10).accessibilityHidden(true)
            Text(label)
                .font(AegisType.body)
                .foregroundStyle(AegisColors.textPrimary)
            Spacer()
            Text(Formatters.bytes(bytes))
                .font(AegisType.callout)
                .foregroundStyle(AegisColors.textSecondary)
        }
        .accessibilityLabel("\(label): \(Formatters.bytes(bytes))")
    }
}

#Preview {
    let appState = AppState(factory: PreviewServiceFactory())
    return NavigationStack {
        StorageSettingsView(appState: appState)
            .environmentObject(appState)
    }
}
