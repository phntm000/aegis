import AegisModeration
import SwiftUI

/// The per-group admin audit log: every administrative action — member
/// add/remove, role change, permission edit, slow-mode change, invite
/// issued/revoked, announcement flips, join approvals — as signed,
/// hash-chained entries. Anyone can verify the chain; gaps are detectable.
///
/// The log contains administrative events only — never message content.
/// It replicates to members sealed inside group control messages, never
/// to the relay in plaintext.
struct AuditLogView: View {
    @ObservedObject var viewModel: ChannelPermissionsViewModel
    @EnvironmentObject private var appState: AppState

    @State private var exportURL: URL?

    var body: some View {
        Group {
            if viewModel.isLoading {
                LoadingOverlayView(label: "Loading audit log…")
            } else {
                auditContent
            }
        }
        .background(AegisColors.background.ignoresSafeArea())
        .navigationTitle("Audit log")
        .navigationBarTitleDisplayMode(.inline)
        .task { @MainActor in await viewModel.load() }
        .toolbar {
            if viewModel.canEdit, !viewModel.auditEvents.isEmpty {
                ToolbarItem(placement: .primaryAction) {
                    Button {
                        exportURL = viewModel.makeAuditExport()
                        Task { @MainActor in await viewModel.noteAuditExported() }
                    } label: {
                        Label("Export", systemImage: "square.and.arrow.up")
                    }
                    .accessibilityLabel("Export audit log")
                    .accessibilityHint("Shares the signed audit log as JSON. The export itself is logged.")
                }
            }
        }
        .sheet(isPresented: Binding(
            get: { exportURL != nil },
            set: { if !$0 { exportURL = nil } }
        )) {
            if let url = exportURL {
                ShareLink(item: url) {
                    Label("Share audit log", systemImage: "square.and.arrow.up")
                }
                .presentationDetents([.medium])
            }
        }
    }

    private var auditContent: some View {
        List {
            verificationSection

            if viewModel.auditEvents.isEmpty {
                Section {
                    EmptyStateView(
                        icon: "scroll",
                        title: "No admin actions yet",
                        message: "Role changes, permission edits, slow-mode changes, and other administrative actions will appear here as signed events."
                    )
                    .frame(minHeight: 300)
                    .listRowBackground(Color.clear)
                }
            } else {
                Section("Events (\(viewModel.auditEvents.count))") {
                    ForEach(viewModel.auditEvents.reversed(), id: \.seq) { entry in
                        AuditEventRow(entry: entry)
                    }
                }
            }
        }
    }

    private var verificationSection: some View {
        Section {
            HStack(spacing: AegisLayout.m) {
                verificationIcon
                VStack(alignment: .leading, spacing: 2) {
                    Text(verificationTitle)
                        .font(AegisType.bodyStrong)
                        .foregroundStyle(AegisColors.textPrimary)
                    Text(verificationDetail)
                        .font(AegisType.caption)
                        .foregroundStyle(AegisColors.textSecondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            .padding(.vertical, AegisLayout.xs)
            .accessibilityElement(children: .combine)
            .accessibilityLabel("Audit log verification: \(verificationTitle)")
        }
    }

    private var verificationIcon: some View {
        Group {
            switch viewModel.auditVerification {
            case .ok:
                Image(systemName: "checkmark.seal.fill")
                    .foregroundStyle(AegisColors.success)
            case .empty, .none:
                Image(systemName: "seal")
                    .foregroundStyle(AegisColors.textTertiary)
            default:
                Image(systemName: "exclamationmark.triangle.fill")
                    .foregroundStyle(AegisColors.danger)
            }
        }
        .font(.system(size: 28))
        .accessibilityHidden(true)
    }

    private var verificationTitle: String {
        switch viewModel.auditVerification {
        case .ok(let count): return "Verified · \(count) events"
        case .empty, .none: return "No entries to verify"
        case .brokenChain(let at): return "Chain broken at event \(at)"
        case .badSignature(let at): return "Bad signature at event \(at)"
        case .unknownActorKey(let at): return "Unknown signer at event \(at)"
        }
    }

    private var verificationDetail: String {
        switch viewModel.auditVerification {
        case .ok:
            return "Every entry's signature verified and the hash chain is unbroken."
        case .empty, .none:
            return "The log is empty."
        case .brokenChain:
            return "Entries were removed, reordered, or altered. Treat later entries as untrusted."
        case .badSignature:
            return "An entry's signature does not verify against the signer's key."
        case .unknownActorKey:
            return "No public key is known for the signer — they may have left the group."
        }
    }
}

/// One audit-log row: what happened, who did it, to whom, when.
struct AuditEventRow: View {
    let entry: SignedGroupEvent

    var body: some View {
        HStack(spacing: AegisLayout.m) {
            Image(systemName: entry.event.kind.systemImage)
                .font(.system(size: 20))
                .foregroundStyle(AegisColors.accent)
                .frame(width: 32)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 2) {
                Text(entry.event.kind.displayName)
                    .font(AegisType.body)
                    .foregroundStyle(AegisColors.textPrimary)
                Text(summary)
                    .font(AegisType.caption)
                    .foregroundStyle(AegisColors.textSecondary)
                    .fixedSize(horizontal: false, vertical: true)
                Text(entry.event.occurredAt, style: .relative)
                    .font(AegisType.caption)
                    .foregroundStyle(AegisColors.textTertiary)
            }
            Spacer()
        }
        .padding(.vertical, AegisLayout.xs)
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(entry.event.kind.displayName). \(summary)")
    }

    private var summary: String {
        var parts: [String] = []
        if let actor = entry.event.actorDisplayName, !actor.isEmpty {
            parts.append("by \(actor)")
        } else {
            parts.append("by ···" + entry.event.actorFingerprint.suffix(4).hexString)
        }
        if let target = entry.event.targetDisplayName, !target.isEmpty {
            parts.append("→ \(target)")
        } else if let targetFP = entry.event.targetFingerprint {
            parts.append("→ ···" + targetFP.suffix(4).hexString)
        }
        if let detail = entry.event.detail, !detail.isEmpty {
            parts.append("· \(detail)")
        }
        return parts.joined(separator: " ")
    }
}

#Preview {
    let appState = AppState(factory: PreviewServiceFactory())
    let vm = ChannelPermissionsViewModel(
        conversation: SampleData.previewConversation(title: "Design sync"),
        appState: appState
    )
    return NavigationStack {
        AuditLogView(viewModel: vm)
            .environmentObject(appState)
    }
}
