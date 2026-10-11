import AegisModeration
import SwiftUI

/// Message-requests inbox: first contact from unknown identities. The
/// sender gets no read receipts, typing indicators, or presence until the
/// request is accepted. One-tap accept / block / report.
struct MessageRequestsView: View {
    @StateObject private var viewModel: MessageRequestsViewModel
    @EnvironmentObject private var appState: AppState

    @State private var selectedRequest: MessageRequestItem?
    @State private var reportingRequest: MessageRequestItem?

    init(appState: AppState) {
        _viewModel = StateObject(wrappedValue: MessageRequestsViewModel(appState: appState))
    }

    var body: some View {
        Group {
            if viewModel.isEmpty {
                EmptyStateView(
                    icon: "tray.and.arrow.down",
                    title: "No message requests",
                    message: "Messages from people you haven't contacted will appear here. They can't see when you're online, typing, or reading until you accept."
                )
            } else {
                List(viewModel.requests) { request in
                    MessageRequestRow(
                        request: request,
                        onSelect: { selectedRequest = request },
                        onAccept: { Task { @MainActor in await viewModel.accept(request) } },
                        onBlock: { viewModel.pendingDecision = request },
                        onReport: { reportingRequest = request }
                    )
                }
            }
        }
        .background(AegisColors.background.ignoresSafeArea())
        .navigationTitle("Message requests")
        .navigationBarTitleDisplayMode(.inline)
        .onAppear { viewModel.start() }
        .onDisappear { viewModel.stop() }
        .sheet(item: $selectedRequest) { request in
            MessageRequestDetailView(request: request, viewModel: viewModel)
                .environmentObject(appState)
        }
        .sheet(item: $reportingRequest) { request in
            ReportSheet(
                subjectName: request.displayName,
                onReport: { reason, detail in
                    Task { @MainActor in await viewModel.report(request, reason: reason, detail: detail) }
                }
            )
        }
        .confirmationDialog(
            "Block this sender?",
            isPresented: Binding(
                get: { viewModel.pendingDecision != nil },
                set: { if !$0 { viewModel.pendingDecision = nil } }
            ),
            titleVisibility: .visible
        ) {
            Button("Block", role: .destructive) {
                if let request = viewModel.pendingDecision {
                    Task { @MainActor in await viewModel.block(request) }
                }
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("Blocking is local and silent — they won't be told. You won't receive any more messages from them.")
        }
        .disabled(viewModel.isWorking)
    }
}

/// One request row: sender, preview, and accept/block/report actions.
struct MessageRequestRow: View {
    let request: MessageRequestItem
    var onSelect: () -> Void
    var onAccept: () -> Void
    var onBlock: () -> Void
    var onReport: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: AegisLayout.s) {
            Button(action: onSelect) {
                HStack(spacing: AegisLayout.m) {
                    AvatarView(displayName: request.displayName, size: AegisLayout.avatarS)
                    VStack(alignment: .leading, spacing: 2) {
                        Text(request.displayName)
                            .font(AegisType.bodyStrong)
                            .foregroundStyle(AegisColors.textPrimary)
                            .lineLimit(1)
                        if let preview = request.preview, !preview.isEmpty {
                            Text(preview)
                                .font(AegisType.callout)
                                .foregroundStyle(AegisColors.textSecondary)
                                .lineLimit(2)
                        }
                        Text(request.receivedAt, style: .relative)
                            .font(AegisType.caption)
                            .foregroundStyle(AegisColors.textTertiary)
                    }
                    Spacer()
                    if request.messageCount > 1 {
                        Text("\(request.messageCount)")
                            .font(AegisType.captionStrong)
                            .foregroundStyle(AegisColors.textOnAccent)
                            .padding(.horizontal, AegisLayout.s)
                            .padding(.vertical, 2)
                            .background(AegisColors.accent)
                            .clipShape(Capsule())
                            .accessibilityLabel("\(request.messageCount) messages")
                    }
                }
            }
            .accessibilityLabel("Message request from \(request.displayName)")

            HStack(spacing: AegisLayout.s) {
                Button("Accept") { onAccept() }
                    .buttonStyle(.borderedProminent)
                    .tint(AegisColors.accent)
                    .frame(maxWidth: .infinity)
                    .accessibilityHint("Move this conversation to your chats")
                Button("Block") { onBlock() }
                    .buttonStyle(.bordered)
                    .tint(AegisColors.textSecondary)
                    .frame(maxWidth: .infinity)
                Button("Report") { onReport() }
                    .buttonStyle(.bordered)
                    .tint(AegisColors.danger)
                    .frame(maxWidth: .infinity)
            }
            .frame(minHeight: AegisLayout.minTapTarget)
            .font(AegisType.body)
        }
        .padding(.vertical, AegisLayout.xs)
    }
}

/// Read-only thread for a request, with the accept/block/report decision bar.
struct MessageRequestDetailView: View {
    let request: MessageRequestItem
    @ObservedObject var viewModel: MessageRequestsViewModel
    @EnvironmentObject private var appState: AppState
    @Environment(\.dismiss) private var dismiss

    @State private var messages: [Message] = []
    @State private var isLoading = true
    @State private var reporting = false

    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                if isLoading {
                    LoadingOverlayView(label: "Loading messages…")
                } else if messages.isEmpty {
                    EmptyStateView(
                        icon: "bubble.left",
                        title: "No messages",
                        message: "The messages for this request couldn't be loaded."
                    )
                } else {
                    List(messages) { message in
                        VStack(alignment: .leading, spacing: 2) {
                            Text(message.body ?? "")
                                .font(AegisType.body)
                                .foregroundStyle(AegisColors.textPrimary)
                                .fixedSize(horizontal: false, vertical: true)
                            Text(message.sentAt, style: .time)
                                .font(AegisType.caption)
                                .foregroundStyle(AegisColors.textTertiary)
                        }
                        .padding(.vertical, AegisLayout.xs)
                    }
                    .listStyle(.plain)
                }

                VStack(spacing: AegisLayout.s) {
                    Text("They can't see your online status, typing, or read receipts until you accept.")
                        .font(AegisType.caption)
                        .foregroundStyle(AegisColors.textSecondary)
                        .multilineTextAlignment(.center)
                        .fixedSize(horizontal: false, vertical: true)
                    HStack(spacing: AegisLayout.s) {
                        Button("Accept") {
                            Task { @MainActor in
                                await viewModel.accept(request)
                                dismiss()
                            }
                        }
                        .buttonStyle(.borderedProminent)
                        .tint(AegisColors.accent)
                        .frame(maxWidth: .infinity)
                        Button("Block") {
                            Task { @MainActor in
                                await viewModel.block(request)
                                dismiss()
                            }
                        }
                        .buttonStyle(.bordered)
                        .tint(AegisColors.textSecondary)
                        .frame(maxWidth: .infinity)
                        Button("Report") { reporting = true }
                            .buttonStyle(.bordered)
                            .tint(AegisColors.danger)
                            .frame(maxWidth: .infinity)
                    }
                    .frame(minHeight: AegisLayout.minTapTarget)
                }
                .padding(AegisLayout.m)
                .background(AegisColors.surface)
            }
            .background(AegisColors.background.ignoresSafeArea())
            .navigationTitle(request.displayName)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Close") { dismiss() }
                }
            }
            .task {
                messages = await viewModel.messages(for: request).sorted { $0.sentAt < $1.sentAt }
                isLoading = false
            }
            .sheet(isPresented: $reporting) {
                ReportSheet(
                    subjectName: request.displayName,
                    onReport: { reason, detail in
                        Task { @MainActor in
                            await viewModel.report(request, reason: reason, detail: detail)
                            dismiss()
                        }
                    }
                )
            }
        }
    }
}

#Preview {
    let appState = AppState(factory: PreviewServiceFactory())
    return NavigationStack {
        MessageRequestsView(appState: appState)
            .environmentObject(appState)
    }
}
