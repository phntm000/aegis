import AegisModeration
import Foundation

/// The message-requests inbox: first contact from unknown identities.
/// No receipts/typing/presence leak to senders until a request is accepted.
@MainActor
final class MessageRequestsViewModel: ObservableObject {
    @Published private(set) var requests: [MessageRequestItem] = []
    @Published var error: String?
    @Published var isWorking = false
    /// Request awaiting a block/report decision in the confirmation UI.
    @Published var pendingDecision: MessageRequestItem?

    private let appState: AppState
    nonisolated(unsafe) private var observer: NSObjectProtocol?

    init(appState: AppState) {
        self.appState = appState
    }

    deinit {
        if let observer {
            NotificationCenter.default.removeObserver(observer)
        }
    }

    func start() {
        refresh()
        guard observer == nil else { return }
        observer = NotificationCenter.default.addObserver(
            forName: .aegisMessageRequests,
            object: nil,
            queue: .main
        ) { [weak self] _ in
            guard let self else { return }
            Task { @MainActor in self.refresh() }
        }
    }

    func stop() {
        if let observer {
            NotificationCenter.default.removeObserver(observer)
            self.observer = nil
        }
    }

    var isEmpty: Bool { requests.isEmpty }

    func refresh() {
        requests = appState.messageRequests
    }

    func accept(_ item: MessageRequestItem) async {
        isWorking = true
        defer { isWorking = false }
        await appState.acceptMessageRequest(item)
        refresh()
    }

    func block(_ item: MessageRequestItem) async {
        isWorking = true
        defer { isWorking = false }
        await appState.blockMessageRequest(item)
        refresh()
    }

    func report(_ item: MessageRequestItem, reason: ReportReason, detail: String?) async {
        isWorking = true
        defer { isWorking = false }
        await appState.blockMessageRequest(item, report: (reason: reason, detail: detail))
        refresh()
    }

    /// Thread preview for a request (read-only until accepted).
    func messages(for item: MessageRequestItem) async -> [Message] {
        (try? await appState.store.fetchMessages(conversationID: item.conversationID, limit: 50, before: nil)) ?? []
    }
}
