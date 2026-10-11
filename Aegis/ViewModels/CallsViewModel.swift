import Foundation

/// Call history list.
@MainActor
final class CallsViewModel: ObservableObject {
    @Published private(set) var records: [CallRecord] = []
    @Published private(set) var isLoading = true
    @Published var error: String?
    @Published var showingClearConfirmation = false

    private let appState: AppState

    init(appState: AppState) {
        self.appState = appState
    }

    var isEmpty: Bool { records.isEmpty }

    func load() async {
        isLoading = true
        error = nil
        defer { isLoading = false }
        do {
            records = try await appState.store.fetchCallHistory(limit: 100)
        } catch {
            self.error = error.localizedDescription
        }
    }

    func clearHistory() async {
        do {
            try await appState.store.clearCallHistory()
            records = []
            Haptics.notification(.warning)
        } catch {
            self.error = error.localizedDescription
        }
    }

    /// Start a new call to the contact from a history entry.
    func callBack(_ record: CallRecord, kind: CallKind) async {
        let contacts = (try? await appState.store.fetchContacts()) ?? []
        guard let contact = contacts.first(where: { $0.id == record.contactID }) else {
            error = "That contact is no longer in your list."
            return
        }
        await appState.placeCall(to: contact, kind: kind)
    }
}

/// Controls for the active-call screen: mute, speaker, camera, screen share,
/// and the elapsed-time ticker.
@MainActor
final class ActiveCallViewModel: ObservableObject {
    @Published var screenShareError: String?
    @Published private(set) var elapsed: TimeInterval = 0
    /// Shown when the user taps "Redact" while screen sharing.
    @Published var showingRedactSheet = false
    /// Shown when the user picks full-device sharing (system picker).
    @Published var showingBroadcastPicker = false

    private let appState: AppState
    private var ticker: Timer?

    init(appState: AppState) {
        self.appState = appState
    }

    var call: ActiveCall? { appState.activeCall }

    func startTicker() {
        ticker?.invalidate()
        ticker = Timer.scheduledTimer(withTimeInterval: 1.0, repeats: true) { [weak self] _ in
            Task { @MainActor [weak self] in
                self?.elapsed = self?.call?.elapsed ?? 0
            }
        }
    }

    func stopTicker() {
        ticker?.invalidate()
        ticker = nil
    }

    func toggleMute() async {
        guard let call else { return }
        let muted = !call.isMuted
        try? await appState.transport.setCallMuted(muted, callID: call.id)
        appState.activeCall?.isMuted = muted
        Haptics.selection()
    }

    func toggleSpeaker() async {
        guard let call else { return }
        let enabled = !call.isSpeakerOn
        try? await appState.transport.setCallSpeaker(enabled, callID: call.id)
        appState.activeCall?.isSpeakerOn = enabled
        Haptics.selection()
    }

    func toggleVideo() async {
        guard let call else { return }
        let enabled = !call.isVideoEnabled
        do {
            try await appState.transport.setCallVideoEnabled(enabled, callID: call.id)
            appState.activeCall?.isVideoEnabled = enabled
            Haptics.selection()
        } catch {
            screenShareError = error.localizedDescription
        }
    }

    func toggleScreenShare() async {
        guard let call else { return }
        screenShareError = nil
        guard appState.transport.screenShareSupported else {
            screenShareError = "Screen sharing isn't available on this device yet."
            return
        }
        do {
            if call.isScreenSharing {
                try await appState.transport.stopScreenShare(callID: call.id)
                appState.activeCall?.isScreenSharing = false
                appState.activeCall?.isScreenSharePaused = false
            } else if call.isBroadcastSharing {
                try await appState.transport.stopBroadcastShare(callID: call.id)
                appState.activeCall?.isBroadcastSharing = false
            } else {
                try await appState.transport.startScreenShare(callID: call.id)
                appState.activeCall?.isScreenSharing = true
            }
            Haptics.selection()
        } catch {
            screenShareError = error.localizedDescription
            Haptics.notification(.error)
        }
    }

    /// Pauses/resumes in-app screen-share capture (the peer sees a frozen
    /// frame while paused; resume needs no renegotiation).
    func toggleScreenSharePaused() async {
        guard let call, call.isScreenSharing else { return }
        let paused = !call.isScreenSharePaused
        do {
            try await appState.transport.setScreenSharePaused(paused, callID: call.id)
            appState.activeCall?.isScreenSharePaused = paused
            Haptics.selection()
        } catch {
            screenShareError = error.localizedDescription
            Haptics.notification(.error)
        }
    }

    /// Applies on-device redaction regions for screen sharing (normalized
    /// unit coordinates). Redacted pixels never leave the device.
    func applyRedactionRegions(_ regions: [CGRect]) async {
        guard let call, call.isScreenSharing else { return }
        do {
            try await appState.transport.setScreenShareRedactionRegions(regions, callID: call.id)
            appState.activeCall?.screenShareRedactions = regions
            Haptics.selection()
        } catch {
            screenShareError = error.localizedDescription
            Haptics.notification(.error)
        }
    }

    var broadcastShareSupported: Bool {
        appState.transport.broadcastShareSupported
    }

    /// Starts full-device sharing via the ReplayKit Broadcast Upload
    /// Extension. The user picks Aegis in the system broadcast picker; the
    /// extension's frames take over the call's video track once they arrive.
    func startBroadcastShare() async {
        guard let call else { return }
        screenShareError = nil
        guard broadcastShareSupported else {
            screenShareError = "Full-screen sharing needs the Aegis broadcast extension, which isn't installed with this build."
            return
        }
        do {
            try await appState.transport.startBroadcastShare(callID: call.id)
            // The extension only starts after the user confirms in the
            // system picker; the UI flips to sharing on the first frame.
            // Mark it now so the controls reflect the armed state.
            appState.activeCall?.isBroadcastSharing = true
            Haptics.selection()
        } catch {
            screenShareError = error.localizedDescription
            Haptics.notification(.error)
        }
    }

    func stopBroadcastShare() async {
        guard let call, call.isBroadcastSharing else { return }
        do {
            try await appState.transport.stopBroadcastShare(callID: call.id)
            appState.activeCall?.isBroadcastSharing = false
            Haptics.selection()
        } catch {
            screenShareError = error.localizedDescription
            Haptics.notification(.error)
        }
    }

    func endCall() async {
        stopTicker()
        await appState.endActiveCall()
    }

    /// Records the outcome of the SAS verification ceremony. "Match" marks
    /// the call verified for its duration; "mismatch" surfaces a loud
    /// warning — a SAS mismatch means someone may be relaying the media.
    func confirmSAS(match: Bool) {
        guard appState.activeCall?.callSAS != nil else { return }
        appState.activeCall?.sasVerification = match ? .verified : .mismatch
        Haptics.notification(match ? .success : .error)
    }
}
