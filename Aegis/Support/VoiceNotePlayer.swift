import AVFoundation
import Foundation

/// Plays back voice notes with progress publishing for the waveform UI.
@MainActor
final class VoiceNotePlayer: ObservableObject {
    @Published private(set) var isPlaying = false
    @Published private(set) var progress: Double = 0 // 0...1

    private var player: AVAudioPlayer?
    private var progressTimer: Timer?
    private var currentURL: URL?

    /// Toggle: play if stopped/paused on another note, pause if playing this one.
    func toggle(url: URL) {
        if currentURL == url, isPlaying {
            pause()
            return
        }
        play(url: url)
    }

    func stop() {
        progressTimer?.invalidate()
        progressTimer = nil
        player?.stop()
        player = nil
        currentURL = nil
        isPlaying = false
        progress = 0
    }

    private func play(url: URL) {
        stop()
        do {
            let session = AVAudioSession.sharedInstance()
            try session.setCategory(.playback, mode: .voiceChat)
            try session.setActive(true)
            player = try AVAudioPlayer(contentsOf: url)
            player?.delegate = nil
            player?.play()
            currentURL = url
            isPlaying = true
            progressTimer = Timer.scheduledTimer(withTimeInterval: 0.05, repeats: true) { [weak self] _ in
                Task { @MainActor [weak self] in self?.tick() }
            }
        } catch {
            stop()
        }
    }

    private func pause() {
        player?.pause()
        isPlaying = false
        progressTimer?.invalidate()
        progressTimer = nil
    }

    private func tick() {
        guard let player else { return }
        if !player.isPlaying {
            // Finished naturally.
            stop()
            return
        }
        progress = player.duration > 0 ? player.currentTime / player.duration : 0
    }
}
