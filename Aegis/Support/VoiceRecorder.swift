import AVFoundation
import Foundation

/// Records voice notes with live level metering for the waveform UI.
/// Output is a compressed .m4a in a temporary URL; the caller encrypts and
/// uploads it through the normal attachment pipeline.
@MainActor
final class VoiceRecorder: ObservableObject {
    @Published private(set) var isRecording = false
    @Published private(set) var levels: [Float] = []
    @Published private(set) var duration: TimeInterval = 0

    private var recorder: AVAudioRecorder?
    private var meterTimer: Timer?
    private var outputURL: URL?

    var hasMicrophonePermission: Bool {
        AVAudioApplication.shared.recordPermission == .granted
    }

    func requestPermission() async -> Bool {
        await AVAudioApplication.requestRecordPermission()
    }

    func start() throws {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("voicenote-\(UUID().uuidString).m4a")
        let settings: [String: Any] = [
            AVFormatIDKey: Int(kAudioFormatMPEG4AAC),
            AVSampleRateKey: 44100,
            AVNumberOfChannelsKey: 1,
            AVEncoderAudioQualityKey: AVAudioQuality.high.rawValue,
        ]
        let session = AVAudioSession.sharedInstance()
        try session.setCategory(.playAndRecord, mode: .voiceChat, options: [.defaultToSpeaker])
        try session.setActive(true)

        recorder = try AVAudioRecorder(url: url, settings: settings)
        recorder?.isMeteringEnabled = true
        recorder?.record()
        outputURL = url
        levels = []
        duration = 0
        isRecording = true

        meterTimer = Timer.scheduledTimer(withTimeInterval: 0.08, repeats: true) { [weak self] _ in
            Task { @MainActor [weak self] in self?.sampleMeter() }
        }
    }

    private func sampleMeter() {
        guard let recorder, isRecording else { return }
        recorder.updateMeters()
        // Average power -160...0 dB → 0...1.
        let power = recorder.averagePower(forChannel: 0)
        let level = max(0, min(1, (power + 60) / 60))
        levels.append(level)
        duration = recorder.currentTime
    }

    /// Stop and return the recording, or nil if nothing was captured.
    func stop() -> (url: URL, duration: TimeInterval, levels: [Float])? {
        meterTimer?.invalidate()
        meterTimer = nil
        recorder?.stop()
        isRecording = false
        try? AVAudioSession.sharedInstance().setActive(false)
        guard let url = outputURL, duration > 0.3 else { return nil }
        // Downsample levels to a fixed bucket count for the waveform view.
        let buckets = Self.downsample(levels, to: 48)
        return (url, duration, buckets)
    }

    func cancel() {
        meterTimer?.invalidate()
        meterTimer = nil
        recorder?.stop()
        recorder?.deleteRecording()
        isRecording = false
        try? AVAudioSession.sharedInstance().setActive(false)
    }

    private static func downsample(_ levels: [Float], to count: Int) -> [Float] {
        guard !levels.isEmpty else { return [] }
        guard levels.count > count else { return levels }
        let bucketSize = Double(levels.count) / Double(count)
        return (0..<count).map { i in
            let start = Int(Double(i) * bucketSize)
            let end = min(levels.count, Int(Double(i + 1) * bucketSize))
            guard end > start else { return 0 }
            return levels[start..<end].max() ?? 0
        }
    }
}
