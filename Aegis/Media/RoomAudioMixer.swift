// RoomAudioMixer — software audio mixer for voice-room mesh peers.
//
// Stock WebRTC renders every enabled remote audio track through its own
// output mix and exposes no per-track gain API, but voice rooms need
// per-user volume. Room peers therefore take a different path: each remote
// audio track is tapped (RTCAudioSink) and kept disabled so WebRTC never
// renders it, and this mixer applies per-user gain and plays the summed
// mix through AVAudioEngine.
//
// Privacy: all mixing happens on-device. Gains are local UI state; audio
// levels and PCM never leave the device and are never transmitted.
//
// Realtime notes: the render callback runs on a high-priority audio thread.
// It never allocates (fixed scratch buffers) and holds locks only to
// snapshot the peer list. The tap converts Int16 PCM → mono Float and
// applies the peer's gain at capture time.

import AVFoundation
import Foundation
import WebRTCBridge

// MARK: - Per-peer tap

/// Receives decoded PCM for one room peer and applies that peer's gain.
/// Attached to the peer's RTCAudioTrack via `add(_:)`; the track stays
/// disabled so WebRTC doesn't also render it (no double playback).
final class RoomAudioTap: NSObject, RTCAudioSink, @unchecked Sendable {
    /// The peer connection's call UUID (the mixer's key for this peer).
    let peerID: UUID

    private let lock = NSLock()
    private var _gain: Float = 1.0
    private var ring = AudioRingBuffer(capacityFrames: 96_000) // 2s @ 48k
    private var sourceRateHz: Int = 48_000

    /// Per-user gain, 0.0–2.0 (UI exposes 0–100%).
    var gain: Float {
        get { lock.withLock { _gain } }
        set { lock.withLock { _gain = max(0, min(2, newValue)) } }
    }

    init(peerID: UUID) {
        self.peerID = peerID
    }

    // MARK: RTCAudioSink

    func onData(
        _ audioData: UnsafeRawPointer,
        bitsPerSample: Int32,
        sampleRate: Int32,
        channels: Int,
        frames: Int
    ) {
        // WebRTC delivers 16-bit PCM.
        guard bitsPerSample == 16, frames > 0, channels > 0 else { return }
        let total = frames * channels
        let gain = self.gain
        var mono = [Float](repeating: 0, count: frames)
        audioData.withMemoryRebound(to: Int16.self, capacity: total) { ptr in
            for i in 0..<frames {
                var sum: Float = 0
                for c in 0..<channels {
                    sum += Float(ptr[i * channels + c]) / 32768.0
                }
                mono[i] = (sum / Float(channels)) * gain
            }
        }
        lock.withLock {
            sourceRateHz = Int(sampleRate)
            ring.write(mono)
        }
    }

    /// Pulls up to `count` frames, resampled to `targetRateHz`. Pads with
    /// silence when the tap is starved.
    func read(into buffer: UnsafeMutablePointer<Float>, count: Int, targetRateHz: Int) {
        lock.withLock {
            ring.readResampled(into: buffer, count: count, sourceRateHz: sourceRateHz, targetRateHz: targetRateHz)
        }
    }
}

// MARK: - Ring buffer with linear resampling

/// Lock-free-by-contract circular Float buffer. The owner (RoomAudioTap)
/// serializes access with its own lock.
final class AudioRingBuffer {
    private var buf: [Float]
    private var head = 0 // next write position
    private var tail = 0 // next read position
    private var count = 0
    /// Fractional read carry between resampled reads.
    private var phase: Double = 0

    init(capacityFrames: Int) {
        buf = [Float](repeating: 0, count: max(capacityFrames, 64))
    }

    var available: Int { count }

    func write(_ samples: [Float]) {
        for s in samples {
            buf[head] = s
            head = (head + 1) % buf.count
            if count < buf.count {
                count += 1
            } else {
                tail = (tail + 1) % buf.count // overwrite oldest on overflow
            }
        }
    }

    private func sample(at index: Int) -> Float {
        buf[(tail + index) % buf.count]
    }

    private func drop(_ n: Int) {
        let d = min(n, count)
        tail = (tail + d) % buf.count
        count -= d
    }

    /// Reads `count` frames resampled from `sourceRateHz` to `targetRateHz`
    /// with linear interpolation. Short reads are zero-padded.
    func readResampled(
        into out: UnsafeMutablePointer<Float>,
        count: Int,
        sourceRateHz: Int,
        targetRateHz: Int
    ) {
        guard sourceRateHz > 0, targetRateHz > 0, count > 0 else { return }
        let step = Double(sourceRateHz) / Double(targetRateHz)
        var pos = phase
        var produced = 0
        while produced < count {
            let idx = Int(pos)
            // NOTE: `self.count` is the available buffered frames; the
            // `count` parameter is the requested output frames.
            guard idx + 1 < self.count else { break }
            let frac = Float(pos - Double(idx))
            let a = sample(at: idx)
            let b = sample(at: idx + 1)
            out[produced] = a + (b - a) * frac
            pos += step
            produced += 1
        }
        let consumed = Int(pos)
        drop(consumed)
        phase = pos - Double(consumed)
        // Zero-pad starvation so the mix never plays stale audio.
        if produced < count {
            for i in produced..<count { out[i] = 0 }
        }
    }
}

// MARK: - Mixer

/// Mixes room-peer taps to the speaker via AVAudioEngine.
///
/// Lifecycle: the engine starts the mixer when the first room peer's audio
/// tap attaches and stops it when the last room peer leaves. `setMasterGain`
/// implements deafen (0 = deafened).
final class RoomAudioMixer: @unchecked Sendable {
    private let lock = NSLock()
    private var engine: AVAudioEngine?
    private var taps: [UUID: RoomAudioTap] = [:]
    private var masterGain: Float = 1.0

    private let outputRateHz = 48_000.0
    private let scratchFrames = 2048
    // Touched only on the audio render thread.
    private var scratchA: [Float] = [Float](repeating: 0, count: 2048)
    private var scratchB: [Float](repeating: 0, count: 2048)

    /// Starts the audio engine. Idempotent; returns false when the engine
    /// could not start (mixer stays stopped; room audio is then silent —
    /// the caller logs it).
    @discardableResult
    func start() -> Bool {
        lock.withLock {
            if engine != nil { return true }
            let eng = AVAudioEngine()
            guard let format = AVAudioFormat(
                standardFormatWithSampleRate: outputRateHz, channels: 1
            ) else { return false }
            let node = AVAudioSourceNode(format: format) { [weak self] _, _, frameCount, audioBufferList in
                self?.render(frameCount: frameCount, audioBufferList: audioBufferList)
                return noErr
            }
            eng.attach(node)
            eng.connect(node, to: eng.mainMixerNode, format: format)
            do {
                try eng.start()
            } catch {
                return false
            }
            engine = eng
            return true
        }
    }

    func stop() {
        lock.withLock {
            engine?.stop()
            engine = nil
        }
    }

    func addPeer(_ tap: RoomAudioTap) {
        lock.withLock { taps[tap.peerID] = tap }
    }

    func removePeer(_ peerID: UUID) {
        lock.withLock { taps.removeValue(forKey: peerID) }
    }

    func setGain(_ gain: Float, for peerID: UUID) {
        lock.withLock { taps[peerID]?.gain = gain }
    }

    /// Deafen: 0 silences the whole room mix; 1 restores it.
    func setMasterGain(_ gain: Float) {
        lock.withLock { masterGain = max(0, min(1, gain)) }
    }

    // Runs on the realtime audio thread: no allocation, tiny critical
    // section (peer-list snapshot only).
    private func render(
        frameCount: AVAudioFrameCount,
        audioBufferList: UnsafeMutablePointer<AudioBufferList>
    ) {
        let n = min(Int(frameCount), scratchFrames)
        let peers: [RoomAudioTap] = lock.withLock { Array(taps.values) }
        let master: Float = lock.withLock { masterGain }
        for i in 0..<n { scratchA[i] = 0 }
        for tap in peers {
            scratchB.withUnsafeMutableBufferPointer { ptr in
                guard let base = ptr.baseAddress else { return }
                tap.read(into: base, count: n, targetRateHz: Int(outputRateHz))
            }
            for i in 0..<n { scratchA[i] += scratchB[i] }
        }
        for i in 0..<n {
            let v = scratchA[i] * master
            scratchA[i] = max(-1, min(1, v))
        }
        let abl = UnsafeMutableAudioBufferListPointer(audioBufferList)
        for buffer in abl {
            guard let dst = buffer.mData?.assumingMemoryBound(to: Float.self) else { continue }
            let frames = min(n, Int(buffer.mDataByteSize) / MemoryLayout<Float>.size)
            for i in 0..<frames { dst[i] = scratchA[i] }
            buffer.mDataByteSize = UInt32(frames * MemoryLayout<Float>.size)
        }
    }
}
