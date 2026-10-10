import QuickLook
import UIKit
import SwiftUI

/// Renders an attachment inside a bubble: image thumbnail, file row, or voice
/// note player. Tap downloads + decrypts on demand with visible progress;
/// files open in QuickLook once local.
struct AttachmentContentView: View {
    let attachment: Attachment
    @ObservedObject var viewModel: ConversationViewModel

    @State private var localURL: URL?
    @State private var previewURL: URL?
    @State private var isResolving = false

    var body: some View {
        Group {
            if attachment.isImage {
                imageContent
            } else {
                fileContent
            }
        }
        .quickLookPreview($previewURL)
    }

    // MARK: - Images

    private var imageContent: some View {
        Button {
            Task { @MainActor in await open() }
        } label: {
            ZStack {
                if let data = attachment.thumbnailData,
                   let uiImage = UIImage(data: data) {
                    Image(uiImage: uiImage)
                        .resizable()
                        .scaledToFill()
                } else {
                    RoundedRectangle(cornerRadius: AegisLayout.radiusS)
                        .fill(Color.black.opacity(0.12))
                        .overlay {
                            ProgressView().tint(AegisColors.accent)
                        }
                }
            }
            .frame(maxWidth: 240, maxHeight: 240)
            .clipShape(RoundedRectangle(cornerRadius: AegisLayout.radiusS))
            .overlay(alignment: .bottomTrailing) {
                if isResolving { progressBadge }
            }
        }
        .accessibilityLabel("Image attachment: \(attachment.filename)")
    }

    // MARK: - Files

    private var fileContent: some View {
        Button {
            Task { @MainActor in await open() }
        } label: {
            HStack(spacing: AegisLayout.m) {
                Image(systemName: iconName)
                    .font(.system(size: 28, weight: .light))
                    .foregroundStyle(AegisColors.accent)
                    .frame(width: 40)
                    .accessibilityHidden(true)
                VStack(alignment: .leading, spacing: 2) {
                    Text(attachment.filename)
                        .font(AegisType.callout)
                        .foregroundStyle(AegisColors.textPrimary)
                        .lineLimit(1)
                    Text(attachment.sizeLabel)
                        .font(AegisType.caption)
                        .foregroundStyle(AegisColors.textSecondary)
                }
                Spacer()
                transferControl
            }
            .padding(AegisLayout.m)
            .background(Color.black.opacity(0.06))
            .clipShape(RoundedRectangle(cornerRadius: AegisLayout.radiusS))
        }
        .accessibilityLabel("File attachment: \(attachment.filename), \(attachment.sizeLabel)")
    }

    private var iconName: String {
        if attachment.isVideo { return "film.fill" }
        if attachment.isAudio { return "waveform" }
        if attachment.mimeType == "application/pdf" { return "doc.fill" }
        return "doc.fill"
    }

    @ViewBuilder
    private var transferControl: some View {
        let state = viewModel.transfers[attachment.id] ?? .idle
        switch state {
        case .idle:
            Image(systemName: "arrow.down.circle.fill")
                .font(.system(size: 24))
                .foregroundStyle(AegisColors.accent)
                .accessibilityLabel("Download")
        case .preparing:
            ProgressView().tint(AegisColors.accent)
        case .inProgress(let p):
            ProgressView(value: p)
                .tint(AegisColors.accent)
                .frame(width: 60)
                .accessibilityLabel("Downloading, \(Int(p * 100)) percent")
        case .done:
            Image(systemName: "checkmark.circle.fill")
                .font(.system(size: 24))
                .foregroundStyle(AegisColors.success)
                .accessibilityLabel("Downloaded")
        case .failed:
            Image(systemName: "exclamationmark.circle.fill")
                .font(.system(size: 24))
                .foregroundStyle(AegisColors.danger)
                .accessibilityLabel("Download failed, tap to retry")
        }
    }

    private var progressBadge: some View {
        ProgressView()
            .tint(.white)
            .padding(6)
            .background(Color.black.opacity(0.5))
            .clipShape(Circle())
            .padding(8)
    }

    private func open() async {
        if previewURL == nil {
            isResolving = true
            defer { isResolving = false }
            localURL = await viewModel.localURL(for: attachment)
        }
        if let localURL {
            previewURL = localURL
            Haptics.selection()
        }
    }
}

/// Voice note bubble: play/pause, waveform with progress, duration.
struct VoiceNoteBubbleView: View {
    let voiceNote: VoiceNote
    @ObservedObject var viewModel: ConversationViewModel

    @StateObject private var player = VoiceNotePlayer()
    @State private var audioURL: URL?
    @State private var isResolving = false

    var body: some View {
        HStack(spacing: AegisLayout.s) {
            Button {
                Task { @MainActor in await toggle() }
            } label: {
                ZStack {
                    Circle()
                        .fill(Color.black.opacity(0.12))
                        .frame(width: 38, height: 38)
                    if isResolving {
                        ProgressView().tint(AegisColors.accent)
                    } else {
                        Image(systemName: player.isPlaying ? "pause.fill" : "play.fill")
                            .font(.system(size: 15))
                            .foregroundStyle(AegisColors.accent)
                    }
                }
            }
            .accessibilityLabel(player.isPlaying ? "Pause voice note" : "Play voice note")

            // Waveform with played-progress tint.
            HStack(spacing: 2) {
                ForEach(Array(voiceNote.levels.enumerated()), id: \.offset) { index, level in
                    RoundedRectangle(cornerRadius: 1.5)
                        .fill(barColor(for: index))
                        .frame(width: 3, height: max(4, CGFloat(level) * 30))
                        .accessibilityHidden(true)
                }
            }

            Text(Formatters.duration(voiceNote.duration))
                .font(AegisType.caption)
                .foregroundStyle(AegisColors.textSecondary)
                .monospacedDigit()
        }
        .padding(.vertical, AegisLayout.xs)
        .onDisappear { player.stop() }
        .accessibilityLabel("Voice note, \(Formatters.duration(voiceNote.duration))")
    }

    private func barColor(for index: Int) -> Color {
        let played = Double(index) / Double(max(1, voiceNote.levels.count)) <= player.progress
        return played ? AegisColors.accent : AegisColors.textTertiary.opacity(0.5)
    }

    private func toggle() async {
        if audioURL == nil {
            isResolving = true
            defer { isResolving = false }
            audioURL = await viewModel.localAudioURL(for: voiceNote)
        }
        if let audioURL {
            player.toggle(url: audioURL)
            Haptics.selection()
        }
    }
}

#Preview {
    let appState = AppState(factory: PreviewServiceFactory())
    let conversation = SampleData.previewConversation(title: "Design sync")
    let vm = ConversationViewModel(conversation: conversation, contact: nil, appState: appState)
    let attachment = Attachment(filename: "launch-checklist.pdf", mimeType: "application/pdf", byteCount: 184_320, remoteLocator: "blob-1")
    let voice = VoiceNote(duration: 14, levels: [0.2, 0.4, 0.7, 0.5, 0.9, 0.6, 0.3, 0.8, 0.5, 0.4, 0.7, 0.6, 0.3, 0.2])
    return VStack(spacing: 16) {
        AttachmentContentView(attachment: attachment, viewModel: vm)
        VoiceNoteBubbleView(voiceNote: voice, viewModel: vm)
    }
    .padding()
    .environmentObject(appState)
}
