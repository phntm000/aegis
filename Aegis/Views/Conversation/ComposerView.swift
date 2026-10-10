import PhotosUI
import UIKit
import SwiftUI
import UniformTypeIdentifiers

/// Message composer: reply/edit banner, text field, attachment menu,
/// voice-note recording, and send. The send button reflects connectivity and
/// channel permissions so it's never a dead control.
struct ComposerView: View {
    @ObservedObject var viewModel: ConversationViewModel
    @EnvironmentObject private var appState: AppState

    @State private var showingAttachMenu = false
    @State private var showingPhotoPicker = false
    @State private var showingFilePicker = false
    @State private var photoItem: PhotosPickerItem?
    @StateObject private var recorder = VoiceRecorder()
    @State private var typingDebounce: Task<Void, Never>?
    @State private var showingMicDenied = false
    @FocusState private var fieldFocused: Bool

    var body: some View {
        VStack(spacing: 0) {
            if let replyingTo = viewModel.replyingTo {
                replyBanner(for: replyingTo) {
                    viewModel.replyingTo = nil
                }
            }
            if let editing = viewModel.editingMessage {
                editBanner {
                    viewModel.editingMessage = nil
                    viewModel.draft = ""
                }
            }

            if recorder.isRecording {
                recordingBar
            } else {
                inputRow
            }

            if let error = viewModel.sendError {
                Text(error)
                    .font(AegisType.caption)
                    .foregroundStyle(AegisColors.danger)
                    .lineLimit(2)
                    .padding(.horizontal, AegisLayout.l)
                    .padding(.bottom, AegisLayout.xs)
            }

            ForEach(viewModel.failedUploads) { upload in
                HStack(spacing: AegisLayout.s) {
                    Image(systemName: "exclamationmark.circle.fill")
                        .foregroundStyle(AegisColors.danger)
                    Text("Couldn't send \(upload.displayName)")
                        .font(AegisType.caption)
                        .foregroundStyle(AegisColors.textSecondary)
                        .lineLimit(1)
                    Spacer()
                    Button("Retry") {
                        Task { @MainActor in await viewModel.retryUpload(upload) }
                    }
                    .font(AegisType.captionStrong)
                    .foregroundStyle(AegisColors.accent)
                    .accessibilityLabel("Retry upload of \(upload.displayName)")
                    Button("Dismiss") {
                        viewModel.discardUpload(upload)
                    }
                    .font(AegisType.caption)
                    .foregroundStyle(AegisColors.textSecondary)
                    .accessibilityLabel("Dismiss failed upload")
                }
                .padding(.horizontal, AegisLayout.l)
                .padding(.bottom, AegisLayout.xs)
            }
        }
        .background(AegisColors.surfaceElevated)
        .overlay(alignment: .top) {
            Divider()
        }
        .confirmationDialog("Attach", isPresented: $showingAttachMenu, titleVisibility: .hidden) {
            Button("Photo or video") { showingPhotoPicker = true }
            Button("File") { showingFilePicker = true }
            Button("Cancel", role: .cancel) {}
        }
        .photosPicker(isPresented: $showingPhotoPicker, selection: $photoItem, matching: .any(of: [.images, .videos]))
        .fileImporter(isPresented: $showingFilePicker, allowedContentTypes: [.data], allowsMultipleSelection: false) { result in
            handleFileImport(result)
        }
        .onChange(of: photoItem) { _, item in
            handlePhotoItem(item)
        }
        .onChange(of: viewModel.draft) { _, _ in
            viewModel.sendTyping(true)
            typingDebounce?.cancel()
            typingDebounce = Task { @MainActor in
                try? await Task.sleep(nanoseconds: 3_000_000_000)
                await MainActor.run { viewModel.sendTyping(false) }
            }
        }
        .alert("Microphone access needed", isPresented: $showingMicDenied) {
            Button("Open Settings") {
                if let url = URL(string: UIApplication.openSettingsURLString) {
                    UIApplication.shared.open(url)
                }
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("Voice notes need microphone access. You can enable it in Settings — recordings never leave your device unencrypted.")
        }
    }

    // MARK: - Input row

    private var inputRow: some View {
        HStack(alignment: .bottom, spacing: AegisLayout.s) {
            Button {
                showingAttachMenu = true
            } label: {
                Image(systemName: "plus.circle.fill")
                    .font(.system(size: 26))
                    .foregroundStyle(AegisColors.accent)
            }
            .frame(minWidth: AegisLayout.minTapTarget, minHeight: AegisLayout.minTapTarget)
            .accessibilityLabel("Attach a photo or file")

            TextField("Message", text: $viewModel.draft, axis: .vertical)
                .font(AegisType.body)
                .lineLimit(1...6)
                .focused($fieldFocused)
                .onSubmit { sendOrSaveEdit() }
                .accessibilityLabel("Message field")

            if viewModel.draft.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
                && viewModel.editingMessage == nil {
                Button {
                    startRecording()
                } label: {
                    Image(systemName: "mic.fill")
                        .font(.system(size: 20))
                        .foregroundStyle(AegisColors.accent)
                }
                .frame(minWidth: AegisLayout.minTapTarget, minHeight: AegisLayout.minTapTarget)
                .accessibilityLabel("Record a voice note")
            }

            Button {
                sendOrSaveEdit()
            } label: {
                Image(systemName: viewModel.editingMessage == nil ? "arrow.up.circle.fill" : "checkmark.circle.fill")
                    .font(.system(size: 30))
                    .foregroundStyle(sendEnabled ? AegisColors.accent : AegisColors.textTertiary)
            }
            .frame(minWidth: AegisLayout.minTapTarget, minHeight: AegisLayout.minTapTarget)
            .disabled(!sendEnabled)
            .accessibilityLabel(viewModel.editingMessage == nil ? "Send message" : "Save edit")
        }
        .padding(.horizontal, AegisLayout.s)
        .padding(.vertical, AegisLayout.xs)
    }

    private var sendEnabled: Bool {
        if viewModel.editingMessage != nil {
            return !viewModel.draft.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
        }
        return !viewModel.draft.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            && viewModel.canSend
    }

    private func sendOrSaveEdit() {
        if let editing = viewModel.editingMessage {
            let newBody = viewModel.draft
            viewModel.editingMessage = nil
            viewModel.draft = ""
            Task { @MainActor in await viewModel.editMessage(editing, newBody: newBody) }
        } else {
            Task { @MainActor in await viewModel.send() }
        }
    }

    // MARK: - Reply / edit banners

    private func replyBanner(for message: Message, onCancel: @escaping () -> Void) -> some View {
        banner(title: "Replying to \(message.isFromMe ? "yourself" : "message")",
               body: message.body ?? "📎 Attachment",
               onCancel: onCancel)
    }

    private func editBanner(onCancel: @escaping () -> Void) -> some View {
        banner(title: "Editing message", body: "Changes are sent to everyone in this chat.", onCancel: onCancel)
    }

    private func banner(title: String, body: String, onCancel: @escaping () -> Void) -> some View {
        HStack {
            Capsule().fill(AegisColors.accent).frame(width: 3)
            VStack(alignment: .leading, spacing: 2) {
                Text(title).font(AegisType.captionStrong).foregroundStyle(AegisColors.accent)
                Text(body).font(AegisType.caption).foregroundStyle(AegisColors.textSecondary).lineLimit(1)
            }
            Spacer()
            Button(action: onCancel) {
                Image(systemName: "xmark")
                    .foregroundStyle(AegisColors.textSecondary)
                    .frame(minWidth: AegisLayout.minTapTarget, minHeight: AegisLayout.minTapTarget)
            }
            .accessibilityLabel("Cancel")
        }
        .padding(.horizontal, AegisLayout.l)
        .padding(.vertical, AegisLayout.s)
        .background(AegisColors.accentSoft.opacity(0.5))
    }

    // MARK: - Voice recording

    private func startRecording() {
        Task { @MainActor in
            let granted = await recorder.requestPermission()
            guard granted else {
                showingMicDenied = true
                return
            }
            do {
                try recorder.start()
                Haptics.impact(.medium)
            } catch {
                viewModel.sendError = "Couldn't start recording: \(error.localizedDescription)"
            }
        }
    }

    private var recordingBar: some View {
        HStack(spacing: AegisLayout.m) {
            Button {
                recorder.cancel()
                Haptics.selection()
            } label: {
                Image(systemName: "trash.fill")
                    .foregroundStyle(AegisColors.danger)
            }
            .frame(minWidth: AegisLayout.minTapTarget, minHeight: AegisLayout.minTapTarget)
            .accessibilityLabel("Discard recording")

            Circle()
                .fill(AegisColors.danger)
                .frame(width: 10, height: 10)
                .accessibilityHidden(true)
            Text(Formatters.duration(recorder.duration))
                .font(AegisType.numeric)
                .foregroundStyle(AegisColors.textPrimary)
                .monospacedDigit()

            // Live level bars.
            HStack(spacing: 2) {
                ForEach(Array(recorder.levels.suffix(30).enumerated()), id: \.offset) { _, level in
                    RoundedRectangle(cornerRadius: 1)
                        .fill(AegisColors.accent)
                        .frame(width: 3, height: max(4, CGFloat(level) * 28))
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)

            Button {
                if let result = recorder.stop() {
                    Task { @MainActor in
                        await viewModel.sendVoiceNote(
                            fileURL: result.url,
                            duration: result.duration,
                            levels: result.levels
                        )
                    }
                }
            } label: {
                Image(systemName: "arrow.up.circle.fill")
                    .font(.system(size: 30))
                    .foregroundStyle(AegisColors.accent)
            }
            .frame(minWidth: AegisLayout.minTapTarget, minHeight: AegisLayout.minTapTarget)
            .accessibilityLabel("Send voice note")
        }
        .padding(.horizontal, AegisLayout.m)
        .padding(.vertical, AegisLayout.s)
        .accessibilityLabel("Recording voice note")
    }

    // MARK: - Imports

    private func handlePhotoItem(_ item: PhotosPickerItem?) {
        guard let item else { return }
        photoItem = nil
        Task { @MainActor in
            do {
                if let data = try await item.loadTransferable(type: Data.self) {
                    let url = FileManager.default.temporaryDirectory
                        .appendingPathComponent("photo-\(UUID().uuidString).jpg")
                    try data.write(to: url)
                    await viewModel.sendAttachment(fileURL: url, filename: "photo.jpg", mimeType: "image/jpeg")
                }
            } catch {
                viewModel.sendError = "Couldn't load that photo: \(error.localizedDescription)"
            }
        }
    }

    private func handleFileImport(_ result: Result<[URL], Error>) {
        switch result {
        case .success(let urls):
            guard let url = urls.first else { return }
            Task { @MainActor in
                let staging = AegisPaths.ensureStaging()
                    .appendingPathComponent("import-\(UUID().uuidString)-\(url.lastPathComponent)")
                do {
                    let accessing = url.startAccessingSecurityScopedResource()
                    defer { if accessing { url.stopAccessingSecurityScopedResource() } }
                    try FileManager.default.copyItem(at: url, to: staging)
                    let mime = mimeType(for: url)
                    await viewModel.sendAttachment(fileURL: staging, filename: url.lastPathComponent, mimeType: mime)
                } catch {
                    viewModel.sendError = "Couldn't import that file: \(error.localizedDescription)"
                }
            }
        case .failure(let error):
            viewModel.sendError = error.localizedDescription
        }
    }

    private func mimeType(for url: URL) -> String {
        if let type = UTType(filenameExtension: url.pathExtension),
           let mime = type.preferredMIMEType {
            return mime
        }
        return "application/octet-stream"
    }
}

#Preview {
    let appState = AppState(factory: PreviewServiceFactory())
    let conversation = SampleData.previewConversation(title: "Maya Chen")
    let vm = ConversationViewModel(conversation: conversation, contact: nil, appState: appState)
    return ComposerView(viewModel: vm)
        .environmentObject(appState)
}
