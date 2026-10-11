import SwiftUI

/// Poll creation sheet: question, 2–10 options, single/multi-choice,
/// anonymous mode, and timed auto-close. Validation is inline; the Create
/// button is disabled until the poll is valid, and send failures surface
/// as an error banner with a retry path.
struct PollComposerView: View {
    @ObservedObject var viewModel: ConversationViewModel
    @Environment(\.dismiss) private var dismiss

    @State private var question = ""
    @State private var options = ["", ""]
    @State private var allowsMultipleChoice = false
    @State private var isAnonymous = false
    @State private var closeSelection: CloseOption = .oneDay
    @State private var isSending = false
    @State private var errorMessage: String?

    private enum CloseOption: String, CaseIterable, Identifiable {
        case fifteenMinutes = "15 minutes"
        case oneHour = "1 hour"
        case oneDay = "1 day"
        case threeDays = "3 days"
        case oneWeek = "1 week"
        case never = "Never"

        var id: String { rawValue }

        var date: Date? {
            switch self {
            case .fifteenMinutes: return Date().addingTimeInterval(15 * 60)
            case .oneHour: return Date().addingTimeInterval(3600)
            case .oneDay: return Date().addingTimeInterval(24 * 3600)
            case .threeDays: return Date().addingTimeInterval(3 * 24 * 3600)
            case .oneWeek: return Date().addingTimeInterval(7 * 24 * 3600)
            case .never: return nil
            }
        }
    }

    private var trimmedOptions: [String] {
        options.map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }.filter { !$0.isEmpty }
    }

    private var isValid: Bool {
        !question.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            && trimmedOptions.count >= 2
    }

    var body: some View {
        NavigationStack {
            Form {
                Section("Question") {
                    TextField("Ask something…", text: $question, axis: .vertical)
                        .lineLimit(1...3)
                        .accessibilityLabel("Poll question")
                }

                Section("Options (2–10)") {
                    ForEach(options.indices, id: \.self) { index in
                        HStack {
                            TextField("Option \(index + 1)", text: $options[index])
                                .accessibilityLabel("Poll option \(index + 1)")
                            if options.count > 2 {
                                Button {
                                    options.remove(at: index)
                                } label: {
                                    Image(systemName: "minus.circle.fill")
                                        .foregroundStyle(AegisColors.danger)
                                }
                                .frame(minWidth: AegisLayout.minTapTarget, minHeight: AegisLayout.minTapTarget)
                                .accessibilityLabel("Remove option \(index + 1)")
                            }
                        }
                    }
                    if options.count < 10 {
                        Button {
                            options.append("")
                        } label: {
                            Label("Add option", systemImage: "plus.circle")
                        }
                        .frame(minHeight: AegisLayout.minTapTarget)
                        .accessibilityLabel("Add another option")
                    }
                }

                Section("Settings") {
                    Toggle("Allow multiple choices", isOn: $allowsMultipleChoice)
                    Toggle("Anonymous voting", isOn: $isAnonymous)
                    if isAnonymous {
                        Text("Voters are counted but individual choices stay hidden. Anonymous votes can't be changed.")
                            .font(AegisType.caption)
                            .foregroundStyle(AegisColors.textSecondary)
                    }
                    Picker("Closes", selection: $closeSelection) {
                        ForEach(CloseOption.allCases) { option in
                            Text(option.rawValue).tag(option)
                        }
                    }
                    .accessibilityLabel("Poll closing time")
                }

                if let errorMessage {
                    Section {
                        Label(errorMessage, systemImage: "exclamationmark.triangle.fill")
                            .font(AegisType.caption)
                            .foregroundStyle(AegisColors.danger)
                            .accessibilityLabel("Error: \(errorMessage)")
                    }
                }
            }
            .navigationTitle("New poll")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                        .disabled(isSending)
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Create") { create() }
                        .disabled(!isValid || isSending)
                        .accessibilityHint(isValid ? "Create and send this poll" : "Add a question and at least two options first")
                }
            }
            .overlay {
                if isSending {
                    LoadingOverlayView(label: "Sending poll…")
                }
            }
        }
    }

    private func create() {
        guard isValid, !isSending else { return }
        isSending = true
        errorMessage = nil
        Task { @MainActor in
            let ok = await viewModel.createPoll(
                question: question,
                options: trimmedOptions,
                allowsMultipleChoice: allowsMultipleChoice,
                isAnonymous: isAnonymous,
                closesAt: closeSelection.date
            )
            isSending = false
            if ok {
                dismiss()
            } else {
                errorMessage = viewModel.sendError ?? "Couldn't send the poll. Check your connection and try again."
            }
        }
    }
}

#Preview {
    let appState = AppState(factory: PreviewServiceFactory())
    let vm = ConversationViewModel(
        conversation: SampleData.previewConversation(title: "Maya Chen"),
        contact: nil,
        appState: appState
    )
    return PollComposerView(viewModel: vm)
}
