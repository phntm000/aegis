import SwiftUI

/// Local version history for an edited message: every previous body with
/// its timestamp, plus the current version on top.
struct EditHistoryView: View {
    let message: Message
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            Group {
                if message.editHistory.isEmpty && !message.isEdited {
                    EmptyStateView(
                        icon: "pencil",
                        title: "No edits",
                        message: "This message hasn't been edited."
                    )
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                } else {
                    List {
                        Section("Current") {
                            VStack(alignment: .leading, spacing: 4) {
                                Text(message.body ?? "")
                                    .font(AegisType.body)
                                    .foregroundStyle(AegisColors.textPrimary)
                                if let editedAt = message.editedAt {
                                    Text("Edited \(Formatters.bubbleTime(editedAt))")
                                        .font(AegisType.caption)
                                        .foregroundStyle(AegisColors.textSecondary)
                                }
                            }
                            .padding(.vertical, AegisLayout.xs)
                        }
                        if !message.editHistory.isEmpty {
                            Section("Previous versions") {
                                ForEach(Array(message.editHistory.enumerated().reversed()), id: \.offset) { _, edit in
                                    VStack(alignment: .leading, spacing: 4) {
                                        Text(edit.body)
                                            .font(AegisType.body)
                                            .foregroundStyle(AegisColors.textSecondary)
                                        Text(Formatters.bubbleTime(edit.editedAt))
                                            .font(AegisType.caption)
                                            .foregroundStyle(AegisColors.textTertiary)
                                    }
                                    .padding(.vertical, AegisLayout.xs)
                                    .accessibilityLabel("Previous version from \(Formatters.bubbleTime(edit.editedAt)): \(edit.body)")
                                }
                            }
                        }
                    }
                }
            }
            .background(AegisColors.background.ignoresSafeArea())
            .navigationTitle("Edit history")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") { dismiss() }
                }
            }
        }
    }
}

#Preview {
    var message = SampleData.previewMessages(for: "Maya Chen").first!
    message.editHistory = [
        MessageEdit(body: "Original draft", editedAt: Date().addingTimeInterval(-7200)),
        MessageEdit(body: "Second draft", editedAt: Date().addingTimeInterval(-3600)),
    ]
    message.body = "Final version"
    message.editedAt = Date()
    return EditHistoryView(message: message)
}
