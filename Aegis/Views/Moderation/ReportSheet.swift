import AegisModeration
import SwiftUI

/// Report flow. Reports are LOCAL HEURISTICS ONLY — there is no central
/// abuse desk to send them to, by design (a global abuse pipeline would be
/// a metadata honeypot and a censorship choke point). The UI states this
/// honestly. Reporting also blocks the sender.
struct ReportSheet: View {
    let subjectName: String
    var onReport: (ReportReason, String?) -> Void

    @State private var reason: ReportReason = .spam
    @State private var detail: String = ""
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    ForEach(ReportReason.allCases, id: \.self) { option in
                        Button {
                            reason = option
                            Haptics.selection()
                        } label: {
                            HStack {
                                Label(option.displayName, systemImage: option.systemImage)
                                    .foregroundStyle(AegisColors.textPrimary)
                                Spacer()
                                if reason == option {
                                    Image(systemName: "checkmark")
                                        .foregroundStyle(AegisColors.accent)
                                        .accessibilityHidden(true)
                                }
                            }
                        }
                        .accessibilityLabel("Report reason: \(option.displayName)")
                    }
                } header: {
                    Text("What's wrong with \(subjectName)?")
                }

                Section("Details (optional)") {
                    TextField("Anything we should note locally?", text: $detail, axis: .vertical)
                        .lineLimit(2...4)
                }

                Section {
                    VStack(alignment: .leading, spacing: AegisLayout.s) {
                        Text("What happens next")
                            .font(AegisType.bodyStrong)
                            .foregroundStyle(AegisColors.textPrimary)
                        Text("This report never leaves your device — there is no central abuse desk. It's stored locally so repeat offenders can be recognized, and the sender is blocked silently: they won't be told.")
                            .font(AegisType.callout)
                            .foregroundStyle(AegisColors.textSecondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    .padding(.vertical, AegisLayout.xs)
                }
            }
            .navigationTitle("Report")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Report & block") {
                        let trimmed = detail.trimmingCharacters(in: .whitespacesAndNewlines)
                        onReport(reason, trimmed.isEmpty ? nil : trimmed)
                        dismiss()
                    }
                    .tint(AegisColors.danger)
                }
            }
        }
        .presentationDetents([.medium, .large])
    }
}

#Preview {
    ReportSheet(subjectName: "Unknown sender", onReport: { _, _ in })
}
