import SwiftUI

/// Renders a poll inside a message bubble: voting UI, live client-side
/// tally, quorum display, countdown to auto-close, and the closed state.
/// Every control is wired: votes go through `onVote`, which validates
/// single/multi-choice, anonymity, and the close deadline.
struct PollMessageView: View {
    let poll: PollMessage
    var isFromMe: Bool
    var onVote: ([Int]) -> Void

    @State private var selection: Set<Int> = []
    @State private var now = Date()

    var body: some View {
        VStack(alignment: .leading, spacing: AegisLayout.s) {
            HStack(spacing: AegisLayout.xs) {
                Image(systemName: "chart.bar.fill")
                    .font(AegisType.caption)
                    .accessibilityHidden(true)
                Text(poll.question)
                    .font(AegisType.bodyStrong)
            }
            .accessibilityLabel("Poll: \(poll.question)")

            if poll.isClosed {
                closedBanner
            } else if poll.closesAt != nil {
                countdownRow
            }

            optionsList

            HStack {
                Text(poll.quorumText)
                    .font(AegisType.caption)
                Spacer()
                if poll.isAnonymous {
                    Label("Anonymous", systemImage: "eye.slash")
                        .font(AegisType.caption)
                        .accessibilityLabel("Anonymous poll")
                } else if poll.allowsMultipleChoice {
                    Text("Multi-choice")
                        .font(AegisType.caption)
                }
            }
            .foregroundStyle(metaColor)

            if canChangeVote {
                Button("Vote") {
                    onVote(Array(selection).sorted())
                    Haptics.selection()
                }
                .buttonStyle(.borderedProminent)
                .tint(AegisColors.accent)
                .disabled(selection.isEmpty)
                .frame(minHeight: AegisLayout.minTapTarget)
                .accessibilityLabel("Submit vote")
                .accessibilityHint(selectionHint)
            } else if !poll.isClosed && !poll.isAnonymous && !poll.myChoices.isEmpty {
                Text("Tap an option to change your vote")
                    .font(AegisType.caption)
                    .foregroundStyle(metaColor)
            }
        }
        .onAppear { selection = Set(poll.myChoices) }
        .onChange(of: poll.myChoices) { _, choices in selection = Set(choices) }
        .onReceive(Timer.publish(every: 30, on: .main, in: .common).autoconnect()) { date in
            now = date
        }
        .accessibilityElement(children: .contain)
    }

    // MARK: - Subviews

    private var metaColor: Color {
        isFromMe ? AegisColors.textOnAccent.opacity(0.8) : AegisColors.textSecondary
    }

    private var optionsList: some View {
        VStack(spacing: AegisLayout.xs) {
            ForEach(Array(poll.options.enumerated()), id: \.offset) { index, option in
                optionRow(index: index, option: option)
            }
        }
    }

    private func optionRow(index: Int, option: String) -> some View {
        let count = poll.count(for: index)
        let share = poll.share(for: index)
        let selected = selection.contains(index)
        let voted = poll.myChoices.contains(index)
        return Button {
            toggleOption(index)
        } label: {
            ZStack(alignment: .leading) {
                // Result bar.
                GeometryReader { geo in
                    RoundedRectangle(cornerRadius: 8)
                        .fill(barColor)
                        .frame(width: geo.size.width * max(0.04, CGFloat(share)))
                }
                HStack {
                    if !poll.isClosed {
                        Image(systemName: selectionGlyph(selected: selected))
                            .foregroundStyle(metaColor)
                            .accessibilityHidden(true)
                    }
                    Text(option)
                        .font(AegisType.body)
                        .lineLimit(3)
                        .multilineTextAlignment(.leading)
                    Spacer()
                    if voted && !poll.isAnonymous {
                        Image(systemName: "checkmark.circle.fill")
                            .font(AegisType.caption)
                            .accessibilityLabel("Your vote")
                    }
                    Text("\(count)")
                        .font(AegisType.numeric)
                        .monospacedDigit()
                }
                .padding(.horizontal, AegisLayout.s)
                .padding(.vertical, 8)
            }
            .frame(minHeight: AegisLayout.minTapTarget)
            .overlay {
                RoundedRectangle(cornerRadius: 8)
                    .stroke(selected ? AegisColors.accent : AegisColors.separator, lineWidth: selected ? 2 : 1)
            }
        }
        .disabled(poll.isClosed)
        .accessibilityLabel("\(option), \(count) votes\(voted ? ", your vote" : "")")
        .accessibilityHint(poll.isClosed ? "Poll closed" : "Double tap to select")
    }

    private var barColor: Color {
        isFromMe
            ? AegisColors.textOnAccent.opacity(0.25)
            : AegisColors.accent.opacity(0.18)
    }

    private func selectionGlyph(selected: Bool) -> String {
        if poll.allowsMultipleChoice {
            return selected ? "checkmark.square.fill" : "square"
        }
        return selected ? "largecircle.fill.circle" : "circle"
    }

    private var closedBanner: some View {
        Label("Poll closed", systemImage: "lock.fill")
            .font(AegisType.captionStrong)
            .foregroundStyle(metaColor)
            .accessibilityLabel("Poll closed")
    }

    private var countdownRow: some View {
        Group {
            if let closesAt = poll.closesAt, closesAt > now {
                Label("Closes in \(Formatters.duration(closesAt.timeIntervalSince(now)))", systemImage: "timer")
                    .font(AegisType.caption)
                    .foregroundStyle(metaColor)
            }
        }
    }

    // MARK: - Voting logic

    /// Whether the Vote button flow is available (vs tap-to-change).
    private var canChangeVote: Bool {
        guard !poll.isClosed else { return false }
        // Multi-choice and first votes use the explicit Vote button;
        // single-choice re-votes apply immediately on tap.
        if poll.allowsMultipleChoice { return true }
        if poll.isAnonymous && !poll.myChoices.isEmpty { return false }
        return poll.myChoices.isEmpty
    }

    private var selectionHint: String {
        if selection.isEmpty { return "Select at least one option first" }
        return "Vote for \(selection.count) option\(selection.count == 1 ? "" : "s")"
    }

    private func toggleOption(_ index: Int) {
        guard !poll.isClosed else { return }
        if poll.allowsMultipleChoice {
            if selection.contains(index) {
                selection.remove(index)
            } else {
                selection.insert(index)
            }
        } else {
            // Single-choice: tapping applies the vote immediately (unless
            // it's an anonymous re-vote, which the view model rejects).
            selection = [index]
            if poll.myChoices.isEmpty || !poll.isAnonymous {
                onVote([index])
                Haptics.selection()
            }
        }
    }
}

#Preview {
    let poll = PollMessage(
        question: "Where should we order from tonight?",
        options: ["Steve's Burgers", "Luigi's Pizza", "Taco truck"],
        allowsMultipleChoice: false,
        isAnonymous: false,
        closesAt: Date().addingTimeInterval(3600),
        tally: [0: 3, 1: 1],
        voters: [UUID(), UUID()],
        voterChoices: [:],
        myChoices: [0],
        eligibleVoterCount: 5
    )
    return PollMessageView(poll: poll, isFromMe: false, onVote: { _ in })
        .padding()
}
