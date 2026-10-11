import SwiftUI

// MARK: - Screen share redaction editor
//
// Lets the sharer black out regions of their screen before anything is
// sent. Rectangles are stored in normalized unit coordinates (0–1) and
// painted opaque on-device by WindowSnapshotCapturer — redacted pixels
// never leave the device in any form.

struct ScreenShareRedactView: View {
    @State private var regions: [CGRect]
    @State private var draft: CGRect?
    @State private var selectedIndex: Int?
    var onSave: ([CGRect]) -> Void

    @Environment(\.dismiss) private var dismiss

    init(regions: [CGRect], onSave: @escaping ([CGRect]) -> Void) {
        _regions = State(initialValue: regions)
        self.onSave = onSave
    }

    var body: some View {
        NavigationStack {
            VStack(spacing: AegisLayout.m) {
                Text("Drag on the screen to black out areas. Redaction is applied on this device before anything is sent.")
                    .font(AegisType.caption)
                    .foregroundStyle(AegisColors.textSecondary)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal, AegisLayout.m)

                GeometryReader { geo in
                    let canvas = canvasRect(in: geo.size)
                    ZStack {
                        RoundedRectangle(cornerRadius: 12)
                            .fill(AegisColors.surfaceElevated)
                            .frame(width: canvas.width, height: canvas.height)
                            .overlay {
                                Image(systemName: "rectangle.dashed")
                                    .foregroundStyle(AegisColors.textTertiary)
                            }
                        ForEach(regions.indices, id: \.self) { i in
                            regionRect(regions[i], in: canvas, selected: selectedIndex == i)
                                .onTapGesture { selectedIndex = (selectedIndex == i ? nil : i) }
                                .accessibilityLabel("Redacted region \(i + 1)")
                        }
                        if let draft {
                            regionRect(draft, in: canvas, selected: false)
                                .opacity(0.6)
                        }
                    }
                    .frame(width: geo.size.width, height: geo.size.height)
                    .gesture(
                        DragGesture(minimumDistance: 12)
                            .onChanged { value in
                                let start = toUnit(value.startLocation, in: canvas)
                                let current = toUnit(value.location, in: canvas)
                                draft = CGRect(
                                    x: min(start.x, current.x),
                                    y: min(start.y, current.y),
                                    width: abs(current.x - start.x),
                                    height: abs(current.y - start.y)
                                ).clampedToUnit()
                            }
                            .onEnded { _ in
                                if let d = draft, !d.isDegenerate {
                                    regions.append(d)
                                    selectedIndex = regions.count - 1
                                }
                                draft = nil
                            }
                    )
                }
                .accessibilityLabel("Screen preview. Drag to add a redacted region.")

                if let idx = selectedIndex, regions.indices.contains(idx) {
                    Button("Delete selected region", role: .destructive) {
                        regions.remove(at: idx)
                        selectedIndex = nil
                    }
                    .accessibilityLabel("Delete selected redacted region")
                }

                Text(regions.isEmpty ? "No redacted regions" : "\(regions.count) redacted region\(regions.count == 1 ? "" : "s")")
                    .font(AegisType.caption)
                    .foregroundStyle(AegisColors.textSecondary)
                    .padding(.bottom, AegisLayout.m)
            }
            .navigationTitle("Redact screen share")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Save") {
                        onSave(regions)
                        dismiss()
                    }
                    .accessibilityLabel("Save redacted regions")
                }
            }
        }
    }

    /// Screen-proportioned canvas centered in the available space.
    private func canvasRect(in size: CGSize) -> CGRect {
        let aspect: CGFloat = 9.0 / 19.5
        var w = size.width - AegisLayout.xl * 2
        var h = w / aspect
        if h > size.height {
            h = size.height
            w = h * aspect
        }
        return CGRect(
            x: (size.width - w) / 2,
            y: (size.height - h) / 2,
            width: w,
            height: h
        )
    }

    private func toUnit(_ point: CGPoint, in canvas: CGRect) -> CGPoint {
        CGPoint(
            x: (point.x - canvas.minX) / canvas.width,
            y: (point.y - canvas.minY) / canvas.height
        )
    }

    private func unitRect(_ unit: CGRect, in canvas: CGRect) -> CGRect {
        CGRect(
            x: canvas.minX + unit.minX * canvas.width,
            y: canvas.minY + unit.minY * canvas.height,
            width: unit.width * canvas.width,
            height: unit.height * canvas.height
        )
    }

    /// A redaction rectangle positioned on the canvas.
    private func regionRect(_ unit: CGRect, in canvas: CGRect, selected: Bool) -> some View {
        let r = unitRect(unit, in: canvas)
        return Rectangle()
            .fill(Color.black.opacity(0.9))
            .overlay {
                Rectangle()
                    .stroke(selected ? AegisColors.accent : Color.clear, lineWidth: 3)
            }
            .frame(width: r.width, height: r.height)
            .position(x: r.midX, y: r.midY)
    }
}

#Preview {
    ScreenShareRedactView(regions: [CGRect(x: 0.1, y: 0.2, width: 0.8, height: 0.15)]) { _ in }
}
