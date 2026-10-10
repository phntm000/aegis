import CoreImage.CIFilterBuiltins
import SwiftUI
import UIKit

/// QR generation for identity sharing and group invites.
/// Payloads are produced by AegisCrypto (`qrPayload(for:)`); this file only
/// renders them. QR is always black-on-white for scanner reliability, even in
/// dark mode.
enum QRCode {
    /// Render a QR `UIImage` for a payload string, or nil if encoding fails.
    static func image(from payload: String, size: CGFloat = 240) -> UIImage? {
        guard let data = payload.data(using: .utf8) else { return nil }
        let filter = CIFilter.qrCodeGenerator()
        filter.message = data
        filter.correctionLevel = "H"
        guard let output = filter.outputImage else { return nil }

        // Scale up with no interpolation so modules stay crisp.
        let scale = size / output.extent.width
        let scaled = output.transformed(by: CGAffineTransform(scaleX: scale, y: scale))

        // Composite over white — scanners need the quiet zone.
        let white = CIImage(color: .white).cropped(to: scaled.extent)
        let composed = scaled.composited(over: white)

        let context = CIContext(options: [.useSoftwareRenderer: false])
        guard let cgImage = context.createCGImage(composed, from: composed.extent) else {
            return nil
        }
        return UIImage(cgImage: cgImage)
    }
}

/// SwiftUI wrapper that renders a QR code or a graceful fallback.
struct QRCodeView: View {
    let payload: String
    var size: CGFloat = 220

    var body: some View {
        Group {
            if let image = QRCode.image(from: payload, size: size) {
                Image(uiImage: image)
                    .interpolation(.none)
                    .resizable()
                    .frame(width: size, height: size)
                    .clipShape(RoundedRectangle(cornerRadius: AegisLayout.radiusM))
                    .accessibilityLabel("QR code for sharing")
            } else {
                RoundedRectangle(cornerRadius: AegisLayout.radiusM)
                    .fill(AegisColors.surfacePressed)
                    .frame(width: size, height: size)
                    .overlay {
                        Text("Could not generate QR code")
                            .font(AegisType.footnote)
                            .foregroundStyle(AegisColors.textSecondary)
                            .multilineTextAlignment(.center)
                            .padding()
                    }
                    .accessibilityLabel("QR code unavailable")
            }
        }
    }
}
