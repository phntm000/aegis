import AVFoundation
import SwiftUI

/// QR code scanner for adding contacts and joining groups. Handles every
/// camera-permission state with guidance instead of a dead screen.
struct ScannerView: View {
    var onScanned: (String) -> Void
    @Environment(\.dismiss) private var dismiss

    @State private var permission: AVAuthorizationStatus = .notDetermined
    @State private var torchOn = false
    @State private var didScan = false
    /// Set once the user taps through the pre-permission rationale, so the
    /// system prompt only ever fires from an explicit user action.
    @State private var didRequestPermission = false

    var body: some View {
        NavigationStack {
            Group {
                switch permission {
                case .authorized:
                    ZStack {
                        ScannerCameraView(onScanned: handleScan, torchOn: $torchOn)
                            .ignoresSafeArea()
                        scanOverlay
                    }
                case .notDetermined:
                    if didRequestPermission {
                        LoadingOverlayView(label: "Requesting camera access…")
                    } else {
                        cameraRationale
                    }
                case .denied, .restricted:
                    PermissionDeniedView(
                        icon: "qrcode.viewfinder",
                        title: "Camera access needed",
                        message: "Aegis scans QR codes on-device to add contacts. Nothing is uploaded."
                    )
                @unknown default:
                    PermissionDeniedView(
                        icon: "qrcode.viewfinder",
                        title: "Camera unavailable",
                        message: "The camera can't be used right now."
                    )
                }
            }
            .navigationTitle("Scan QR code")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
                if permission == .authorized {
                    ToolbarItem(placement: .primaryAction) {
                        Button {
                            torchOn.toggle()
                        } label: {
                            Image(systemName: torchOn ? "flashlight.on.fill" : "flashlight.off.fill")
                                .accessibilityLabel(torchOn ? "Turn flashlight off" : "Turn flashlight on")
                        }
                    }
                }
            }
            .onAppear {
                permission = AVCaptureDevice.authorizationStatus(for: .video)
            }
        }
    }

    /// Pre-permission rationale (HIG): explain the value before the
    /// system prompt appears, so the user can decide with context.
    private var cameraRationale: some View {
        VStack(spacing: AegisLayout.l) {
            Spacer()
            Image(systemName: "qrcode.viewfinder")
                .font(.system(size: 52))
                .foregroundStyle(AegisColors.accent)
                .accessibilityHidden(true)
            Text("Scan to add contacts")
                .font(AegisType.title)
                .foregroundStyle(AegisColors.textPrimary)
            Text("Aegis needs the camera to scan your contact's identity QR code. Scanning happens entirely on this device — nothing is uploaded or shared.")
                .font(AegisType.body)
                .foregroundStyle(AegisColors.textSecondary)
                .multilineTextAlignment(.center)
            Button("Continue") {
                requestCameraAccess()
            }
            .buttonStyle(.borderedProminent)
            .tint(AegisColors.accent)
            .frame(minHeight: AegisLayout.minTapTarget)
            .accessibilityHint("Shows the system camera permission prompt")
            Button("Not now") { dismiss() }
                .foregroundStyle(AegisColors.textSecondary)
                .frame(minHeight: AegisLayout.minTapTarget)
            Spacer()
        }
        .padding(.horizontal, AegisLayout.l)
    }

    private func requestCameraAccess() {
        didRequestPermission = true
        AVCaptureDevice.requestAccess(for: .video) { granted in
            Task { @MainActor in
                permission = granted ? .authorized : .denied
            }
        }
    }

    private var scanOverlay: some View {
        VStack {
            Spacer()
            RoundedRectangle(cornerRadius: AegisLayout.radiusL)
                .stroke(AegisColors.textOnAccent, lineWidth: 3)
                .frame(width: 240, height: 240)
                .accessibilityHidden(true)
            Text("Point at a contact's identity QR")
                .font(AegisType.callout)
                .foregroundStyle(.white)
                .padding(.top, AegisLayout.l)
                .shadow(radius: 4)
            Spacer()
        }
        .padding()
        .allowsHitTesting(false)
    }

    private func handleScan(_ payload: String) {
        guard !didScan else { return }
        didScan = true
        Haptics.notification(.success)
        dismiss()
        onScanned(payload)
    }
}

// MARK: - Camera plumbing

private struct ScannerCameraView: UIViewControllerRepresentable {
    var onScanned: (String) -> Void
    @Binding var torchOn: Bool

    func makeUIViewController(context: Context) -> ScannerViewController {
        let controller = ScannerViewController()
        controller.onScanned = onScanned
        return controller
    }

    func updateUIViewController(_ uiViewController: ScannerViewController, context: Context) {
        uiViewController.setTorch(on: torchOn)
    }
}

private final class ScannerViewController: UIViewController, AVCaptureMetadataOutputObjectsDelegate {
    var onScanned: ((String) -> Void)?
    // AVCaptureSession isn't Sendable; deinit is nonisolated. The session is
    // only ever touched on the main actor (or in deinit), so this is safe.
    nonisolated(unsafe) private var session: AVCaptureSession?
    private var didFire = false

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .black

        let session = AVCaptureSession()
        guard let device = AVCaptureDevice.default(for: .video),
              let input = try? AVCaptureDeviceInput(device: device),
              session.canAddInput(input) else { return }
        session.addInput(input)

        let output = AVCaptureMetadataOutput()
        guard session.canAddOutput(output) else { return }
        session.addOutput(output)
        output.setMetadataObjectsDelegate(self, queue: .main)
        output.metadataObjectTypes = [.qr]

        let preview = AVCaptureVideoPreviewLayer(session: session)
        preview.videoGravity = .resizeAspectFill
        preview.frame = view.bounds
        view.layer.addSublayer(preview)

        self.session = session
        // startRunning blocks until the session is up; this runs once during
        // presentation and keeps the code free of Sendable gymnastics.
        session.startRunning()
    }

    override func viewDidLayoutSubviews() {
        super.viewDidLayoutSubviews()
        (view.layer.sublayers?.first as? AVCaptureVideoPreviewLayer)?.frame = view.bounds
    }

    // Nonisolated to satisfy the delegate protocol; hops back to the main
    // actor (the delegate queue is .main) before touching view state.
    nonisolated func metadataOutput(
        _ output: AVCaptureMetadataOutput,
        didOutput metadataObjects: [AVMetadataObject],
        from connection: AVCaptureConnection
    ) {
        guard let code = metadataObjects.first as? AVMetadataMachineReadableCodeObject,
              let value = code.stringValue, !value.isEmpty else { return }
        Task { @MainActor [weak self] in
            self?.handleScanned(value)
        }
    }

    @MainActor
    private func handleScanned(_ value: String) {
        guard !didFire else { return }
        didFire = true
        session?.stopRunning()
        onScanned?(value)
    }

    func setTorch(on: Bool) {
        guard let device = AVCaptureDevice.default(for: .video), device.hasTorch else { return }
        do {
            try device.lockForConfiguration()
            device.torchMode = on ? .on : .off
            device.unlockForConfiguration()
        } catch {
            // Torch unavailable — the toggle simply does nothing.
        }
    }

    deinit {
        session?.stopRunning()
    }
}

#Preview {
    ScannerView(onScanned: { _ in })
}
