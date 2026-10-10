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
                    LoadingOverlayView(label: "Requesting camera access…")
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
                if permission == .notDetermined {
                    AVCaptureDevice.requestAccess(for: .video) { granted in
                        Task { @MainActor in
                            permission = granted ? .authorized : .denied
                        }
                    }
                }
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
    private var session: AVCaptureSession?
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

    func metadataOutput(
        _ output: AVCaptureMetadataOutput,
        didOutput metadataObjects: [AVMetadataObject],
        from connection: AVCaptureConnection
    ) {
        guard !didFire,
              let code = metadataObjects.first as? AVMetadataMachineReadableCodeObject,
              let value = code.stringValue, !value.isEmpty else { return }
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
