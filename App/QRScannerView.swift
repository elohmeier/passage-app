import SwiftUI
import VisionKit

/// Scans a QR code with the camera and returns its text. Used for otpauth:// URIs, age keys and
/// repository URLs. Nothing leaves the device; VisionKit does the recognition locally.
struct QRScannerView: View {
    @Environment(\.dismiss) private var dismiss
    let title: LocalizedStringKey
    /// Return false to keep scanning (e.g. the code isn't the expected kind).
    let accept: (String) -> Bool
    @State private var hint: String?

    var body: some View {
        NavigationStack {
            Group {
                if DataScannerViewController.isSupported && DataScannerViewController.isAvailable {
                    Scanner { text in
                        if accept(text) {
                            dismiss()
                        } else {
                            hint = String(localized: "That code isn't what Passage expects here.")
                        }
                    }
                    .ignoresSafeArea()
                    .overlay(alignment: .bottom) {
                        if let hint {
                            Text(hint).font(.footnote).padding(10).glassEffect().padding()
                        }
                    }
                } else {
                    ContentUnavailableView(
                        "Camera Unavailable", systemImage: "camera",
                        description: Text("Allow camera access for Passage in Settings, or paste the text instead."))
                }
            }
            .navigationTitle(title)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel", role: .cancel) { dismiss() } }
            }
        }
    }

    private struct Scanner: UIViewControllerRepresentable {
        let found: (String) -> Void

        func makeUIViewController(context: Context) -> DataScannerViewController {
            let scanner = DataScannerViewController(
                recognizedDataTypes: [.barcode(symbologies: [.qr])], qualityLevel: .accurate, isHighlightingEnabled: true)
            scanner.delegate = context.coordinator
            try? scanner.startScanning()
            return scanner
        }

        func updateUIViewController(_ controller: DataScannerViewController, context: Context) {}

        func makeCoordinator() -> Coordinator { Coordinator(found: found) }

        final class Coordinator: NSObject, DataScannerViewControllerDelegate {
            let found: (String) -> Void
            init(found: @escaping (String) -> Void) { self.found = found }

            func dataScanner(_ dataScanner: DataScannerViewController, didAdd addedItems: [RecognizedItem], allItems: [RecognizedItem]) {
                for item in addedItems {
                    if case .barcode(let barcode) = item, let text = barcode.payloadStringValue {
                        found(text)
                        return
                    }
                }
            }
        }
    }
}
