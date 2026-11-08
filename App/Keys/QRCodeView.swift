import CoreImage.CIFilterBuiltins
import SwiftUI

/// Renders `text` as a QR code. Post-quantum recipients are about 2,000 characters, so use the
/// lowest error correction level to keep the code scannable.
struct QRCodeView: View {
    let text: String

    var body: some View {
        if let image = Self.render(text) {
            Image(uiImage: image)
                .interpolation(.none)
                .resizable()
                .scaledToFit()
                .frame(maxWidth: 280)
                .accessibilityLabel("QR code")
        } else {
            Label("Too long for a QR code", systemImage: "qrcode")
                .foregroundStyle(.secondary)
        }
    }

    static func render(_ text: String) -> UIImage? {
        let filter = CIFilter.qrCodeGenerator()
        filter.message = Data(text.utf8)
        filter.correctionLevel = "L"
        guard let output = filter.outputImage,
            let cg = CIContext().createCGImage(output, from: output.extent)
        else { return nil }
        return UIImage(cgImage: cg)
    }
}
