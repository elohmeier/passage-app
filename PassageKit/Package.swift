// swift-tools-version: 6.2
import PackageDescription

let package = Package(
    name: "PassageKit",
    platforms: [.iOS(.v26), .macOS(.v26)],
    products: [
        .library(name: "AgeCrypto", targets: ["AgeCrypto"]),
    ],
    targets: [
        .target(name: "AgeCrypto"),
        .testTarget(
            name: "AgeCryptoTests",
            dependencies: ["AgeCrypto"],
            resources: [.copy("testkit")]
        ),
    ]
)
