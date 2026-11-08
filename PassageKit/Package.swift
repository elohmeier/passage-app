// swift-tools-version: 6.2
import PackageDescription

let package = Package(
    name: "PassageKit",
    platforms: [.iOS(.v26), .macOS(.v26)],
    products: [
        .library(name: "AgeCrypto", targets: ["AgeCrypto"]),
        .library(name: "KeyStore", targets: ["KeyStore"]),
        .library(name: "PassStore", targets: ["PassStore"]),
    ],
    targets: [
        .target(name: "AgeCrypto"),
        .target(name: "KeyStore", dependencies: ["AgeCrypto"]),
        .target(name: "PassStore", dependencies: ["AgeCrypto"]),
        .testTarget(
            name: "AgeCryptoTests",
            dependencies: ["AgeCrypto"],
            resources: [.copy("testkit")]
        ),
        .testTarget(name: "KeyStoreTests", dependencies: ["KeyStore"]),
        .testTarget(name: "PassStoreTests", dependencies: ["PassStore"]),
    ]
)
