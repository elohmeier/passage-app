// swift-tools-version: 6.2
import PackageDescription

// libgit2, vendored as a submodule at the upstream v1.9.2 tag and built without CMake.
// The feature defines below replace the generated git2_features.h (see
// Vendor/libgit2/src/util/git2_features.h.in). HTTPS uses Secure Transport, SHA-1 uses
// collision detection (sha1dc), compression and regex are the bundled implementations. No SSH:
// iOS can't spawn ssh, so a custom transport registers the ssh scheme instead.
let libgit2Sources = ["deps/llhttp", "deps/pcre", "deps/xdiff", "deps/zlib", "src/libgit2", "src/util"]
let libgit2Exclude = [
    "deps/llhttp/CMakeLists.txt", "deps/llhttp/LICENSE-MIT",
    "deps/pcre/CMakeLists.txt", "deps/pcre/config.h.in", "deps/pcre/COPYING", "deps/pcre/LICENCE", "deps/pcre/cmake",
    "deps/xdiff/CMakeLists.txt",
    "deps/zlib/CMakeLists.txt", "deps/zlib/LICENSE",
    "src/libgit2/CMakeLists.txt", "src/libgit2/experimental.h.in", "src/libgit2/config.cmake.in", "src/libgit2/git2.rc",
    "src/util/CMakeLists.txt", "src/util/git2_features.h.in", "src/util/win32",
    "src/util/hash/builtin.c", "src/util/hash/builtin.h", "src/util/hash/rfc6234",
    "src/util/hash/mbedtls.c", "src/util/hash/mbedtls.h", "src/util/hash/openssl.c", "src/util/hash/openssl.h",
    "src/util/hash/win32.c", "src/util/hash/win32.h",
]
let libgit2Settings: [CSetting] = [
    .headerSearchPath("deps/llhttp"), .headerSearchPath("deps/pcre"), .headerSearchPath("deps/xdiff"),
    .headerSearchPath("deps/zlib"), .headerSearchPath("src/libgit2"), .headerSearchPath("src/util"),
    .headerSearchPath("src/util/hash/sha1dc"),
    .define("LIBGIT2_NO_FEATURES_H"),
    .define("GIT_THREADS", to: "1"), .define("GIT_ARCH_64", to: "1"),
    .define("GIT_USE_ICONV", to: "1"), .define("GIT_USE_NSEC", to: "1"), .define("GIT_USE_STAT_MTIMESPEC", to: "1"),
    .define("GIT_USE_FUTIMENS", to: "1"), .define("GIT_QSORT_BSD", to: "1"), .define("GIT_IO_POLL", to: "1"),
    .define("GIT_HTTPS", to: "1"), .define("GIT_SECURE_TRANSPORT", to: "1"), .define("GIT_HTTPPARSER_BUILTIN", to: "1"),
    .define("GIT_SHA1_COLLISIONDETECT", to: "1"), .define("GIT_SHA256_COMMON_CRYPTO", to: "1"),
    .define("SHA1DC_NO_STANDARD_INCLUDES", to: "1"),
    .define("SHA1DC_CUSTOM_INCLUDE_SHA1_C", to: "\"git2_util.h\""),
    .define("SHA1DC_CUSTOM_INCLUDE_UBC_CHECK_C", to: "\"git2_util.h\""),
    .define("GIT_COMPRESSION_BUILTIN", to: "1"), .define("GIT_REGEX_BUILTIN", to: "1"),
    // Bundled PCRE, as configured by deps/pcre/CMakeLists.txt.
    .define("SUPPORT_PCRE8", to: "1"), .define("HAVE_STDINT_H", to: "1"), .define("HAVE_INTTYPES_H", to: "1"),
    .define("HAVE_MEMMOVE", to: "1"), .define("HAVE_STRERROR", to: "1"), .define("LINK_SIZE", to: "2"),
    .define("PARENS_NEST_LIMIT", to: "250"), .define("MATCH_LIMIT", to: "10000000"),
    .define("MATCH_LIMIT_RECURSION", to: "10000000"), .define("NEWLINE", to: "10"), .define("NO_RECURSE", to: "1"),
    .define("POSIX_MALLOC_THRESHOLD", to: "10"), .define("BSR_ANYCRLF", to: "0"), .define("MAX_NAME_SIZE", to: "32"),
    .define("MAX_NAME_COUNT", to: "10000"),
    // With Clang modules, <search.h>'s `struct entry` leaks into deps/xdiff/xpatience.c, which
    // declares its own. Compiling the C sources without modules avoids patching upstream.
    .unsafeFlags(["-fno-modules"]),
    // Upstream's code isn't clean under Xcode's default warnings; don't drown ours.
    .unsafeFlags(["-w"]),
]

let package = Package(
    name: "PassageKit",
    platforms: [.iOS(.v26), .macOS(.v26)],
    products: [
        .library(name: "AgeCrypto", targets: ["AgeCrypto"]),
        .library(name: "KeyStore", targets: ["KeyStore"]),
        .library(name: "PassStore", targets: ["PassStore"]),
        .library(name: "GitSync", targets: ["GitSync"]),
        .library(name: "GitHubKit", targets: ["GitHubKit"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-nio.git", from: "2.105.0"),
        .package(url: "https://github.com/apple/swift-nio-ssh.git", exact: "0.15.1"),
        .package(url: "https://github.com/apple/swift-nio-transport-services.git", from: "1.28.0"),
    ],
    targets: [
        .target(name: "AgeCrypto"),
        .target(name: "KeyStore", dependencies: ["AgeCrypto"]),
        .target(name: "PassStore", dependencies: ["AgeCrypto"], resources: [.copy("Resources/eff_large_wordlist.txt")]),
        .target(
            name: "CGit2", path: "Vendor/libgit2", exclude: libgit2Exclude, sources: libgit2Sources,
            publicHeadersPath: "include", cSettings: libgit2Settings, linkerSettings: [.linkedLibrary("iconv")]),
        .target(
            name: "GitSync",
            dependencies: [
                "CGit2",
                .product(name: "NIOCore", package: "swift-nio"),
                .product(name: "NIOSSH", package: "swift-nio-ssh"),
                .product(name: "NIOTransportServices", package: "swift-nio-transport-services"),
            ]),
        .testTarget(
            name: "AgeCryptoTests",
            dependencies: ["AgeCrypto"],
            resources: [.copy("testkit")]
        ),
        .testTarget(name: "KeyStoreTests", dependencies: ["KeyStore"]),
        .target(name: "GitHubKit"),
        .testTarget(name: "GitHubKitTests", dependencies: ["GitHubKit"]),
        .testTarget(name: "PassStoreTests", dependencies: ["PassStore"]),
        .testTarget(
            name: "GitSyncTests",
            dependencies: [
                "GitSync",
                .product(name: "NIOPosix", package: "swift-nio"),
                .product(name: "NIOSSH", package: "swift-nio-ssh"),
            ]),
    ]
)
