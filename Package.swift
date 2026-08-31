// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "IntentAuthorityKit",
    platforms: [
        .iOS(.v17),
        .macOS(.v14)
    ],
    products: [
        .library(name: "IntentAuthority", targets: ["IntentAuthority"]),
        .library(name: "IntentAuthorityUI", targets: ["IntentAuthorityUI"])
    ],
    targets: [
        .target(
            name: "IntentAuthority",
            swiftSettings: [.swiftLanguageMode(.v6)]
        ),
        .target(
            name: "IntentAuthorityUI",
            dependencies: ["IntentAuthority"],
            swiftSettings: [.swiftLanguageMode(.v6)]
        ),
        .testTarget(
            name: "IntentAuthorityTests",
            dependencies: ["IntentAuthority"],
            swiftSettings: [.swiftLanguageMode(.v6)]
        )
    ]
)
