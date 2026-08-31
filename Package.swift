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
        // Depends on BOTH modules on purpose. `IntentAuthorityUI` previously had
        // no tests on any platform, which meant the seven-row scenario table
        // both READMEs print could drift from what the policy actually returns
        // and nothing would notice. `AuthorityScenario` is plain Swift — only
        // `AuthorityConsoleView` is behind `#if canImport(SwiftUI)` — so the
        // catalog is testable on Linux too.
        .testTarget(
            name: "IntentAuthorityTests",
            dependencies: ["IntentAuthority", "IntentAuthorityUI"],
            swiftSettings: [.swiftLanguageMode(.v6)]
        )
    ]
)
