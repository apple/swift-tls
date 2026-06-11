// swift-tools-version: 6.3
// The swift-tools-version declares the minimum version of Swift required to build this package.
//===----------------------------------------------------------------------===//
//
// This source file is part of the Swift open source project
//
// Copyright (c) 2026 Apple Inc. and the Swift project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of Swift project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import PackageDescription

// Availability Macros

let availabilityTags: [_Availability] = [
    _Availability("SwiftTLS"),
]
let versionNumbers = ["0.1.0"]

// Availability Macro Utilities
enum _OSAvailability: String {
    // The OS versions in which `SwiftTLS 0.1.0` APIs first became available.
    case alwaysAvailable = "macOS 26, iOS 26, tvOS 26, watchOS 26, visionOS 26"
    // Use 10000 for future availability to avoid compiler magic around the 9999 version number but ensure it is greater than 9999"
    case future = "macOS 10000, iOS 10000, tvOS 10000, watchOS 10000, visionOS 10000"
}

struct _Availability {
    let name: String
    let osAvailability: _OSAvailability

    init(_ name: String, osAvailability: _OSAvailability = .alwaysAvailable) {
        self.name = name
        self.osAvailability = osAvailability
    }
}
let availabilityMacros: [SwiftSetting] = versionNumbers.flatMap { version in
    availabilityTags.map {
        .enableExperimentalFeature("AvailabilityMacro=\($0.name) \(version):\($0.osAvailability.rawValue)")
    }
}

var packageDependencies = [PackageDescription.Package.Dependency]()
var targetDependencies = [PackageDescription.Target.Dependency]()

var settings: [SwiftSetting]? = [
    // Add build settings here
    .enableExperimentalFeature("Lifetimes"),
]

#if os(Linux)
packageDependencies = [
    .package(url: "https://github.com/apple/swift-log.git", from: "1.0.0"),
    .package(url: "https://github.com/apple/swift-crypto.git", from: "5.0.0-beta.1"),
]
targetDependencies = [
    .product(name: "Logging", package: "swift-log"),
    .product(name: "Crypto", package: "swift-crypto"),
    .product(name: "CryptoExtras", package: "swift-crypto"),
]
#else
packageDependencies = [
    .package(url: "https://github.com/apple/swift-crypto.git", from: "5.0.0-beta.1")
]
targetDependencies = [
    .product(name: "Crypto", package: "swift-crypto"),
    .product(name: "CryptoExtras", package: "swift-crypto"),
]
#endif

let package = Package(
    name: "swift-tls",
    products: [
        // Products define the executables and libraries a package produces, making them visible to other packages.
        .library(
            name: "SwiftTLS",
            targets: ["SwiftTLS"]),
    ],
    dependencies: packageDependencies,
    targets: [
        // Targets are the basic building blocks of a package, defining a module or a test suite.
        // Targets can depend on other targets in this package and products from dependencies.
        .target(
            name: "SwiftTLS",
            dependencies: targetDependencies,
            swiftSettings: availabilityMacros + (settings ?? [])
        ),
        .testTarget(
            name: "SwiftTLSTests",
            dependencies: ["SwiftTLS"],
            swiftSettings: availabilityMacros + (settings ?? [])
        ),
    ]
)
