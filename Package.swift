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

var packageDependencies = [PackageDescription.Package.Dependency]()
var targetDependencies = [PackageDescription.Target.Dependency]()

var settings: [SwiftSetting] = [
    // Add build settings here
    .enableExperimentalFeature("Lifetimes"),
    .enableExperimentalFeature("AnyAppleOSAvailability"),
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
            swiftSettings: settings
        ),
        .testTarget(
            name: "SwiftTLSTests",
            dependencies: ["SwiftTLS"],
            swiftSettings: settings
        ),
    ]
)
