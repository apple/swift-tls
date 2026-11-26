// swift-tools-version: 6.3
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

let settings: [SwiftSetting] = [
    .enableExperimentalFeature(
        "AvailabilityMacro=SwiftTLS 0.1.0:macOS 26, iOS 26, tvOS 26, watchOS 26, visionOS 26"
    ),
    .enableUpcomingFeature("ExistentialAny"),
]

let cryptoDependency: Target.Dependency = .product(
    name: "Crypto",
    package: "swift-crypto",
    condition: .when(platforms: [.linux, .android])
)

let package = Package(
    name: "swift-tls-benchmarks",
    platforms: [
        .macOS(.v26)
    ],
    dependencies: [
        .package(name: "swift-tls", path: "../"),
        .package(url: "https://github.com/apple/swift-crypto.git", from: "5.0.0-beta.1"),
        .package(url: "https://github.com/ordo-one/package-benchmark.git", from: "1.36.2"),
    ],
    targets: [
        .target(
            name: "TLSBenchmarkSupport",
            dependencies: [
                .product(name: "Benchmark", package: "package-benchmark"),
                .product(name: "SwiftTLS", package: "swift-tls"),
                cryptoDependency,
            ],
            path: "Sources/TLSBenchmarkSupport",
            swiftSettings: settings
        ),
        .executableTarget(
            name: "HandshakeBenchmarks",
            dependencies: [
                .product(name: "Benchmark", package: "package-benchmark"),
                .product(name: "SwiftTLS", package: "swift-tls"),
                "TLSBenchmarkSupport",
                cryptoDependency,
            ],
            path: "Benchmarks/HandshakeBenchmarks",
            swiftSettings: settings,
            plugins: [
                .plugin(name: "BenchmarkPlugin", package: "package-benchmark")
            ]
        ),
        .executableTarget(
            name: "RecordBenchmarks",
            dependencies: [
                .product(name: "Benchmark", package: "package-benchmark"),
                .product(name: "SwiftTLS", package: "swift-tls"),
                "TLSBenchmarkSupport",
                cryptoDependency,
            ],
            path: "Benchmarks/RecordBenchmarks",
            swiftSettings: settings,
            plugins: [
                .plugin(name: "BenchmarkPlugin", package: "package-benchmark")
            ]
        ),
    ]
)
