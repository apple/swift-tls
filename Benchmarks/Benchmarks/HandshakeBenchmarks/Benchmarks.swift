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

import Benchmark
import TLSBenchmarkSupport

@_spi(SwiftTLSOptions) @_spi(SwiftTLSProtocol) import SwiftTLS

let benchmarks: @Sendable () -> Void = {
    if #available(SwiftTLS 0.1.0, *) {
        handshakeBenchmarks()
    }
}

@available(SwiftTLS 0.1.0, *)
private func handshakeBenchmarks() {
    let credentials = Credentials()

    // Each scenario builds both peers and runs the handshake inside the measurement, so the counts
    // include ephemeral key generation, key agreement, signing and verification, and the key
    // schedule. The allowances absorb the run-to-run variation in the allocator and in the number
    // of allocations the platform crypto makes.
    let tolerance = Tolerance(
        mallocCount: 2,
        objectAllocationCount: 2,
        retainReleaseCount: 8
    )

    func handshake(_ name: String, scenario: HandshakeScenario) {
        let clientOptions = scenario.clientOptions(credentials: credentials)
        let serverOptions = scenario.serverOptions(credentials: credentials)

        Benchmark(name, configuration: gatedConfiguration(tolerance: tolerance)) { benchmark in
            benchmark.startMeasurement()

            switch scenario.transport {
            case .tcp:
                for _ in benchmark.scaledIterations {
                    do {
                        var client = try SwiftTLSHandshakeAndRecordManager(options: clientOptions, isServer: false)
                        var server = try SwiftTLSHandshakeAndRecordManager(options: serverOptions, isServer: true)
                        try completeHandshake(client: &client, server: &server)
                        blackHole(client.negotiatedApplicationProtocol)
                    } catch {
                        preconditionFailure("the handshake benchmark failed: \(error)")
                    }
                }

            case .quic:
                for _ in benchmark.scaledIterations {
                    do {
                        let client = SwiftTLSHandshaker.createClientHandshake()
                        let server = SwiftTLSHandshaker.createServerHandshake()
                        try completeQUICHandshake(
                            client: client,
                            server: server,
                            clientOptions: clientOptions,
                            serverOptions: serverOptions
                        )
                        blackHole(client.negotiatedApplicationProtocol)
                    } catch {
                        preconditionFailure("the handshake benchmark failed: \(error)")
                    }
                }
            }

            benchmark.stopMeasurement()
        }
    }

    // MARK: - TLS over TCP

    handshake("TLSHandshake_AES256GCM_P384", scenario: HandshakeScenario())

    handshake(
        "TLSHandshake_AES128GCM_X25519",
        scenario: HandshakeScenario(cipherSuite: .AES128GCM_SHA256, keyExchangeGroup: .x25519)
    )

    handshake(
        "TLSHandshake_AES256GCM_X25519MLKEM768",
        scenario: HandshakeScenario(keyExchangeGroup: .x25519MLKEM768)
    )

    handshake(
        "TLSHandshake_mutual_authentication",
        scenario: HandshakeScenario(authentication: .mutualRawPublicKey)
    )

    handshake(
        "TLSHandshake_external_pre_shared_key",
        scenario: HandshakeScenario(authentication: .externalPreSharedKey)
    )

    // MARK: - TLS for QUIC

    handshake("QUICTLSHandshake_AES256GCM_P384", scenario: HandshakeScenario(transport: .quic))

    handshake(
        "QUICTLSHandshake_ChaCha20Poly1305_X25519",
        scenario: HandshakeScenario(
            cipherSuite: .chacha20Poly1305_SHA256,
            keyExchangeGroup: .x25519,
            transport: .quic
        )
    )

    handshake(
        "QUICTLSHandshake_mutual_authentication",
        scenario: HandshakeScenario(authentication: .mutualRawPublicKey, transport: .quic)
    )
}
