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

@_spi(SwiftTLSOptions) @_spi(SwiftTLSProtocol) import SwiftTLS

#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

/// A counter that a benchmark gates, and the allowance within which its p90 may differ from the
/// recorded one.
@available(SwiftTLS 0.1.0, *)
private struct GatedMetric: Sendable {
    var metric: BenchmarkMetric
    var allowance: any (KeyPath<Tolerance, Int> & Sendable)
}

/// Every gated counter. `gatedMetrics` and the thresholds in `gatedConfiguration` both derive from
/// this table, so a metric cannot be measured without a threshold or the reverse.
@available(SwiftTLS 0.1.0, *)
private let gatedMetricTable: [GatedMetric] = [
    GatedMetric(metric: .mallocCountTotal, allowance: \Tolerance.mallocCount),
    GatedMetric(metric: .objectAllocCount, allowance: \Tolerance.objectAllocationCount),
    GatedMetric(metric: .retainCount, allowance: \Tolerance.retainReleaseCount),
    GatedMetric(metric: .releaseCount, allowance: \Tolerance.retainReleaseCount),
    GatedMetric(metric: .mallocFreeDelta, allowance: \Tolerance.leakedAllocationCount),
]

/// The counters the thresholds gate. They are deterministic for a given toolchain, unlike wall
/// clock time.
@available(SwiftTLS 0.1.0, *)
package let gatedMetrics: [BenchmarkMetric] = gatedMetricTable.map(\.metric)

/// The largest amount a gated counter may differ from its recorded p90 before the check fails.
/// The retain and release allowance applies to both `.retainCount` and `.releaseCount`.
@available(SwiftTLS 0.1.0, *)
package struct Tolerance: Sendable {
    package var mallocCount: Int
    package var objectAllocationCount: Int
    package var retainReleaseCount: Int
    package var leakedAllocationCount: Int

    package init(
        mallocCount: Int,
        objectAllocationCount: Int,
        retainReleaseCount: Int,
        leakedAllocationCount: Int = 0
    ) {
        self.mallocCount = mallocCount
        self.objectAllocationCount = objectAllocationCount
        self.retainReleaseCount = retainReleaseCount
        self.leakedAllocationCount = leakedAllocationCount
    }
}

/// A configuration that gates `gatedMetrics` against the recorded thresholds.
@available(SwiftTLS 0.1.0, *)
package func gatedConfiguration(
    tolerance: Tolerance,
    scalingFactor: BenchmarkScalingFactor = .one,
    maxDuration: Duration = .seconds(10),
    maxIterations: Int = 100
) -> Benchmark.Configuration {
    var thresholds: [BenchmarkMetric: BenchmarkThresholds] = [:]
    for gated in gatedMetricTable {
        thresholds[gated.metric] = .init(absolute: [.p90: tolerance[keyPath: gated.allowance]])
    }

    return .init(
        metrics: gatedMetrics,
        scalingFactor: scalingFactor,
        maxDuration: maxDuration,
        maxIterations: maxIterations,
        thresholds: thresholds
    )
}

/// The signing keys for one server and one client. They are generated once so that signing key
/// generation is not part of what a scenario measures; handshake scenarios still measure
/// ephemeral key agreement.
@available(SwiftTLS 0.1.0, *)
package struct Credentials: Sendable {
    package let serverSigningKey = P256.Signing.PrivateKey()
    package let clientSigningKey = P256.Signing.PrivateKey()

    package init() {}
}

/// The ways a pair of peers can authenticate each other.
@available(SwiftTLS 0.1.0, *)
package enum Authentication: Sendable {
    /// The server proves its identity with a raw public key; the client presents nothing.
    case serverRawPublicKey

    /// Both peers prove their identity with raw public keys.
    case mutualRawPublicKey

    /// Both peers share an external pre-shared key and no signatures are made.
    case externalPreSharedKey
}

/// How the handshake messages travel between the peers.
@available(SwiftTLS 0.1.0, *)
package enum Transport: Sendable {
    /// TLS over a byte stream, driven through `SwiftTLSHandshakeAndRecordManager`.
    case tcp

    /// TLS as QUIC uses it, driven through `SwiftTLSHandshaker`.
    case quic
}

/// What a pair of peers negotiates.
@available(SwiftTLS 0.1.0, *)
package struct HandshakeScenario: Sendable {
    package var cipherSuite: SwiftTLSOptions.CipherSuite
    package var keyExchangeGroup: SwiftTLSOptions.KeyExchangeGroup
    package var authentication: Authentication
    package var transport: Transport

    package init(
        cipherSuite: SwiftTLSOptions.CipherSuite = .AES256GCM_SHA384,
        keyExchangeGroup: SwiftTLSOptions.KeyExchangeGroup = .secp384,
        authentication: Authentication = .serverRawPublicKey,
        transport: Transport = .tcp
    ) {
        self.cipherSuite = cipherSuite
        self.keyExchangeGroup = keyExchangeGroup
        self.authentication = authentication
        self.transport = transport
    }

    private static let serverName = "example.com"
    private static let applicationProtocol = "benchmark"
    private static let quicTransportParameters: [UInt8] = [1, 2, 3]
    private static let presharedKeyBytes: [UInt8] = Array(0..<16)
    private static let presharedKeyIdentity: [UInt8] = Array("benchmark identity".utf8)

    /// The options both peers use.
    private func sharedOptions() -> SwiftTLSOptions {
        var options = SwiftTLSOptions()
        options.serverName = Self.serverName
        options.applicationProtocols = [Self.applicationProtocol]
        options.supportedCipherSuites = [self.cipherSuite]

        switch self.transport {
        case .tcp:
            break

        case .quic:
            options.quicTransportParameters = Self.quicTransportParameters
        }

        switch self.authentication {
        case .serverRawPublicKey, .mutualRawPublicKey:
            break

        case .externalPreSharedKey:
            options.externalPSK = .init(
                externalIdentity: Self.presharedKeyIdentity,
                epsk: SymmetricKey(data: Self.presharedKeyBytes)
            )
        }

        return options
    }

    package func clientOptions(credentials: Credentials) -> SwiftTLSOptions {
        var options = self.sharedOptions()
        options.keyExchangeGroup = self.keyExchangeGroup

        switch self.authentication {
        case .serverRawPublicKey:
            options.trustedRawPublicKeyP256PublicKeys = [credentials.serverSigningKey.publicKey]

        case .mutualRawPublicKey:
            options.trustedRawPublicKeyP256PublicKeys = [credentials.serverSigningKey.publicKey]
            options.privateKey = .p256(credentials.clientSigningKey)

        case .externalPreSharedKey:
            // The pre-shared key authenticates both peers, so there is nothing more to set.
            break
        }

        return options
    }

    package func serverOptions(credentials: Credentials) -> SwiftTLSOptions {
        var options = self.sharedOptions()

        switch self.authentication {
        case .serverRawPublicKey:
            options.privateKey = .p256(credentials.serverSigningKey)

        case .mutualRawPublicKey:
            options.privateKey = .p256(credentials.serverSigningKey)
            options.trustedRawPublicKeyP256PublicKeys = [credentials.clientSigningKey.publicKey]
            options.clientAuthentication = .required

        case .externalPreSharedKey:
            // The pre-shared key authenticates both peers, so there is nothing more to set.
            break
        }

        return options
    }
}

/// Moves everything `sender` has queued for the network to `receiver`.
@available(SwiftTLS 0.1.0, *)
package func deliver(
    from sender: inout SwiftTLSHandshakeAndRecordManager,
    to receiver: inout SwiftTLSHandshakeAndRecordManager
) throws(SwiftTLSError) {
    guard var bytes = sender.getOutput(numBytes: sender.outgoingBytesCount) else {
        return
    }
    // `withUnsafeMutableBytes` on `Array` only rethrows, so the typed error is carried out of the
    // closure in a `Result`.
    let result: Result<Void, SwiftTLSError> = bytes.withUnsafeMutableBytes { buffer in
        do throws(SwiftTLSError) {
            try receiver.processNetworkData(networkDataIn: buffer)
            return .success(())
        } catch {
            return .failure(error)
        }
    }

    try result.get()
}

/// Runs a TLS handshake over TCP between two peers, in memory, until both have finished it.
@available(SwiftTLS 0.1.0, *)
package func completeHandshake(
    client: inout SwiftTLSHandshakeAndRecordManager,
    server: inout SwiftTLSHandshakeAndRecordManager
) throws(SwiftTLSError) {
    try client.startHandshake()
    try deliver(from: &client, to: &server)
    try deliver(from: &server, to: &client)
    try deliver(from: &client, to: &server)
    precondition(
        client.isHandshakeComplete && server.isHandshakeComplete,
        "the in-memory handshake must finish after one flight in each direction"
    )
}

/// Runs a QUIC-style handshake between two handshakers, in memory, until both have reached the
/// application encryption level.
@available(SwiftTLS 0.1.0, *)
package func completeQUICHandshake(
    client: SwiftTLSHandshaker,
    server: SwiftTLSHandshaker,
    clientOptions: SwiftTLSOptions,
    serverOptions: SwiftTLSOptions
) throws(SwiftTLSError) {
    let serverSetupOutput = try server.setupHandshake(options: serverOptions)
    precondition(serverSetupOutput == nil, "a server has nothing to send until it hears from the client")
    guard let clientHello = try client.setupHandshake(options: clientOptions) else {
        preconditionFailure("a client must produce a ClientHello")
    }

    var serverFlights: [[UInt8]] = []
    var nextFlight = try server.continueHandshake(with: clientHello)
    while let flight = nextFlight {
        serverFlights.append(flight)
        nextFlight = try server.continueHandshake()
    }

    var clientFinished: [UInt8]?
    for flight in serverFlights {
        if let output = try client.continueHandshake(with: flight) {
            clientFinished = output
        }
    }

    guard let clientFinished else {
        preconditionFailure("the client must produce Finished after reading the server's flights")
    }
    let serverFinalOutput = try server.continueHandshake(with: clientFinished)
    precondition(serverFinalOutput == nil, "the server has nothing to send after the client's Finished")
    precondition(
        client.readEncryptionLevel == .application && server.readEncryptionLevel == .application,
        "both peers must reach the application encryption level"
    )
}

/// A client and a server that have completed a handshake over TCP.
@available(SwiftTLS 0.1.0, *)
package struct ConnectedPair: ~Copyable {
    package var client: SwiftTLSHandshakeAndRecordManager
    package var server: SwiftTLSHandshakeAndRecordManager

    package init(scenario: HandshakeScenario, credentials: Credentials) throws(SwiftTLSError) {
        var connectedClient = try SwiftTLSHandshakeAndRecordManager(
            options: scenario.clientOptions(credentials: credentials),
            isServer: false
        )
        var connectedServer = try SwiftTLSHandshakeAndRecordManager(
            options: scenario.serverOptions(credentials: credentials),
            isServer: true
        )
        try completeHandshake(client: &connectedClient, server: &connectedServer)
        self.client = connectedClient
        self.server = connectedServer
    }
}
