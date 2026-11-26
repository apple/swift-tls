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
        recordBenchmarks()
    }
}

/// The largest plaintext a single TLS record carries.
private let maximumRecordPlaintextByteCount = 16384

/// The size of a write that fits in one record.
private let singleRecordPayloadByteCount = 1024

/// The number of records the multi-record write spans.
private let multipleRecordCount = 4

/// The size of a write that fills `multipleRecordCount` records.
private let multipleRecordPayloadByteCount = multipleRecordCount * maximumRecordPlaintextByteCount

@available(SwiftTLS 0.1.0, *)
private func recordBenchmarks() {
    let credentials = Credentials()

    // The handshake is finished before the measurement starts. One measurement is a thousand
    // writes on that connection, so an extra allocation or retain per write moves the count by
    // about a thousand, far outside the allowance, which only absorbs allocator variation.
    let tolerance = Tolerance(
        mallocCount: 2,
        objectAllocationCount: 2,
        retainReleaseCount: 4
    )

    /// Each iteration of the measurement protects one write on the client, delivers it to the
    /// server and unprotects it there, then consumes the received data so no buffer grows.
    func transfer(_ name: String, cipherSuite: SwiftTLSOptions.CipherSuite, payloadByteCount: Int) {
        let configuration = gatedConfiguration(
            tolerance: tolerance,
            scalingFactor: .kilo,
            maxIterations: 100
        )

        Benchmark(name, configuration: configuration) { benchmark in
            do {
                var pair = try ConnectedPair(
                    scenario: HandshakeScenario(cipherSuite: cipherSuite, keyExchangeGroup: .x25519),
                    credentials: credentials
                )
                let payload = [UInt8](repeating: 0x5A, count: payloadByteCount)

                benchmark.startMeasurement()
                for _ in benchmark.scaledIterations {
                    try pair.client.addApplicationData(bytes: payload)
                    try deliver(from: &pair.client, to: &pair.server)
                    let received = pair.server.getAvailableApplicationData(
                        numBytes: pair.server.availableApplicationDataLength
                    )
                    precondition(received?.count == payloadByteCount, "the server must receive the whole payload")
                    blackHole(received)
                }

                benchmark.stopMeasurement()
            } catch {
                preconditionFailure("the record benchmark failed: \(error)")
            }
        }
    }

    // The two cipher suites take different encryption paths.
    transfer(
        "RecordTransfer_AES128GCM_1_record_\(singleRecordPayloadByteCount)_bytes",
        cipherSuite: .AES128GCM_SHA256,
        payloadByteCount: singleRecordPayloadByteCount
    )

    transfer(
        "RecordTransfer_AES256GCM_1_record_\(singleRecordPayloadByteCount)_bytes",
        cipherSuite: .AES256GCM_SHA384,
        payloadByteCount: singleRecordPayloadByteCount
    )

    // A write larger than one record is split across several.
    transfer(
        "RecordTransfer_AES256GCM_\(multipleRecordCount)_records_\(multipleRecordPayloadByteCount)_bytes",
        cipherSuite: .AES256GCM_SHA384,
        payloadByteCount: multipleRecordPayloadByteCount
    )
}
