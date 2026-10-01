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

import XCTest
#if canImport(SwiftTLS) && !SWIFTTLS_BUILTIN_TESTS
@_spi(SwiftTLSOptions) @_spi(SwiftTLSProtocol) @testable import SwiftTLS
#endif
#if canImport(CryptoKit)
import CryptoKit
#elseif canImport(Crypto)
@preconcurrency import Crypto
#endif

@available(SwiftTLS 0.1.0, *)
class SwiftTLSProtocolTests: XCTestCase {
    var serverSigningKey = P256.Signing.PrivateKey()
    var clientSigningKey = P256.Signing.PrivateKey()

    var epskData: [UInt8] = [
        0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a, 0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68,
        0xc8, 0x4e,
    ]
    var epskIdentity: [UInt8] = [ 0x65, 0x70, 0x73, 0x6B ]

    func defaultClientOptions(quic: Bool = true, clientAuth: Bool = false, refKey: Bool = false, rawKeys: Bool = false, externalPSKs: Bool = false) -> SwiftTLSOptions {
        var clientOptions = SwiftTLSOptions()
        clientOptions.serverName = "example.com"
        if quic {
            clientOptions.quicTransportParameters = [1, 2, 3]
        }

        clientOptions.applicationProtocols = ["foo", "bar"]
        if externalPSKs {
            clientOptions.externalPSK = .init(externalIdentity: epskIdentity, epsk: SymmetricKey(data: epskData))
        } else {
            if clientAuth {
                if rawKeys {
                    clientOptions.rawPrivateKey = Array(clientSigningKey.rawRepresentation)
                } else {
                    clientOptions.privateKey = .p256(clientSigningKey)
                }
                if refKey {
                    clientOptions.privateKey = .opaqueReference(SwiftTLSOpaqueReferenceKey(clientSigningKey.publicKey) { (data: Data, sigAlg: UInt16) -> Data? in
                        do {
                            return try self.clientSigningKey.signature(for: data).derRepresentation
                        } catch {
                            return nil
                        }
                    })
                }
            }
            clientOptions.trustedRawPublicKeyP256PublicKeys = [serverSigningKey.publicKey]
            clientOptions.enableEarlyData = true
        }
        clientOptions.sessionState = nil
        clientOptions.newSessionTicketRequestCount = 0
        clientOptions.resumedSessionTicketRequestCount = 0
        clientOptions.keyExchangeGroup = .secp384
        return clientOptions
    }

    func defaultServerOptions(quic: Bool = true, clientAuth: Bool = false, refKey: Bool = false, rawKeys: Bool = false, externalPSKs: Bool = false) -> SwiftTLSOptions {
        var serverOptions = SwiftTLSOptions()
        serverOptions.serverName = "example.com"
        if quic {
            serverOptions.quicTransportParameters = [1, 2, 3]
        }
        serverOptions.applicationProtocols = ["bar"]
        if externalPSKs {
            serverOptions.externalPSK = .init(externalIdentity: epskIdentity, epsk: SymmetricKey(data: epskData))
        } else {
            if rawKeys {
                serverOptions.rawPrivateKey = Array(serverSigningKey.rawRepresentation)
            } else {
                serverOptions.privateKey = .p256(serverSigningKey)
            }
            if refKey {
                serverOptions.privateKey = .opaqueReference(SwiftTLSOpaqueReferenceKey(serverSigningKey.publicKey) { (data: Data, sigAlg: UInt16) -> Data? in
                    do {
                        return try self.serverSigningKey.signature(for: data).derRepresentation
                    } catch {
                        return nil
                    }
                })
            }
            serverOptions.trustedRawPublicKeyP256PublicKeys = clientAuth ? [clientSigningKey.publicKey] : nil
        }
        serverOptions.clientAuthRequired = clientAuth
        return serverOptions
    }

    func testHandshakerSetup() throws {
        let clientOptions = defaultClientOptions()
        let serverOptions = defaultServerOptions()

        let server = SwiftTLSServerHandshaker()
        XCTAssertNil(try server.setupHandshake(options: serverOptions))

        let client = SwiftTLSClientHandshaker()
        guard try client.setupHandshake(options: clientOptions) != nil else {
            XCTFail("Failed to setup handshake")
            return
        }
    }

    func testHandshakerHappyPath_NoEarlyData() throws {
        let clientOptions = defaultClientOptions()
        let serverOptions = defaultServerOptions()

        let server = SwiftTLSServerHandshaker()
        XCTAssertNil(try server.setupHandshake(options: serverOptions))
        XCTAssertEqual(server.readEncryptionLevel, .initial)
        XCTAssertEqual(server.writeEncryptionLevel, .initial)

        let client = SwiftTLSClientHandshaker()
        guard let clientHelloBytes = try client.setupHandshake(options: clientOptions) else {
            XCTFail("Failed to setup handshake. Nil client hello bytes")
            return
        }
        XCTAssertEqual(client.readEncryptionLevel, .initial)
        XCTAssertEqual(client.writeEncryptionLevel, .earlyData)

        // send client hello
        guard let serverHelloBytes = try server.continueHandshake(with: clientHelloBytes.span.bytes) else {
            XCTFail("Failed to setup handshake. Nil server hello bytes")
            return
        }
        XCTAssertEqual(server.readEncryptionLevel, .handshake)
        XCTAssertEqual(server.writeEncryptionLevel, .handshake)

        guard let serverEEBytes = try server.continueHandshake() else {
            XCTFail("Failed to setup handshake. Nil server EE bytes")
            return
        }
        XCTAssertEqual(server.readEncryptionLevel, .handshake)
        XCTAssertEqual(server.writeEncryptionLevel, .handshake)

        guard let serverCertificateBytes = try server.continueHandshake() else {
            XCTFail("Failed to setup handshake. Nil server certificate bytes")
            return
        }
        XCTAssertEqual(server.readEncryptionLevel, .handshake)
        XCTAssertEqual(server.writeEncryptionLevel, .handshake)

        guard let serverCertificateVerifyBytes = try server.continueHandshake() else {
            XCTFail("Failed to setup handshake. Nil server certificate verify bytes")
            return
        }
        XCTAssertEqual(server.readEncryptionLevel, .handshake)
        XCTAssertEqual(server.writeEncryptionLevel, .handshake)

        guard let serverFinishedBytes = try server.continueHandshake() else {
            XCTFail("Failed to setup handshake. Nil server finished bytes")
            return
        }
        XCTAssertEqual(server.readEncryptionLevel, .handshake)
        XCTAssertEqual(server.writeEncryptionLevel, .application)

        // send server hello
        var res = try client.continueHandshake(with: serverHelloBytes.span.bytes)
        XCTAssertNil(res)
        XCTAssertEqual(client.readEncryptionLevel, .handshake)
        XCTAssertEqual(client.writeEncryptionLevel, .handshake)

        // send server EE
        res = try client.continueHandshake(with: serverEEBytes.span.bytes)
        XCTAssertNil(res)
        XCTAssertEqual(client.readEncryptionLevel, .handshake)
        XCTAssertEqual(client.writeEncryptionLevel, .handshake)

        // send server cert
        res = try client.continueHandshake(with: serverCertificateBytes.span.bytes)
        XCTAssertNil(res)
        XCTAssertEqual(client.readEncryptionLevel, .handshake)
        XCTAssertEqual(client.writeEncryptionLevel, .handshake)

        // send server cert verify
        res = try client.continueHandshake(with: serverCertificateVerifyBytes.span.bytes)
        XCTAssertNil(res)
        XCTAssertEqual(client.readEncryptionLevel, .handshake)
        XCTAssertEqual(client.writeEncryptionLevel, .handshake)

        // send server finished
        guard let clientFinishedBytes = try client.continueHandshake(with: serverFinishedBytes.span.bytes) else {
            XCTFail("Failed to setup handshake. Nil client finished bytes")
            return
        }
        XCTAssertEqual(client.readEncryptionLevel, .application)
        XCTAssertEqual(client.writeEncryptionLevel, .application)

        // send client finished
        res = try server.continueHandshake(with: clientFinishedBytes.span.bytes)
        XCTAssertNil(res)
        XCTAssertEqual(server.readEncryptionLevel, .application)
        XCTAssertEqual(server.writeEncryptionLevel, .application)
    }

    /// A peer that closes its write side in the same flight as its last handshake message leaves
    /// the handshake complete and the read side closed at the same time.
    ///
    /// `state` can only report one of those, and reports `.readclosed`, so a consumer watching for
    /// `.connected` to learn that the handshake finished never sees it. `isHandshakeComplete`
    /// answers that question on its own and has to stay true here, otherwise the data the
    /// handshake protected is never handed to the application.
    func testHandshakeCompleteWithCloseNotifyInSameFlight() throws {
        let clientOptions = defaultClientOptions(quic: false)
        let serverOptions = defaultServerOptions(quic: false)

        var client = try SwiftTLSHandshakeAndRecordManager(options: clientOptions, isServer: false)
        var server = try SwiftTLSHandshakeAndRecordManager(options: serverOptions, isServer: true)

        // Run the handshake up to the point where only the client's last flight is outstanding.
        try client.startHandshake()
        guard var clientHello = client.getOutput(numBytes: client.outgoingBytesCount) else {
            XCTFail("no client hello")
            return
        }
        try clientHello.withUnsafeMutableBytes { try server.processNetworkData(networkDataIn: $0) }
        guard var serverFlight = server.getOutput(numBytes: server.outgoingBytesCount) else {
            XCTFail("no server flight")
            return
        }
        try serverFlight.withUnsafeMutableBytes { try client.processNetworkData(networkDataIn: $0) }
        XCTAssertTrue(client.isHandshakeComplete, "client should be through its handshake")

        // The client's remaining flight, its application data, and its close all go out together,
        // which is what an application that writes once and closes produces.
        let payload = Array("hello".utf8)
        try client.addApplicationData(bytes: payload)
        try client.sendCloseNotify()
        guard var clientFlight = client.getOutput(numBytes: client.outgoingBytesCount) else {
            XCTFail("no client flight")
            return
        }
        try clientFlight.withUnsafeMutableBytes { try server.processNetworkData(networkDataIn: $0) }

        XCTAssertTrue(
            server.isHandshakeComplete,
            "the server read the client's Finished, so its handshake is complete"
        )
        XCTAssertEqual(server.state, .readclosed, "the client's close closed the read side")
        XCTAssertEqual(
            server.getAvailableApplicationData(numBytes: server.availableApplicationDataLength)
                .map { [UInt8]($0) },
            payload,
            "the data the handshake protected has to be readable"
        )
    }

    func runHandshakerHappyPath_NoEarlyData_MutualRPK(clientOptions: SwiftTLSOptions, serverOptions: SwiftTLSOptions) throws {
        let server = SwiftTLSServerHandshaker()
        XCTAssertNil(try server.setupHandshake(options: serverOptions))
        XCTAssertEqual(server.readEncryptionLevel, .initial)
        XCTAssertEqual(server.writeEncryptionLevel, .initial)

        let client = SwiftTLSClientHandshaker()
        guard let clientHelloBytes = try client.setupHandshake(options: clientOptions) else {
            XCTFail("Failed to setup handshake. Nil client hello bytes")
            return
        }
        XCTAssertEqual(client.readEncryptionLevel, .initial)
        XCTAssertEqual(client.writeEncryptionLevel, .earlyData)

        // send client hello
        guard let serverHelloBytes = try server.continueHandshake(with: clientHelloBytes.span.bytes) else {
            XCTFail("Failed to setup handshake. Nil server hello bytes")
            return
        }
        XCTAssertEqual(server.readEncryptionLevel, .handshake)
        XCTAssertEqual(server.writeEncryptionLevel, .handshake)

        guard let serverEEBytes = try server.continueHandshake() else {
            XCTFail("Failed to setup handshake. Nil server EE bytes")
            return
        }
        XCTAssertEqual(server.readEncryptionLevel, .handshake)
        XCTAssertEqual(server.writeEncryptionLevel, .handshake)

        guard let serverCertificateRequestBytes = try server.continueHandshake() else {
            XCTFail("Failed to setup handshake. Nil server certificate request bytes")
            return
        }
        XCTAssertEqual(server.readEncryptionLevel, .handshake)
        XCTAssertEqual(server.writeEncryptionLevel, .handshake)

        guard let serverCertificateBytes = try server.continueHandshake() else {
            XCTFail("Failed to setup handshake. Nil server certificate bytes")
            return
        }
        XCTAssertEqual(server.readEncryptionLevel, .handshake)
        XCTAssertEqual(server.writeEncryptionLevel, .handshake)

        guard let serverCertificateVerifyBytes = try server.continueHandshake() else {
            XCTFail("Failed to setup handshake. Nil server certificate verify bytes")
            return
        }
        XCTAssertEqual(server.readEncryptionLevel, .handshake)
        XCTAssertEqual(server.writeEncryptionLevel, .handshake)

        guard let serverFinishedBytes = try server.continueHandshake() else {
            XCTFail("Failed to setup handshake. Nil server finished bytes")
            return
        }
        XCTAssertEqual(server.readEncryptionLevel, .handshake)
        XCTAssertEqual(server.writeEncryptionLevel, .application)

        // send server hello
        var res = try client.continueHandshake(with: serverHelloBytes.span.bytes)
        XCTAssertNil(res)
        XCTAssertEqual(client.readEncryptionLevel, .handshake)
        XCTAssertEqual(client.writeEncryptionLevel, .handshake)

        // send server EE
        res = try client.continueHandshake(with: serverEEBytes.span.bytes)
        XCTAssertNil(res)
        XCTAssertEqual(client.readEncryptionLevel, .handshake)
        XCTAssertEqual(client.writeEncryptionLevel, .handshake)

        // send server cert request
        res = try client.continueHandshake(with: serverCertificateRequestBytes.span.bytes)
        XCTAssertNil(res)
        XCTAssertEqual(client.readEncryptionLevel, .handshake)
        XCTAssertEqual(client.writeEncryptionLevel, .handshake)

        // send server cert
        res = try client.continueHandshake(with: serverCertificateBytes.span.bytes)
        XCTAssertNil(res)
        XCTAssertEqual(client.readEncryptionLevel, .handshake)
        XCTAssertEqual(client.writeEncryptionLevel, .handshake)

        // send server cert verify
        res = try client.continueHandshake(with: serverCertificateVerifyBytes.span.bytes)
        XCTAssertNil(res)
        XCTAssertEqual(client.readEncryptionLevel, .handshake)
        XCTAssertEqual(client.writeEncryptionLevel, .handshake)

        // send server finished
        guard let clientSecondFlightBytes = try client.continueHandshake(with: serverFinishedBytes.span.bytes) else {
            XCTFail("Failed to setup handshake. Nil client second flight bytes")
            return
        }
        XCTAssertEqual(client.readEncryptionLevel, .application)
        XCTAssertEqual(client.writeEncryptionLevel, .application)

        // send client certificate, certificate verify, and finished messages
        res = try server.continueHandshake(with: clientSecondFlightBytes.span.bytes)
        XCTAssertNil(res)
        XCTAssertEqual(server.readEncryptionLevel, .application)
        XCTAssertEqual(server.writeEncryptionLevel, .application)
    }

    func testHandshakerHappyPath_NoEarlyData_MutualRPK() throws {
        let clientOptions = defaultClientOptions(clientAuth: true)
        let serverOptions = defaultServerOptions(clientAuth: true)

        try runHandshakerHappyPath_NoEarlyData_MutualRPK(clientOptions: clientOptions, serverOptions: serverOptions)
    }

    func testHandshakerHappyPath_NoEarlyData_MutualRPK_RefKey() throws {
        let clientOptions = defaultClientOptions(clientAuth: true, refKey: true)
        let serverOptions = defaultServerOptions(clientAuth: true, refKey: true)

        try runHandshakerHappyPath_NoEarlyData_MutualRPK(clientOptions: clientOptions, serverOptions: serverOptions)
    }

    func runHandshakerHappyPath_NoEarlyData_ExternalPSK() throws {
        let clientOptions = defaultClientOptions(externalPSKs: true)
        let serverOptions = defaultServerOptions(externalPSKs: true)

        let server = SwiftTLSServerHandshaker()
        XCTAssertNil(try server.setupHandshake(options: serverOptions))
        XCTAssertEqual(server.readEncryptionLevel, .initial)
        XCTAssertEqual(server.writeEncryptionLevel, .initial)

        let client = SwiftTLSClientHandshaker()
        guard let clientHelloBytes = try client.setupHandshake(options: clientOptions) else {
            XCTFail("Failed to setup handshake. Nil client hello bytes")
            return
        }
        XCTAssertEqual(client.readEncryptionLevel, .initial)
        XCTAssertEqual(client.writeEncryptionLevel, .earlyData)

        // send client hello
        guard let serverHelloBytes = try server.continueHandshake(with: clientHelloBytes.span.bytes) else {
            XCTFail("Failed to setup handshake. Nil server hello bytes")
            return
        }
        XCTAssertEqual(server.readEncryptionLevel, .handshake)
        XCTAssertEqual(server.writeEncryptionLevel, .handshake)

        guard let serverEEBytes = try server.continueHandshake() else {
            XCTFail("Failed to setup handshake. Nil server EE bytes")
            return
        }
        XCTAssertEqual(server.readEncryptionLevel, .handshake)
        XCTAssertEqual(server.writeEncryptionLevel, .handshake)

        guard let serverFinishedBytes = try server.continueHandshake() else {
            XCTFail("Failed to setup handshake. Nil server finished bytes")
            return
        }
        XCTAssertEqual(server.readEncryptionLevel, .handshake)
        XCTAssertEqual(server.writeEncryptionLevel, .application)

        // send server hello
        var res = try client.continueHandshake(with: serverHelloBytes.span.bytes)
        XCTAssertNil(res)
        XCTAssertEqual(client.readEncryptionLevel, .handshake)
        XCTAssertEqual(client.writeEncryptionLevel, .handshake)

        // send server EE
        res = try client.continueHandshake(with: serverEEBytes.span.bytes)
        XCTAssertNil(res)
        XCTAssertEqual(client.readEncryptionLevel, .handshake)
        XCTAssertEqual(client.writeEncryptionLevel, .handshake)

        // send server finished
        guard let clientSecondFlightBytes = try client.continueHandshake(with: serverFinishedBytes.span.bytes) else {
            XCTFail("Failed to setup handshake. Nil client second flight bytes")
            return
        }
        XCTAssertEqual(client.readEncryptionLevel, .application)
        XCTAssertEqual(client.writeEncryptionLevel, .application)

        // send finished message
        res = try server.continueHandshake(with: clientSecondFlightBytes.span.bytes)
        XCTAssertNil(res)
        XCTAssertEqual(server.readEncryptionLevel, .application)
        XCTAssertEqual(server.writeEncryptionLevel, .application)
    }

    func testHandshakerHappyPath_NoEarlyData_ExternalPSK() throws {
        try runHandshakerHappyPath_NoEarlyData_ExternalPSK()
    }

    func testHandshakerHappyPath_NoEarlyData_MutualRPK_SepKeys() throws {
        #if !SWIFTTLS_EMBEDDED && canImport(Darwin)
        if SecureEnclave.isAvailable,
           let clientSEPKey = try? SecureEnclave.P256.Signing.PrivateKey(),
           let serverSEPKey = try? SecureEnclave.P256.Signing.PrivateKey() {

            var clientOptions = defaultClientOptions(clientAuth: true)
            var serverOptions = defaultServerOptions(clientAuth: true)

            clientOptions.privateKey = .p256SEPBacked(clientSEPKey)
            clientOptions.trustedRawPublicKeyP256PublicKeys = [serverSEPKey.publicKey]

            serverOptions.privateKey = .p256SEPBacked(serverSEPKey)
            serverOptions.trustedRawPublicKeyP256PublicKeys = [clientSEPKey.publicKey]

            try runHandshakerHappyPath_NoEarlyData_MutualRPK(clientOptions: clientOptions, serverOptions: serverOptions)
            return
        }
        #endif
        throw XCTSkip("SecureEnclave not available on this platform")
    }
}
