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

@available(anyAppleOS 26, *)
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
