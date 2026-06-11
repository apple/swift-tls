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
#if canImport(CryptoKit)
import CryptoKit
#elseif canImport(Crypto)
@preconcurrency import Crypto
#endif
#if canImport(SwiftTLS) && !SWIFTTLS_BUILTIN_TESTS
@testable @_spi(SwiftTLSProtocol) import SwiftTLS
#endif

#if canImport(Security)
import Security
#endif

enum ErrorLocation {
    case sendClientHello
    case readClientHello
    case readServerHello
    case sendServerEncryptedExtensions
    case readServerEncryptedExtensions
    case sendServerCertificateRequest
    case readServerCertificateRequest
    case sendServerCertificate
    case readServerCertificate
    case sendServerCertificateVerify
    case readServerCertificateVerify
    case sendServerFinished
    case readServerFinished
    case sendClientCertificate
    case readClientCertificate
    case sendClientCertificateVerify
    case readClientCertificateVerify
    case sendClientFinished
    case readClientFinished
}

@available(anyAppleOS 26, *)
class ServerHandshakeStateMachineTests: XCTestCase {
    override func setUp() {
        continueAfterFailure = false
    }

    var serverSigningKey: P256.Signing.PrivateKey {
        configurationGenerator.serverSigningKey
    }

    var clientSigningKey: P256.Signing.PrivateKey {
        configurationGenerator.clientSigningKey
    }

    var configurationGenerator = try! TestConfigurationGenerator()

    @discardableResult
    func checkHandshakeBytes(_ parser: inout HandshakeMessageParser, handshakeBytes: ByteBuffer?, expectedMessage: String) throws -> ByteBuffer? {
        if var handshakeBytesCopy = handshakeBytes {
            parser.appendBytes(&handshakeBytesCopy)
        }
        guard let message = try parser.parseHandshakeMessage() else {
            if (parser.bytesToParse > 0){
                XCTFail("Couldn't parse handshake message.")
            } else {
                XCTFail("No handshake bytes available to check")
            }
            return nil
        }
        guard message.message.logDescription == expectedMessage else {
            XCTFail("Handshake message did not match expected type: expected \(expectedMessage), got \(message.message.logDescription)")
            return nil
        }
        return message.messageBytes
    }

    // run the happy path (with mutual RPK based auth)
    // client hello                 -> server hello, ee, cert request, cert, cert verify, finished
    // server hello                 -> nil
    // server ee                    -> nil
    // server certificate request   -> nil
    // server certificate           -> nil
    // server certificate verify    -> nil
    // server finish                -> client cert, cert verify, finish
    // client cert                  -> nil
    // client cert verify           -> nil
    // client finish                -> nil
    //
    // run the happy path (with earlyServerFinished = false)
    // client hello                 -> server hello
    // server hello                 -> nil
    // server extensions            -> nil
    // server certificate           -> nil
    // server certificate verify    -> nil
    // server finish                -> client finish
    // client finish                -> nil
    //
    // runs the happy path (with earlyServerFinished = true (i.e. when PSK accepted))
    // run the happy path
    // client hello                 -> server hello
    // server hello                 -> nil
    // server extensions            -> nil
    // server finish                -> client finish
    // client finish                -> nil
    func runSuccessfulHandshake(clientStateMachine: inout HandshakeStateMachine, serverStateMachine: inout ServerHandshakeStateMachine, clientAuthRequired: Bool = false, earlyServerFinished: Bool = false, earlyDataExpected: Bool = false, epskNegotiatedExpected: Bool = false) throws {
        var parser = HandshakeMessageParser()

        // Send Client Hello
        var clientHelloBytes = try clientStateMachine.startHandshake().handshakeBytesToSend!

        // Read Client Hello and Send ServerHello
        XCTAssertEqual(serverStateMachine.stateDescription, "idle")
        serverStateMachine.receivedNetworkData(&clientHelloBytes)
        var result = try serverStateMachine.processHandshake()!
        if earlyDataExpected {
            result.assertNewEncryptionLevel(.earlyData, .read)
            result = try serverStateMachine.processHandshake()!
        }
        result.assertNewReadAndWriteEncryptionLevel(.handshake)
        guard var serverHelloBytes = result.handshakeBytesToSend else {
            XCTFail()
            return
        }
        try checkHandshakeBytes(&parser, handshakeBytes: serverHelloBytes, expectedMessage: "serverHello")

        // Read Server Hello
        clientStateMachine.receivedNetworkData(&serverHelloBytes)
        result = try clientStateMachine.processHandshake()!
        XCTAssertNil(result.handshakeBytesToSend)
        result.assertNewReadAndWriteEncryptionLevel(.handshake)

        // Send Encrypted Extensions
        result = try serverStateMachine.processHandshake()!
        guard var serverEncryptedExtensionsBytes = result.handshakeBytesToSend else {
            XCTFail()
            return
        }
        try checkHandshakeBytes(&parser, handshakeBytes: serverEncryptedExtensionsBytes, expectedMessage: "encryptedExtensions")

        // Read Encrypted Extensions
        clientStateMachine.receivedNetworkData(&serverEncryptedExtensionsBytes)
        XCTAssertNil(try clientStateMachine.processHandshake())

        // skip server certificate and certificateverify messages if expected to
        // go straight to serverfinshed.
        if !earlyServerFinished {
            if clientAuthRequired {
                // Send Ceritificate Request if expecting client auth
                result = try serverStateMachine.processHandshake()!
                guard var serverCertificateRequestBytes = result.handshakeBytesToSend else {
                    XCTFail("faile to get Certificate Request bytes")
                    return
                }
                try checkHandshakeBytes(&parser, handshakeBytes: serverCertificateRequestBytes, expectedMessage: "certificateRequest")

                // Read Certificate Request
                clientStateMachine.receivedNetworkData(&serverCertificateRequestBytes)
                XCTAssertNil(try clientStateMachine.processHandshake())
            }
            // Send Certificate
            result = try serverStateMachine.processHandshake()!
            guard var serverCertificateBytes = result.handshakeBytesToSend else {
                XCTFail()
                return
            }
            try checkHandshakeBytes(&parser, handshakeBytes: serverCertificateBytes, expectedMessage: "certificate")


            // Read Server Certificate
            clientStateMachine.receivedNetworkData(&serverCertificateBytes)
            XCTAssertNil(try clientStateMachine.processHandshake())

            // Send CertificateVerify
            result = try serverStateMachine.processHandshake()!
            guard var serverCertificateVerifyBytes = result.handshakeBytesToSend else {
                XCTFail()
                return
            }
            try checkHandshakeBytes(&parser, handshakeBytes: serverCertificateVerifyBytes, expectedMessage: "certificateVerify")

            // Read Server CertificateVerify
            clientStateMachine.receivedNetworkData(&serverCertificateVerifyBytes)
            XCTAssertNil(try clientStateMachine.processHandshake())
        }

        // Send ServerFinished
        result = try serverStateMachine.processHandshake()!
        result.assertNewEncryptionLevel(.application, .write)
        guard var serverFinishedBytes = result.handshakeBytesToSend else {
            XCTFail()
            return
        }
        try checkHandshakeBytes(&parser, handshakeBytes: serverFinishedBytes, expectedMessage: "finished")

        // Read ServerFinished and Send ClientFinished
        clientStateMachine.receivedNetworkData(&serverFinishedBytes)
        result = try clientStateMachine.processHandshake()!

        guard var clientSecondFlightBytes = result.handshakeBytesToSend else {
            XCTFail("failed to get Client second flight bytes")
            return
        }
        var clientSecondFlightBytesCopy = clientSecondFlightBytes
        parser.appendBytes(&clientSecondFlightBytesCopy)

        // if client auth required then we need to get the client cert and cert verify also
        if clientAuthRequired {
            try checkHandshakeBytes(&parser, handshakeBytes: nil, expectedMessage: "certificate")
            // already passed in full second flight, so don't add again
            try checkHandshakeBytes(&parser, handshakeBytes: nil, expectedMessage: "certificateVerify")
        }

        try checkHandshakeBytes(&parser, handshakeBytes: nil, expectedMessage: "finished")

        result.assertNewReadAndWriteEncryptionLevel(.application)

        // Read [Client Certificate, Certificate Verify] + ClientFinished
        serverStateMachine.receivedNetworkData(&clientSecondFlightBytes)
        result = try serverStateMachine.processHandshake()!
        result.assertNewEncryptionLevel(.application, .read)
        XCTAssertEqual(serverStateMachine.stateDescription, "readyForData")

        if epskNegotiatedExpected {
            XCTAssert(clientStateMachine.negotiatedEPSK)
            XCTAssert(serverStateMachine.negotiatedEPSK)
        } else {
            XCTAssert(!clientStateMachine.negotiatedEPSK)
            XCTAssert(!serverStateMachine.negotiatedEPSK)
        }
    }

    func runFailedHandshake(
        clientStateMachine: inout HandshakeStateMachine,
        serverStateMachine: inout ServerHandshakeStateMachine,
        expectedError: TLSError,
        errorLocation: ErrorLocation,
        earlyServerFinished: Bool = false,
        clientAuthRequired: Bool = false,
        clientCertificateVerifyExpected: Bool = false,
        addNonEmptyContextToClientCertificateEntry: Bool = false,
        addNonEmptyContextToServerCertificateRequest: Bool = false,
        omitCertRequestSigAlgsExt: Bool = false,
        omitClientCertificateVerify: Bool = false,
        clientCertificateVerifyWrong: Bool = false
    ) throws {
        var parser = HandshakeMessageParser()

        // Send Client Hello
        if case(.sendClientHello) = errorLocation {
            XCTAssertThrowsError(try clientStateMachine.startHandshake()) { error in
                XCTAssertEqual(error as? TLSError, expectedError)
            }
            return
        }
        var clientHelloBytes = try clientStateMachine.startHandshake().handshakeBytesToSend!

        // Read Client Hello and Send ServerHello
        XCTAssertEqual(serverStateMachine.stateDescription, "idle")
        serverStateMachine.receivedNetworkData(&clientHelloBytes)
        if case(.readClientHello) = errorLocation {
            XCTAssertThrowsError(try serverStateMachine.processHandshake()) { error in
                XCTAssertEqual(error as? TLSError, expectedError)
            }
            return
        }
        var result = try serverStateMachine.processHandshake()!
        result.assertNewReadAndWriteEncryptionLevel(.handshake)
        guard var serverHelloBytes = result.handshakeBytesToSend else {
            XCTFail()
            return
        }
        try checkHandshakeBytes(&parser, handshakeBytes: serverHelloBytes, expectedMessage: "serverHello")

        // Read Server Hello
        clientStateMachine.receivedNetworkData(&serverHelloBytes)
        if case(.readServerHello) = errorLocation {
            XCTAssertThrowsError(try clientStateMachine.processHandshake()) { error in
                XCTAssertEqual(error as? TLSError, expectedError)
            }
            return
        }
        result = try clientStateMachine.processHandshake()!
        XCTAssertNil(result.handshakeBytesToSend)
        result.assertNewReadAndWriteEncryptionLevel(.handshake)

        // Send Encrypted Extensions
        if case(.sendServerEncryptedExtensions) = errorLocation {
            XCTAssertThrowsError(try serverStateMachine.processHandshake()) { error in
                XCTAssertEqual(error as? TLSError, expectedError)
            }
            return
        }
        result = try serverStateMachine.processHandshake()!
        guard var serverEncryptedExtensionsBytes = result.handshakeBytesToSend else {
            XCTFail()
            return
        }
        try checkHandshakeBytes(&parser, handshakeBytes: serverEncryptedExtensionsBytes, expectedMessage: "encryptedExtensions")

        // Read Encrypted Extensions
        clientStateMachine.receivedNetworkData(&serverEncryptedExtensionsBytes)
        if case(.readServerEncryptedExtensions) = errorLocation {
            XCTAssertThrowsError(try clientStateMachine.processHandshake()) { error in
                XCTAssertEqual(error as? TLSError, expectedError)
            }
            return
        }
        XCTAssertNil(try clientStateMachine.processHandshake())

        if !earlyServerFinished {
            if clientAuthRequired {
                // Send Certificate Request
                if case(.sendServerCertificateRequest) = errorLocation {
                    XCTAssertThrowsError(try serverStateMachine.processHandshake()) { error in
                        XCTAssertEqual(error as? TLSError, expectedError)
                    }
                }
                // Send Certificate Request if expecting client auth
                result = try serverStateMachine.processHandshake()!
                guard var serverCertificateRequestBytes = result.handshakeBytesToSend else {
                    XCTFail("failed to get Certificate Request bytes")
                    return
                }
                try checkHandshakeBytes(&parser, handshakeBytes: serverCertificateRequestBytes, expectedMessage: "certificateRequest")
                XCTAssertEqual(parser.bytesToParse, 0)

                if addNonEmptyContextToServerCertificateRequest || omitCertRequestSigAlgsExt {
                    parser.appendBytes(&serverCertificateRequestBytes)
                    guard let originalCertificateRequestMessage = try parser.parseHandshakeMessage() else {
                        XCTFail("error modifying server CertificateReqest message")
                        return
                    }
                    XCTAssertEqual(parser.bytesToParse, 0)
                    let message = originalCertificateRequestMessage.message
                    if case (.certificateRequest(let originalCertRequest)) = message {
                        let newCertRequestMessage = CertificateRequest(
                            certificateRequestContext: addNonEmptyContextToServerCertificateRequest ? ByteBuffer("non-empty") : ByteBuffer(""),
                            extensions: omitCertRequestSigAlgsExt ? [] : originalCertRequest.extensions
                        )
                        serverCertificateRequestBytes = ByteBuffer("")
                        serverCertificateRequestBytes.writeHandshakeMessage(newCertRequestMessage)
                    } else {
                        XCTFail("error modifying client Certificate message")
                        return
                    }
                }

                // Read Certificate Request
                clientStateMachine.receivedNetworkData(&serverCertificateRequestBytes)
                if case(.readServerCertificateRequest) = errorLocation {
                    XCTAssertThrowsError(try clientStateMachine.processHandshake()) { error in
                        XCTAssertEqual(error as? TLSError, expectedError)
                    }
                    return
                }
                XCTAssertNil(try clientStateMachine.processHandshake())
            }

            // Send Certificate
            if case(.sendServerCertificate) = errorLocation {
                XCTAssertThrowsError(try serverStateMachine.processHandshake()) { error in
                    XCTAssertEqual(error as? TLSError, expectedError)
                }
                return
            }
            result = try serverStateMachine.processHandshake()!
            guard var serverCertificateBytes = result.handshakeBytesToSend else {
                XCTFail()
                return
            }
            try checkHandshakeBytes(&parser, handshakeBytes: serverCertificateBytes, expectedMessage: "certificate")


            // Read Server Certificate
            clientStateMachine.receivedNetworkData(&serverCertificateBytes)
            if case(.readServerCertificate) = errorLocation {
                XCTAssertThrowsError(try clientStateMachine.processHandshake()) { error in
                    XCTAssertEqual(error as? TLSError, expectedError)
                }
                return
            }
            XCTAssertNil(try clientStateMachine.processHandshake())

            // Send CertificateVerify
            if case(.sendServerCertificateVerify) = errorLocation {
                XCTAssertThrowsError(try serverStateMachine.processHandshake()) { error in
                    XCTAssertEqual(error as? TLSError, expectedError)
                }
                return
            }
            result = try serverStateMachine.processHandshake()!
            guard var serverCertificateVerifyBytes = result.handshakeBytesToSend else {
                XCTFail()
                return
            }
            try checkHandshakeBytes(&parser, handshakeBytes: serverCertificateVerifyBytes, expectedMessage: "certificateVerify")

            // Read Server CertificateVerify
            clientStateMachine.receivedNetworkData(&serverCertificateVerifyBytes)
            if case(.readServerCertificateVerify) = errorLocation {
                XCTAssertThrowsError(try clientStateMachine.processHandshake()) { error in
                    XCTAssertEqual(error as? TLSError, expectedError)
                }
                return
            }
            XCTAssertNil(try clientStateMachine.processHandshake())
        }

        // Send ServerFinished
        if case(.sendServerFinished) = errorLocation {
            XCTAssertThrowsError(try serverStateMachine.processHandshake()) { error in
                XCTAssertEqual(error as? TLSError, expectedError)
            }
            return
        }
        result = try serverStateMachine.processHandshake()!
        result.assertNewEncryptionLevel(.application, .write)
        guard var serverFinishedBytes = result.handshakeBytesToSend else {
            XCTFail()
            return
        }
        try checkHandshakeBytes(&parser, handshakeBytes: serverFinishedBytes, expectedMessage: "finished")

        // Read ServerFinished and Send [Client Certificate], [Client Certificate Verify], and ClientFinished
        clientStateMachine.receivedNetworkData(&serverFinishedBytes)
        if case(.readServerFinished) = errorLocation {
            XCTAssertThrowsError(try clientStateMachine.processHandshake()) { error in
                XCTAssertEqual(error as? TLSError, expectedError)
            }
            return
        }
        result = try clientStateMachine.processHandshake()!
        result.assertNewReadAndWriteEncryptionLevel(.application)
        XCTAssertNotNil(result.handshakeBytesToSend)

        var clientSecondFlightBytes = result.handshakeBytesToSend!
        parser.appendBytes(&clientSecondFlightBytes)

        var clientCertificateBytes: ByteBuffer? = nil
        var clientCertificateVerifyBytes: ByteBuffer? = nil
        var clientFinishedBytes: ByteBuffer? = nil

        // make sure client sent all the messages we expected it to
        if clientAuthRequired {
            clientCertificateBytes = try checkHandshakeBytes(&parser, handshakeBytes: nil, expectedMessage: "certificate")
            if clientCertificateVerifyExpected {
                clientCertificateVerifyBytes = try checkHandshakeBytes(&parser, handshakeBytes: nil, expectedMessage: "certificateVerify")
            }
        }
        clientFinishedBytes = try checkHandshakeBytes(&parser, handshakeBytes: nil, expectedMessage: "finished")

        if clientAuthRequired {
            guard var clientCertificateBytes = clientCertificateBytes else {
                XCTFail("no client certificate bytes available when required")
                return
            }
            if addNonEmptyContextToClientCertificateEntry {
                parser.appendBytes(&clientCertificateBytes)
                guard let originalCertificateMessage = try parser.parseHandshakeMessage() else {
                    XCTFail("error modifying client Certificate message")
                    return
                }
                let message = originalCertificateMessage.message
                if case(.certificate(let certMessage)) = message {
                    let newCertMessage = CertificateMessage(
                        certificateRequestContext: ByteBuffer(
                            "non empty context"
                        ),
                        certificateList: certMessage.certificateList
                    )
                    clientCertificateBytes.writeHandshakeMessage(newCertMessage)
                } else {
                    XCTFail("error modifying client Certificate message")
                    return
                }
            }
            serverStateMachine.receivedNetworkData(&clientCertificateBytes)
            if case(.readClientCertificate) = errorLocation {
                XCTAssertThrowsError(try serverStateMachine.processHandshake()) { error in
                    XCTAssertEqual(error as? TLSError, expectedError)
                }
                return
            }
            XCTAssertNil(try serverStateMachine.processHandshake())
            if clientCertificateVerifyExpected && !omitClientCertificateVerify {
                guard var clientCertificateVerifyBytes = clientCertificateVerifyBytes else {
                    XCTFail("no client certificate verify bytes available when required")
                    return
                }
                if clientCertificateVerifyWrong {
                    parser.appendBytes(&clientCertificateVerifyBytes)
                    guard let originalCertificateVerifyMessage = try parser.parseHandshakeMessage() else {
                        XCTFail("error modifying client Certificate Verify message")
                        return
                    }
                    if case(.certificateVerify(let originalCertVerify)) = originalCertificateVerifyMessage.message {
                        let data = ByteBuffer("wrong data to sign")
                        let newCertVerify = CertificateVerify(
                            algorithm: originalCertVerify.algorithm,
                            signature: ByteBuffer(data: try TLSError.wrappingCryptoError { () throws(CryptoKitMetaError) in try clientSigningKey.signature(for: data.readableBytesView).derRepresentation })
                        )
                        clientCertificateVerifyBytes.writeHandshakeMessage(newCertVerify)
                    } else {
                        XCTFail("error modifying client Certificate Verify message")
                        return
                    }
                }
                serverStateMachine.receivedNetworkData(&clientCertificateVerifyBytes)
                if case(.readClientCertificateVerify) = errorLocation {
                    XCTAssertThrowsError(try serverStateMachine.processHandshake()) { error in
                        XCTAssertEqual(error as? TLSError, expectedError)
                    }
                    return
                }
                XCTAssertNil(try serverStateMachine.processHandshake())
            }
        }

        // Read Client Finished
        guard var clientFinishedBytes = clientFinishedBytes else {
            XCTFail("no client finished bytes available when required")
            return
        }
        serverStateMachine.receivedNetworkData(&clientFinishedBytes)

        if case(.readClientFinished) = errorLocation {
            XCTAssertThrowsError(try serverStateMachine.processHandshake()) { error in
                XCTAssertEqual(error as? TLSError, expectedError)
            }
            return
        }
        result = try serverStateMachine.processHandshake()!
        result.assertNewEncryptionLevel(.application, .read)
        XCTAssertEqual(serverStateMachine.stateDescription, "readyForData")
        XCTAssertEqual(clientStateMachine.peerALPN, "proto A")
    }

    // MARK: Client RPK auth

    // run the happy path (with mutual RPK based auth)
    // client hello                 -> server hello, ee, cert request, cert, cert verify, finished
    // server hello                 -> nil
    // server ee                    -> nil
    // server certificate request   -> nil
    // server certificate           -> nil
    // server certificate verify    -> nil
    // server finish                -> client cert, cert verify, finish
    // client cert                  -> nil
    // client cert verify           -> nil
    // client finish                -> nil
    func testClientRPKHappyPath() throws {
        let clientConfig = configurationGenerator.getClientConfigWithOptions(signingKey: true)
        let serverConfig = configurationGenerator.getServerConfigWithOptions(clientAuthReq: true)
        var clientStateMachine = try HandshakeStateMachine(configuration: clientConfig)
        var serverStateMachine = try ServerHandshakeStateMachine(configuration: serverConfig)
        try runSuccessfulHandshake(clientStateMachine: &clientStateMachine, serverStateMachine: &serverStateMachine, clientAuthRequired: true)
    }

    func testClientRPKHappyPathRefKeys() throws {
        let clientConfig = configurationGenerator.getClientConfigWithOptions(refKey: true)
        let serverConfig = configurationGenerator.getServerConfigWithOptions(clientAuthReq: true, refKey: true)
        var clientStateMachine = try HandshakeStateMachine(configuration: clientConfig)
        var serverStateMachine = try ServerHandshakeStateMachine(configuration: serverConfig)
        try runSuccessfulHandshake(clientStateMachine: &clientStateMachine, serverStateMachine: &serverStateMachine, clientAuthRequired: true)
    }

    func testClientRPKHappyPathClientRegularServerRefKey() throws {
        let clientConfig = configurationGenerator.getClientConfigWithOptions(signingKey: true)
        let serverConfig = configurationGenerator.getServerConfigWithOptions(clientAuthReq: true, refKey: true)
        var clientStateMachine = try HandshakeStateMachine(configuration: clientConfig)
        var serverStateMachine = try ServerHandshakeStateMachine(configuration: serverConfig)
        try runSuccessfulHandshake(clientStateMachine: &clientStateMachine, serverStateMachine: &serverStateMachine, clientAuthRequired: true)
    }

    func testClientRPKHappyPathClientRefKeyServerRegular() throws {
        let clientConfig = configurationGenerator.getClientConfigWithOptions(refKey: true)
        let serverConfig = configurationGenerator.getServerConfigWithOptions(clientAuthReq: true)
        var clientStateMachine = try HandshakeStateMachine(configuration: clientConfig)
        var serverStateMachine = try ServerHandshakeStateMachine(configuration: serverConfig)
        try runSuccessfulHandshake(clientStateMachine: &clientStateMachine, serverStateMachine: &serverStateMachine, clientAuthRequired: true)
    }

    func testClientRPKHappyPathSEPKeys() throws {
        #if !SWIFTTLS_EMBEDDED && canImport(Darwin)
        if SecureEnclave.isAvailable,
           let _ = configurationGenerator.clientSEPSigningKey,
           let _ = configurationGenerator.serverSEPSigningKey {
            let clientConfig = configurationGenerator.getClientConfigWithOptions(sepKey: true)
            let serverConfig = configurationGenerator.getServerConfigWithOptions(clientAuthReq: true, sepKey: true)
            var clientStateMachine = try HandshakeStateMachine(configuration: clientConfig)
            var serverStateMachine = try ServerHandshakeStateMachine(configuration: serverConfig)
            try runSuccessfulHandshake(clientStateMachine: &clientStateMachine, serverStateMachine: &serverStateMachine, clientAuthRequired: true)
            return
        }
        #endif
        throw XCTSkip("no Secure Enclave on this platform")
    }

    // client hello                 -> server hello, ee, cert request, cert, cert verify, finished
    // server hello                 -> nil
    // server ee                    -> nil
    // server certificate request   -> nil
    // server certificate           -> nil
    // server certificate verify    -> nil
    // server finish                -> client cert, finish
    // client cert                  -> nil
    // client finish                -> nil
    //
    // From RFC 8446:
    //    If the client does not send any certificates (i.e., it sends an empty
    //   Certificate message), the server MAY at its discretion either
    //   continue the handshake without client authentication or abort the
    //   handshake with a "certificate_required" alert.
    //
    // In our implementation the server always requires the cert.
    func testClientRPKServerExpectsButClientDoesntHave() throws {
        let clientConfig = configurationGenerator.getClientConfigWithOptions(signingKey: false)
        let serverConfig = configurationGenerator.getServerConfigWithOptions(clientAuthReq: true)
        var clientStateMachine = try HandshakeStateMachine(configuration: clientConfig)
        var serverStateMachine = try ServerHandshakeStateMachine(configuration: serverConfig)
        #if SWIFTTLS_SUPPORT_UNVERIFIED_X509
        try runFailedHandshake(
            clientStateMachine: &clientStateMachine,
            serverStateMachine: &serverStateMachine,
            expectedError: TLSError.certificateRequired,
            errorLocation: .readClientCertificate,
            clientAuthRequired: true
        )
        #else
        try runFailedHandshake(
            clientStateMachine: &clientStateMachine,
            serverStateMachine: &serverStateMachine,
            expectedError: TLSError.handshakeFailure,
            errorLocation: .readClientHello,
            clientAuthRequired: true
        )
        #endif

    }

    // test untrusted public key
    func testClientRPKMismatchedKeys() throws {
        let clientConfig = configurationGenerator.getClientConfigWithOptions(mismatchSigningKey: true)
        let serverConfig = configurationGenerator.getServerConfigWithOptions(clientAuthReq: true)
        var clientStateMachine = try HandshakeStateMachine(configuration: clientConfig)
        var serverStateMachine = try ServerHandshakeStateMachine(configuration: serverConfig)
        try runFailedHandshake(
            clientStateMachine: &clientStateMachine,
            serverStateMachine: &serverStateMachine,
            expectedError: TLSError.certificateError,
            errorLocation: .readClientCertificateVerify,
            clientAuthRequired: true,
            clientCertificateVerifyExpected: true
        )
    }

    // test non empty certificate context on Certificate msg
    func testClientRPKNonEmptyCertificateContext() throws {
        let clientConfig = configurationGenerator.getClientConfigWithOptions(signingKey: true)
        let serverConfig = configurationGenerator.getServerConfigWithOptions(clientAuthReq: true)
        var clientStateMachine = try HandshakeStateMachine(configuration: clientConfig)
        var serverStateMachine = try ServerHandshakeStateMachine(configuration: serverConfig)
        try runFailedHandshake(
            clientStateMachine: &clientStateMachine,
            serverStateMachine: &serverStateMachine,
            expectedError: TLSError.handshakeInvalidMessage,
            errorLocation: .readClientCertificate,
            clientAuthRequired: true,
            clientCertificateVerifyExpected: true,
            addNonEmptyContextToClientCertificateEntry: true
        )
    }

    // test non empty certificate context on Certificate Request msg
    func testClientRPKServerNonEmptyContextOnCertificateRequest() throws {
        let clientConfig = configurationGenerator.getClientConfigWithOptions()
        let serverConfig = configurationGenerator.getServerConfigWithOptions(clientAuthReq: true)
        var clientStateMachine = try HandshakeStateMachine(configuration: clientConfig)
        var serverStateMachine = try ServerHandshakeStateMachine(configuration: serverConfig)
        #if SWIFTTLS_SUPPORT_UNVERIFIED_X509
        try runFailedHandshake(
            clientStateMachine: &clientStateMachine,
            serverStateMachine: &serverStateMachine,
            expectedError: TLSError.handshakeInvalidMessage,
            errorLocation: .readServerCertificateRequest,
            clientAuthRequired: true,
            addNonEmptyContextToServerCertificateRequest: true
        )
        #else
        try runFailedHandshake(
            clientStateMachine: &clientStateMachine,
            serverStateMachine: &serverStateMachine,
            expectedError: TLSError.handshakeFailure,
            errorLocation: .readClientHello,
            clientAuthRequired: true
        )
        #endif
    }

    // test missing signature algorithms extension on CertificateRequest
    func testClientRPKServerOmitSignatureAlgExtensionOnCertificateRequest() throws {
        let clientConfig = configurationGenerator.getClientConfigWithOptions()
        let serverConfig = configurationGenerator.getServerConfigWithOptions(clientAuthReq: true)
        var clientStateMachine = try HandshakeStateMachine(configuration: clientConfig)
        var serverStateMachine = try ServerHandshakeStateMachine(configuration: serverConfig)
        #if SWIFTTLS_SUPPORT_UNVERIFIED_X509
        try runFailedHandshake(
            clientStateMachine: &clientStateMachine,
            serverStateMachine: &serverStateMachine,
            expectedError: TLSError.handshakeInvalidMessage,
            errorLocation: .readServerCertificateRequest,
            clientAuthRequired: true,
            clientCertificateVerifyExpected: true,
            omitCertRequestSigAlgsExt: true
        )
        #else
        try runFailedHandshake(
            clientStateMachine: &clientStateMachine,
            serverStateMachine: &serverStateMachine,
            expectedError: TLSError.handshakeFailure,
            errorLocation: .readClientHello,
            clientAuthRequired: true
        )
        #endif

    }

    // test missing certificate verify message
    func testClientRPKOmitCertificateVerifyMessage() throws {
        let clientConfig = configurationGenerator.getClientConfigWithOptions(signingKey: true)
        let serverConfig = configurationGenerator.getServerConfigWithOptions(clientAuthReq: true)
        var clientStateMachine = try HandshakeStateMachine(configuration: clientConfig)
        var serverStateMachine = try ServerHandshakeStateMachine(configuration: serverConfig)
        try runFailedHandshake(
            clientStateMachine: &clientStateMachine,
            serverStateMachine: &serverStateMachine,
            expectedError: TLSError.handshakeUnexpectedMessage,
            errorLocation: .readClientFinished,
            clientAuthRequired: true,
            clientCertificateVerifyExpected: true, // client still tries to send
            omitClientCertificateVerify: true // but we drop it on the floor
        )
    }

    // test wrong certificate verify signature
    func testClientRPKCertificateVerifySignatureWrong() throws {
        let clientConfig = configurationGenerator.getClientConfigWithOptions(signingKey: true)
        let serverConfig = configurationGenerator.getServerConfigWithOptions(clientAuthReq: true)
        var clientStateMachine = try HandshakeStateMachine(configuration: clientConfig)
        var serverStateMachine = try ServerHandshakeStateMachine(configuration: serverConfig)
        try runFailedHandshake(
            clientStateMachine: &clientStateMachine,
            serverStateMachine: &serverStateMachine,
            expectedError: TLSError.certificateError,
            errorLocation: .readClientCertificateVerify,
            clientAuthRequired: true,
            clientCertificateVerifyExpected: true,
            clientCertificateVerifyWrong: true
        )
    }

    // TODO: Test no common signature algorithms when possible to configure signature algorithm besides
    // just P256.
    // Do this by fully mocking the server side.
    // Can't currently write a test like it because modifying the CertificateRequest message
    // to fake that the server chose P384 will mean the server CertificateVerify won't verify.

    // test that the server WON'T send app data till getting client certs + finished
    // make this at the record handler layer?

    // MARK: PSK Tests

    // runs the handshake assuming the server sends an early finished message (when PSK accepted)
    // run the happy path
    // client hello                 -> server hello
    // server hello                 -> nil
    // server extensions            -> nil
    // server finish                -> client finish
    // client finish                -> nil
    func runSuccessfulPSKAuthenticatedHandshake(clientStateMachine: inout HandshakeStateMachine, serverStateMachine: inout ServerHandshakeStateMachine) throws {
        try runSuccessfulHandshake(clientStateMachine: &clientStateMachine, serverStateMachine: &serverStateMachine, earlyServerFinished: true, epskNegotiatedExpected: true)
    }

    func testNetworkDataHappyPathProcessHandshake() throws {
        let clientConfig = configurationGenerator.getClientConfigWithOptions()
        let serverConfig = configurationGenerator.getServerConfigWithOptions()
        var clientStateMachine = try HandshakeStateMachine(configuration: clientConfig)
        var serverStateMachine = try ServerHandshakeStateMachine(configuration: serverConfig)
        try runSuccessfulHandshake(clientStateMachine: &clientStateMachine, serverStateMachine: &serverStateMachine)
    }

    func testImportedRawEPSKMismatchFails() throws {
        let clientConfig = configurationGenerator.getClientEPSKConfiguration(nilContext: true)
        let serverConfig = configurationGenerator.getServerEPSKConfiguration(raw: true, nilContext: true)
        var clientStateMachine = try HandshakeStateMachine(configuration: clientConfig)
        var serverStateMachine = try ServerHandshakeStateMachine(configuration: serverConfig)
        try runFailedHandshake(clientStateMachine: &clientStateMachine, serverStateMachine: &serverStateMachine, expectedError: TLSError.serverMissingSigningKey, errorLocation: ErrorLocation.sendServerCertificate)
    }

    func testExternalPSKHappyPath() throws {
        let clientConfig = configurationGenerator.getClientEPSKConfiguration()
        let serverConfig = configurationGenerator.getServerEPSKConfiguration()
        var clientStateMachine = try HandshakeStateMachine(configuration: clientConfig)
        var serverStateMachine = try ServerHandshakeStateMachine(configuration: serverConfig)
        try runSuccessfulPSKAuthenticatedHandshake(clientStateMachine: &clientStateMachine, serverStateMachine: &serverStateMachine)
    }

    func testExternalPSKNilContextHappyPath() throws {
        let clientConfig = configurationGenerator.getClientEPSKConfiguration(nilContext:true)
        let serverConfig = configurationGenerator.getServerEPSKConfiguration(nilContext: true)
        var clientStateMachine = try HandshakeStateMachine(configuration: clientConfig)
        var serverStateMachine = try ServerHandshakeStateMachine(configuration: serverConfig)
        try runSuccessfulPSKAuthenticatedHandshake(clientStateMachine: &clientStateMachine, serverStateMachine: &serverStateMachine)
    }

    func testRawExternalPSKHappyPath() throws {
        let clientConfig = configurationGenerator.getClientEPSKConfiguration(raw:true)
        let serverConfig = configurationGenerator.getServerEPSKConfiguration(raw: true)
        var clientStateMachine = try HandshakeStateMachine(configuration: clientConfig)
        var serverStateMachine = try ServerHandshakeStateMachine(configuration: serverConfig)
        try runSuccessfulPSKAuthenticatedHandshake(clientStateMachine: &clientStateMachine, serverStateMachine: &serverStateMachine)
    }

    func testExternalPSKEarlyDataHappyPath() throws {
        let clientConfig = configurationGenerator.getClientEPSKConfiguration(earlyData: true)
        let serverConfig = configurationGenerator.getServerEPSKConfiguration(earlyData: true)
        var clientStateMachine = try HandshakeStateMachine(configuration: clientConfig)
        var serverStateMachine = try ServerHandshakeStateMachine(configuration: serverConfig)
        try runSuccessfulHandshake(clientStateMachine: &clientStateMachine, serverStateMachine: &serverStateMachine, earlyServerFinished: true, earlyDataExpected: true, epskNegotiatedExpected: true)
    }

    func testRawExternalPSKEarlyDataHappyPath() throws {
        let clientConfig = configurationGenerator.getClientEPSKConfiguration(raw: true, earlyData: true)
        let serverConfig = configurationGenerator.getServerEPSKConfiguration(raw: true, earlyData: true)
        var clientStateMachine = try HandshakeStateMachine(configuration: clientConfig)
        var serverStateMachine = try ServerHandshakeStateMachine(configuration: serverConfig)
        try runSuccessfulHandshake(clientStateMachine: &clientStateMachine, serverStateMachine: &serverStateMachine, earlyServerFinished: true, earlyDataExpected: true, epskNegotiatedExpected: true)
    }

    func testExternalPSKServerConfiguredWithMultipleEPSKs() throws {
        let clientConfig = configurationGenerator.getClientEPSKConfiguration()
        let serverConfig = configurationGenerator.getServerEPSKConfiguration(multiple: true)
        var clientStateMachine = try HandshakeStateMachine(configuration: clientConfig)
        var serverStateMachine = try ServerHandshakeStateMachine(configuration: serverConfig)
        try runSuccessfulPSKAuthenticatedHandshake(clientStateMachine: &clientStateMachine, serverStateMachine: &serverStateMachine)
    }

    func testExternalPSKServerConfiguredWithMultipleRawEPSKs() throws {
        let clientConfig = configurationGenerator.getClientEPSKConfiguration(raw:true)
        let serverConfig = configurationGenerator.getServerEPSKConfiguration(raw:true, multiple: true)
        var clientStateMachine = try HandshakeStateMachine(configuration: clientConfig)
        var serverStateMachine = try ServerHandshakeStateMachine(configuration: serverConfig)
        try runSuccessfulPSKAuthenticatedHandshake(clientStateMachine: &clientStateMachine, serverStateMachine: &serverStateMachine)
    }

    func testExternalPSKMismatchBaseKeyFails() throws {
        // external identity and context the same, but different base key
        let clientConfig = configurationGenerator.getClientEPSKConfiguration()
        let serverConfig = configurationGenerator.getServerEPSKConfiguration(mismatchBaseKey: true)
        var clientStateMachine = try HandshakeStateMachine(configuration: clientConfig)
        var serverStateMachine = try ServerHandshakeStateMachine(configuration: serverConfig)
        try runFailedHandshake(clientStateMachine: &clientStateMachine, serverStateMachine: &serverStateMachine, expectedError: TLSError.decryptError, errorLocation: ErrorLocation.readClientHello, earlyServerFinished: true)
    }

    func testRawExternalPSKMismatchBaseKeyFails() throws {
        // external identity the same, but different base key
        let clientConfig = configurationGenerator.getClientEPSKConfiguration(raw: true)
        let serverConfig = configurationGenerator.getServerEPSKConfiguration(raw: true, mismatchBaseKey: true)
        var clientStateMachine = try HandshakeStateMachine(configuration: clientConfig)
        var serverStateMachine = try ServerHandshakeStateMachine(configuration: serverConfig)
        try runFailedHandshake(clientStateMachine: &clientStateMachine, serverStateMachine: &serverStateMachine, expectedError: TLSError.decryptError, errorLocation: ErrorLocation.readClientHello, earlyServerFinished: true)
    }

    func testExternalPSKMismatchExternalIdentityFails() throws {
        // base key and context the same, but different external identity
        let clientConfig = configurationGenerator.getClientEPSKConfiguration()
        let serverConfig = configurationGenerator.getServerEPSKConfiguration(mismatchIdentity: true)
        var clientStateMachine = try HandshakeStateMachine(configuration: clientConfig)
        var serverStateMachine = try ServerHandshakeStateMachine(configuration: serverConfig)
        try runFailedHandshake(clientStateMachine: &clientStateMachine, serverStateMachine: &serverStateMachine, expectedError: TLSError.serverMissingSigningKey, errorLocation: ErrorLocation.sendServerCertificate)
    }

    func testRawExternalPSKMismatchIdentityFails() throws {
        // base key the same, but different external identity
        let clientConfig = configurationGenerator.getClientEPSKConfiguration(raw: true)
        let serverConfig = configurationGenerator.getServerEPSKConfiguration(raw: true, mismatchIdentity: true)
        var clientStateMachine = try HandshakeStateMachine(configuration: clientConfig)
        var serverStateMachine = try ServerHandshakeStateMachine(configuration: serverConfig)
        try runFailedHandshake(clientStateMachine: &clientStateMachine, serverStateMachine: &serverStateMachine, expectedError: TLSError.serverMissingSigningKey, errorLocation: ErrorLocation.sendServerCertificate)
    }

    func testExternalPSKMismatchContext() throws {
        // base key and external identity the same, but different context
        let clientConfig = configurationGenerator.getClientEPSKConfiguration()
        let serverConfig = configurationGenerator.getServerEPSKConfiguration(mismatchContext: true)
        var clientStateMachine = try HandshakeStateMachine(configuration: clientConfig)
        var serverStateMachine = try ServerHandshakeStateMachine(configuration: serverConfig)
        try runFailedHandshake(clientStateMachine: &clientStateMachine, serverStateMachine: &serverStateMachine, expectedError: TLSError.serverMissingSigningKey, errorLocation: ErrorLocation.sendServerCertificate)
    }

    func testClientHelloNegotiateCipherSuite() throws {
        let clientConfig = configurationGenerator.getClientConfigWithOptions(supportedCipherSuites: [.TLS_CHACHA20_POLY1305_SHA256, .TLS_AES_128_GCM_SHA256, .TLS_AES_256_GCM_SHA384])
        let serverConfig = configurationGenerator.getServerConfigWithOptions(supportedCipherSuites: [.TLS_AES_256_GCM_SHA384, .TLS_AES_128_GCM_SHA256, .TLS_CHACHA20_POLY1305_SHA256])
        var clientStateMachine = try HandshakeStateMachine(configuration: clientConfig)
        var serverStateMachine = try ServerHandshakeStateMachine(configuration: serverConfig)
        try runSuccessfulHandshake(clientStateMachine: &clientStateMachine, serverStateMachine: &serverStateMachine)
    }

    func testClientHelloNegotiateCipherSuiteSingleClient() throws {
        let clientConfig = configurationGenerator.getClientConfigWithOptions(supportedCipherSuites: [.TLS_AES_128_GCM_SHA256])
        let serverConfig = configurationGenerator.getServerConfigWithOptions(supportedCipherSuites: [.TLS_AES_256_GCM_SHA384, .TLS_AES_128_GCM_SHA256, .TLS_CHACHA20_POLY1305_SHA256])
        var clientStateMachine = try HandshakeStateMachine(configuration: clientConfig)
        var serverStateMachine = try ServerHandshakeStateMachine(configuration: serverConfig)
        try runSuccessfulHandshake(clientStateMachine: &clientStateMachine, serverStateMachine: &serverStateMachine)
    }

    func testClientHelloNegotiateCipherSuiteSingleServer() throws {
        let clientConfig = configurationGenerator.getClientConfigWithOptions(supportedCipherSuites: [.TLS_AES_256_GCM_SHA384, .TLS_AES_128_GCM_SHA256, .TLS_CHACHA20_POLY1305_SHA256])
        let serverConfig = configurationGenerator.getServerConfigWithOptions(supportedCipherSuites: [.TLS_AES_128_GCM_SHA256])
        var clientStateMachine = try HandshakeStateMachine(configuration: clientConfig)
        var serverStateMachine = try ServerHandshakeStateMachine(configuration: serverConfig)
        try runSuccessfulHandshake(clientStateMachine: &clientStateMachine, serverStateMachine: &serverStateMachine)
    }

    func testClientHelloChaCha20() throws {
        let clientConfig = configurationGenerator.getClientConfigWithOptions(supportedCipherSuites: [.TLS_CHACHA20_POLY1305_SHA256])
        let serverConfig = configurationGenerator.getServerConfigWithOptions(supportedCipherSuites: [.TLS_CHACHA20_POLY1305_SHA256])
        var clientStateMachine = try HandshakeStateMachine(configuration: clientConfig)
        var serverStateMachine = try ServerHandshakeStateMachine(configuration: serverConfig)
        try runSuccessfulHandshake(clientStateMachine: &clientStateMachine, serverStateMachine: &serverStateMachine)
    }

    func testServerRequiresDHEwithEPSK() throws {
        // check that if the client sends psk_key_exchange_modes without DHE
        // server ignores psks.
        let clientConfig = configurationGenerator.getClientConfigWithOptions()
        let serverConfig = configurationGenerator.getServerEPSKConfiguration()
        var clientStateMachine = try HandshakeStateMachine(configuration: clientConfig)
        var serverStateMachine = try ServerHandshakeStateMachine(configuration: serverConfig)

        var parser = HandshakeMessageParser()

        // Send Client Hello
        var originalClientHelloBytes = try clientStateMachine.startHandshake().handshakeBytesToSend!

        // Modify client hello to only offer pskOnly mode
        parser.appendBytes(&originalClientHelloBytes)
        guard let message = try parser.parseHandshakeMessage(), case .clientHello(var hello) = message.message else {
            XCTFail()
            return
        }

        let index = hello.extensions.firstIndex { $0 == .preSharedKeyKexModes(.init(modes: [.pskAndDHE])) }
        hello.extensions.remove(at: index!)
        hello.extensions.insert(.preSharedKeyKexModes(.init(modes: [.pskOnly])), at: index!)
        var clientHelloBytes = ByteBuffer()
        TLSMessageSerializer().writeHandshakeMessage(.clientHello(hello), into:&clientHelloBytes)

        // Read Client Hello and Send ServerHello
        XCTAssertEqual(serverStateMachine.stateDescription, "idle")
        serverStateMachine.receivedNetworkData(&clientHelloBytes)
        let result = try serverStateMachine.processHandshake()!
        result.assertNewReadAndWriteEncryptionLevel(.handshake)
        guard var serverHelloBytes = result.handshakeBytesToSend else {
            XCTFail()
            return
        }
        try checkHandshakeBytes(&parser, handshakeBytes: serverHelloBytes, expectedMessage: "serverHello")

        // We messed up the server/client views of the ClientHello, so signature
        // validation will fail if we attempt to finish handshake. But we just check
        // that the server does not send a pre_shared_key extension back.
        parser.appendBytes(&serverHelloBytes)
        guard let message = try parser.parseHandshakeMessage(), case .serverHello(let serverHello) = message.message else {
            XCTFail()
            return
        }

        XCTAssertFalse(serverHello.extensions.contains { if case .preSharedKey(_) = $0 { return true }; return false }, "server should not send pre_shared_key")
    }

    func testServerAbortsHSWithPSKAndNoPSKKeyExchangeModesExtension() throws {
        // "If clients offer "pre_shared_key" without a "psk_key_exchange_modes" extension,
        // servers MUST abort the handshake."
        let clientConfig = configurationGenerator.getClientEPSKConfiguration()
        let serverConfig = configurationGenerator.getServerEPSKConfiguration()
        var clientStateMachine = try HandshakeStateMachine(configuration: clientConfig)
        var serverStateMachine = try ServerHandshakeStateMachine(configuration: serverConfig)

        var parser = HandshakeMessageParser()

        // Send Client Hello
        var originalClientHelloBytes = try clientStateMachine.startHandshake().handshakeBytesToSend!

        // Modify client hello to omit psk_key_exchange_modes extension
        parser.appendBytes(&originalClientHelloBytes)
        guard let message = try parser.parseHandshakeMessage(), case .clientHello(var hello) = message.message else {
            XCTFail()
            return
        }

        let index = hello.extensions.firstIndex { $0 == .preSharedKeyKexModes(.init(modes: [.pskAndDHE])) }
        hello.extensions.remove(at: index!)
        var clientHelloBytes = ByteBuffer()
        TLSMessageSerializer().writeHandshakeMessage(.clientHello(hello), into:&clientHelloBytes)

        // Read Client Hello and Send ServerHello
        XCTAssertEqual(serverStateMachine.stateDescription, "idle")
        serverStateMachine.receivedNetworkData(&clientHelloBytes)

        XCTAssertThrowsError(try serverStateMachine.processHandshake()) { error in
            XCTAssertEqual(error as? TLSError, .missingPSKKeyExchangeModesExtension)
        }
    }

    // MARK: General Tests

    func testReadNetworkDataHappyPathSlabData() throws {
        let clientConfig = configurationGenerator.getClientConfigWithOptions()
        let serverConfig = configurationGenerator.getServerConfigWithOptions()
        var clientStateMachine = try HandshakeStateMachine(configuration: clientConfig)
        var serverStateMachine = try ServerHandshakeStateMachine(configuration: serverConfig)

        var parser = HandshakeMessageParser()
        var networkBuffer = ByteBuffer()

        // Send Client Hello
        var clientHelloBytes = try clientStateMachine.startHandshake().handshakeBytesToSend!

        // Read Client Hello and Send ServerHello
        XCTAssertEqual(serverStateMachine.stateDescription, "idle")
        serverStateMachine.receivedNetworkData(&clientHelloBytes)
        var result = try serverStateMachine.processHandshake()!
        result.assertNewReadAndWriteEncryptionLevel(.handshake)
        guard var serverHelloBytes = result.handshakeBytesToSend else {
            XCTFail()
            return
        }
        try checkHandshakeBytes(&parser, handshakeBytes: serverHelloBytes, expectedMessage: "serverHello")
        networkBuffer.writeBuffer(&serverHelloBytes)

        // Send Encrypted Extensions
        result = try serverStateMachine.processHandshake()!
        guard var serverEncryptedExtensionsBytes = result.handshakeBytesToSend else {
            XCTFail()
            return
        }
        try checkHandshakeBytes(&parser, handshakeBytes: serverEncryptedExtensionsBytes, expectedMessage: "encryptedExtensions")
        networkBuffer.writeBuffer(&serverEncryptedExtensionsBytes)

        // Send Certificate
        result = try serverStateMachine.processHandshake()!
        guard var serverCertificateBytes = result.handshakeBytesToSend else {
            XCTFail()
            return
        }
        try checkHandshakeBytes(&parser, handshakeBytes: serverCertificateBytes, expectedMessage: "certificate")
        networkBuffer.writeBuffer(&serverCertificateBytes)


        // Send CertificateVerify
        result = try serverStateMachine.processHandshake()!
        guard var serverCertificateVerifyBytes = result.handshakeBytesToSend else {
            XCTFail()
            return
        }
        try checkHandshakeBytes(&parser, handshakeBytes: serverCertificateVerifyBytes, expectedMessage: "certificateVerify")
        networkBuffer.writeBuffer(&serverCertificateVerifyBytes)

        // Send ServerFinished
        result = try serverStateMachine.processHandshake()!
        result.assertNewEncryptionLevel(.application, .write)
        guard var serverFinishedBytes = result.handshakeBytesToSend else {
            XCTFail()
            return
        }
        try checkHandshakeBytes(&parser, handshakeBytes: serverFinishedBytes, expectedMessage: "finished")
        networkBuffer.writeBuffer(&serverFinishedBytes)


        // feed in all server messages
        clientStateMachine.receivedNetworkData(&networkBuffer)
        // Now spin the state machine. This will initially go up to the handshake keys.
        result = try clientStateMachine.processHandshake()!
        XCTAssertNil(result.handshakeBytesToSend)
        result.assertNewReadAndWriteEncryptionLevel(.handshake)

        // Spin again, we'll go through to the application keys and finished message.
        result = try clientStateMachine.processHandshake()!
        result.assertNewReadAndWriteEncryptionLevel(.application)
        var clientFinishedBytes = result.handshakeBytesToSend!
        var clientFinishedBytesCopy = result.handshakeBytesToSend!
        parser.appendBytes(&clientFinishedBytesCopy)
        guard let message = try parser.parseHandshakeMessage(), case .finished =
                message.message else {
            XCTFail()
            return
        }

        // Read ClientFinished
        serverStateMachine.receivedNetworkData(&clientFinishedBytes)
        result = try serverStateMachine.processHandshake()!
        result.assertNewEncryptionLevel(.application, .read)
        XCTAssertEqual(serverStateMachine.stateDescription, "readyForData")
    }

    // client hello with legacy_version not set to 0x303
    func testClientHelloLegacyVersionWrong() throws {
        let serverConfig = configurationGenerator.getServerConfigWithOptions()
        var serverStateMachine = try ServerHandshakeStateMachine(configuration: serverConfig)

        var clientHello = goodClientHello
        clientHello.legacyVersion = .tlsv10
        var buffer = ByteBuffer()
        TLSMessageSerializer().writeHandshakeMessage(.clientHello(clientHello), into: &buffer)

        // Read Client Hello
        XCTAssertEqual(serverStateMachine.stateDescription, "idle")
        serverStateMachine.receivedNetworkData(&buffer)
        XCTAssertThrowsError(try serverStateMachine.processHandshake()) { error in
            XCTAssertEqual(error as? TLSError, .handshakeInvalidMessage)
        }
    }

    // client hello without supported_versions extension missing
    func testClientHelloMissingSupportedVersionsExtension() throws {
        let serverConfig = configurationGenerator.getServerConfigWithOptions()
        var serverStateMachine = try ServerHandshakeStateMachine(configuration: serverConfig)

        var clientHello = goodClientHello
        clientHello.extensions.remove(at: 0)
        var buffer = ByteBuffer()
        TLSMessageSerializer().writeHandshakeMessage(.clientHello(clientHello), into: &buffer)

        // Read Client Hello
        XCTAssertEqual(serverStateMachine.stateDescription, "idle")
        serverStateMachine.receivedNetworkData(&buffer)
        XCTAssertThrowsError(try serverStateMachine.processHandshake()) { error in
            XCTAssertEqual(error as? TLSError, .protocolVersion)
        }
    }

    // client hello with supported_versions extension that does not include 0x0304
    func testClientHelloSupportedVersionsMissingTLS13() throws {
        let serverConfig = configurationGenerator.getServerConfigWithOptions()
        var serverStateMachine = try ServerHandshakeStateMachine(configuration: serverConfig)
        var clientHello = goodClientHello
        clientHello.extensions.remove(at: 0)
        clientHello.extensions.append(.supportedVersions(.offer([.tlsv12])))
        var buffer = ByteBuffer()
        TLSMessageSerializer().writeHandshakeMessage(.clientHello(clientHello), into: &buffer)

        // Read Client Hello
        XCTAssertEqual(serverStateMachine.stateDescription, "idle")
        serverStateMachine.receivedNetworkData(&buffer)
        XCTAssertThrowsError(try serverStateMachine.processHandshake()) { error in
            XCTAssertEqual(error as? TLSError, .handshakeInvalidMessage)
        }
    }

    // client hello without TLS_AES_256_GCM_SHA384 in cipher suites
    func testClientHelloNoCommonCipherSuites() throws {
        let serverConfig = configurationGenerator.getServerConfigWithOptions()
        var serverStateMachine = try ServerHandshakeStateMachine(configuration: serverConfig)
        var clientHello = goodClientHello
        clientHello.cipherSuites = []
        var buffer = ByteBuffer()
        TLSMessageSerializer().writeHandshakeMessage(.clientHello(clientHello), into: &buffer)

        // Read Client Hello
        XCTAssertEqual(serverStateMachine.stateDescription, "idle")
        serverStateMachine.receivedNetworkData(&buffer)
        XCTAssertThrowsError(try serverStateMachine.processHandshake()) { error in
            XCTAssertEqual(error as? TLSError, .negotiationFailed)
        }
    }

    // client hello with legacy_compression_methods set to non zero value
    func testClientHelloLegacyCompressionMethodsNonZero() throws {
        let serverConfig = configurationGenerator.getServerConfigWithOptions()
        var serverStateMachine = try ServerHandshakeStateMachine(configuration: serverConfig)
        var clientHello = goodClientHello
        clientHello.legacyCompressionMethods = [1]
        var buffer = ByteBuffer()
        TLSMessageSerializer().writeHandshakeMessage(.clientHello(clientHello), into: &buffer)

        // Read Client Hello
        XCTAssertEqual(serverStateMachine.stateDescription, "idle")
        serverStateMachine.receivedNetworkData(&buffer)
        XCTAssertThrowsError(try serverStateMachine.processHandshake()) { error in
            XCTAssertEqual(error as? TLSError, .handshakeInvalidMessage)
        }
    }

    // client hello without key_shares extension
    func testClientHelloMissingKeySharesExtension() throws {
        let serverConfig = configurationGenerator.getServerConfigWithOptions()
        var serverStateMachine = try ServerHandshakeStateMachine(configuration: serverConfig)
        var clientHello = goodClientHello
        clientHello.extensions.remove(at: 2)
        var buffer = ByteBuffer()
        TLSMessageSerializer().writeHandshakeMessage(.clientHello(clientHello), into: &buffer)

        // Read Client Hello
        XCTAssertEqual(serverStateMachine.stateDescription, "idle")
        serverStateMachine.receivedNetworkData(&buffer)
        XCTAssertThrowsError(try serverStateMachine.processHandshake()) { error in
            XCTAssertEqual(error as? TLSError, .missingExtension)
        }
    }

    // client hello where key_shares does not contain a key share for negotiated group fails right now (should be hello retry request)
    func testClientHelloMissingKeyShareForNegotiatedGroup() throws {
        let serverConfig = configurationGenerator.getServerConfigWithOptions()
        var serverStateMachine = try ServerHandshakeStateMachine(configuration: serverConfig)
        var clientHello = goodClientHello
        clientHello.extensions.remove(at: 2)
        let ephemeralKey = Curve25519EphemeralKey()
        clientHello.extensions.append(.keyShare(.clientHello([.init(group: ephemeralKey.namedGroup, keyExchange: ByteBuffer(data: ephemeralKey.publicKeyData))])))
        var buffer = ByteBuffer()
        TLSMessageSerializer().writeHandshakeMessage(.clientHello(clientHello), into: &buffer)

        // Read Client Hello
        XCTAssertEqual(serverStateMachine.stateDescription, "idle")
        serverStateMachine.receivedNetworkData(&buffer)
        XCTAssertThrowsError(try serverStateMachine.processHandshake()) { error in
            XCTAssertEqual(error as? TLSError, .helloRetryRequestPlaceholder)
        }
    }

    // client hello where key_shares is empty right now (should be hello retry request)
    func testClientHelloEmptyKeyShares() throws {
        let serverConfig = configurationGenerator.getServerConfigWithOptions()
        var serverStateMachine = try ServerHandshakeStateMachine(configuration: serverConfig)
        var clientHello = goodClientHello
        clientHello.extensions.remove(at: 2)
        clientHello.extensions.append(.keyShare(.clientHello([])))
        var buffer = ByteBuffer()
        TLSMessageSerializer().writeHandshakeMessage(.clientHello(clientHello), into: &buffer)

        // Read Client Hello
        XCTAssertEqual(serverStateMachine.stateDescription, "idle")
        serverStateMachine.receivedNetworkData(&buffer)
        XCTAssertThrowsError(try serverStateMachine.processHandshake()) { error in
            XCTAssertEqual(error as? TLSError, .helloRetryRequestPlaceholder)
        }
    }

    // client hello missing supported_groups extension
    func testClientHelloMissingSupportedGroupsExtension() throws {
        let serverConfig = configurationGenerator.getServerConfigWithOptions()
        var serverStateMachine = try ServerHandshakeStateMachine(configuration: serverConfig)
        var clientHello = goodClientHello
        clientHello.extensions.remove(at: 1)
        var buffer = ByteBuffer()
        TLSMessageSerializer().writeHandshakeMessage(.clientHello(clientHello), into: &buffer)

        // Read Client Hello
        XCTAssertEqual(serverStateMachine.stateDescription, "idle")
        serverStateMachine.receivedNetworkData(&buffer)
        XCTAssertThrowsError(try serverStateMachine.processHandshake()) { error in
            XCTAssertEqual(error as? TLSError, .missingExtension)
        }
    }

    // client hello with supported_groups extension that does not contain secp384 or x25519
    func testClientHelloNoCommonSupportedGroups() throws {
        let serverConfig = configurationGenerator.getServerConfigWithOptions()
        var serverStateMachine = try ServerHandshakeStateMachine(configuration: serverConfig)
        var clientHello = goodClientHello
        clientHello.extensions.remove(at: 1)
        clientHello.extensions.append(.supportedGroups(.init(groups: [])))
        var buffer = ByteBuffer()
        TLSMessageSerializer().writeHandshakeMessage(.clientHello(clientHello), into: &buffer)

        // Read Client Hello
        XCTAssertEqual(serverStateMachine.stateDescription, "idle")
        serverStateMachine.receivedNetworkData(&buffer)
        XCTAssertThrowsError(try serverStateMachine.processHandshake()) { error in
            XCTAssertEqual(error as? TLSError, .negotiationFailed)
        }
    }

    // TODO: when certificate support added, add a test for client hello without signature_algorithms extension
    // client hello without signature_algorithms extension ok (since always using raw public keys)
    func testClientHelloMissingSignatureAlgorithmsExtension() throws {
        let serverConfig = configurationGenerator.getServerConfigWithOptions()
        var serverStateMachine = try ServerHandshakeStateMachine(configuration: serverConfig)
        var clientHello = goodClientHello
        clientHello.extensions.remove(at: 3) // remove signature algorithms extension
        var buffer = ByteBuffer()
        TLSMessageSerializer().writeHandshakeMessage(.clientHello(clientHello), into: &buffer)

        // Read Client Hello
        XCTAssertEqual(serverStateMachine.stateDescription, "idle")
        serverStateMachine.receivedNetworkData(&buffer)
        XCTAssertNoThrow(try serverStateMachine.processHandshake())
    }

    // client hello no common signature algoirthms
    func testClientHelloNoCommonSignatureAlgorithms() throws {
        let serverConfig = configurationGenerator.getServerConfigWithOptions()
        var serverStateMachine = try ServerHandshakeStateMachine(configuration: serverConfig)
        var clientHello = goodClientHello
        clientHello.extensions.remove(at: 3)
        clientHello.extensions.append(.signatureAlgorithms(.init(schemes: [])))
        var buffer = ByteBuffer()
        TLSMessageSerializer().writeHandshakeMessage(.clientHello(clientHello), into: &buffer)

        // Read Client Hello
        XCTAssertEqual(serverStateMachine.stateDescription, "idle")
        serverStateMachine.receivedNetworkData(&buffer)
        XCTAssertThrowsError(try serverStateMachine.processHandshake()) { error in
            XCTAssertEqual(error as? TLSError, .negotiationFailed)
        }
    }

    // client hello with server_certificate_type extension does not contain a server supported type fails
    func testClientHelloNoServerSupportedCertificateType() throws {
        let serverConfig = configurationGenerator.getServerConfigWithOptions()
        var serverStateMachine = try ServerHandshakeStateMachine(configuration: serverConfig)
        var clientHello = goodClientHello
        clientHello.extensions.remove(at: 4)
        clientHello.extensions.append(.serverCertificateType(Extension.CertificateTypeExt.offer([CertificateType(rawValue: 99)])))
        var buffer = ByteBuffer()
        TLSMessageSerializer().writeHandshakeMessage(.clientHello(clientHello), into: &buffer)

        // Read Client Hello
        XCTAssertEqual(serverStateMachine.stateDescription, "idle")
        serverStateMachine.receivedNetworkData(&buffer)
        XCTAssertThrowsError(try serverStateMachine.processHandshake()) { error in
            XCTAssertEqual(error as? TLSError, .unsupportedCertificate)
        }
    }

    // client hello with no server_certificate_type extension server does not respond with a server_certificate_type extension
    func testNoServerCertificateTypeExtension() throws {
        let serverConfig = configurationGenerator.getServerConfigWithOptions()
        var serverStateMachine = try ServerHandshakeStateMachine(configuration: serverConfig)
        var parser = HandshakeMessageParser()

        var clientHello = goodClientHello
        clientHello.extensions.remove(at: 4)
        var buffer = ByteBuffer()
        TLSMessageSerializer().writeHandshakeMessage(.clientHello(clientHello), into: &buffer)

        // Read Client Hello
        XCTAssertEqual(serverStateMachine.stateDescription, "idle")
        serverStateMachine.receivedNetworkData(&buffer)

        var result = try serverStateMachine.processHandshake()!
        result.assertNewReadAndWriteEncryptionLevel(.handshake)
        guard let serverHelloBytes = result.handshakeBytesToSend else {
            XCTFail()
            return
        }
        try checkHandshakeBytes(&parser, handshakeBytes: serverHelloBytes, expectedMessage: "serverHello")

        // Send Encrypted Extensions
        result = try serverStateMachine.processHandshake()!
        guard let serverEncryptedExtensionsBytes = result.handshakeBytesToSend else {
            XCTFail()
            return
        }
        var handshakeBytesCopy = serverEncryptedExtensionsBytes
        parser.appendBytes(&handshakeBytesCopy)
        guard let message = try parser.parseHandshakeMessage(), message.message.logDescription == "encryptedExtensions" else {
            XCTFail()
            return
        }
        switch (message.message) {
        case .encryptedExtensions(let extensions):
            XCTAssert(!(extensions.extensions.contains(where: { $0.type == .serverCertificateType })))
        default:
            XCTFail()
        }

    }

    func testClientHelloWithDuplicateExtensions() throws {
        let serverConfig = configurationGenerator.getServerConfigWithOptions()
        var serverStateMachine = try ServerHandshakeStateMachine(configuration: serverConfig)

        var clientHello = goodClientHello
        clientHello.extensions.append(.keyShare(.clientHello([])))
        var buffer = ByteBuffer()
        TLSMessageSerializer().writeHandshakeMessage(.clientHello(clientHello), into: &buffer)

        // Read Client Hello
        XCTAssertEqual(serverStateMachine.stateDescription, "idle")
        serverStateMachine.receivedNetworkData(&buffer)
        XCTAssertThrowsError(try serverStateMachine.processHandshake()) { error in
            XCTAssertEqual(error as? TLSError, .handshakeInvalidMessage)
        }
    }

    // ALPN extension is required extension when QUIC is used
    func testClientHelloWithNoALPN() throws {
        let serverConfig = configurationGenerator.getServerConfigWithOptions(quicTransportParams: ByteBuffer("opaque bytes"), transportIsQUIC: true)
        var serverStateMachine = try ServerHandshakeStateMachine(configuration: serverConfig)
        XCTAssertNil(serverStateMachine.peerQUICTransportParameters)

        var clientHello = goodClientHello
        clientHello.extensions.remove(at: 7)
        var buffer = ByteBuffer()
        TLSMessageSerializer().writeHandshakeMessage(.clientHello(clientHello), into: &buffer)

        // Read Client Hello
        XCTAssertEqual(serverStateMachine.stateDescription, "idle")
        serverStateMachine.receivedNetworkData(&buffer)
        XCTAssertThrowsError(try serverStateMachine.processHandshake()) { error in
            XCTAssertEqual(error as? TLSError, .noApplicationProtocol)
        }
    }

    func testCanReadQUICTransportParametersFullHandshake() throws {
        let clientConfig = configurationGenerator.getClientConfigWithOptions(quicTransportParams: ByteBuffer("opaque client quic params"), alpn: ["protoX"])
        let serverConfig = configurationGenerator.getServerConfigWithOptions(quicTransportParams: ByteBuffer("opaque server quic params"), alpn: ["protoY", "protoX"])

        var clientStateMachine = try HandshakeStateMachine(configuration: clientConfig)
        var serverStateMachine = try ServerHandshakeStateMachine(configuration: serverConfig)

        var parser = HandshakeMessageParser()

        XCTAssertNil(serverStateMachine.peerQUICTransportParameters)
        XCTAssertNil(clientStateMachine.peerQUICTransportParameters)

        // Send Client Hello
        var clientHelloBytes = try clientStateMachine.startHandshake().handshakeBytesToSend!
        XCTAssertNil(serverStateMachine.peerQUICTransportParameters)
        XCTAssertNil(clientStateMachine.peerQUICTransportParameters)

        // Read Client Hello and Send ServerHello
        XCTAssertEqual(serverStateMachine.stateDescription, "idle")
        serverStateMachine.receivedNetworkData(&clientHelloBytes)
        var result = try serverStateMachine.processHandshake()!
        result.assertNewReadAndWriteEncryptionLevel(.handshake)
        guard var serverHelloBytes = result.handshakeBytesToSend else {
            XCTFail()
            return
        }
        try checkHandshakeBytes(&parser, handshakeBytes: serverHelloBytes, expectedMessage: "serverHello")
        XCTAssertEqual(serverStateMachine.peerQUICTransportParameters, clientConfig.quicTransportParameters)
        XCTAssertNil(clientStateMachine.peerQUICTransportParameters)

        // Read Server Hello
        clientStateMachine.receivedNetworkData(&serverHelloBytes)
        result = try clientStateMachine.processHandshake()!
        XCTAssertNil(result.handshakeBytesToSend)
        result.assertNewReadAndWriteEncryptionLevel(.handshake)
        XCTAssertNil(clientStateMachine.peerQUICTransportParameters)

        // Send Encrypted Extensions
        result = try serverStateMachine.processHandshake()!
        guard var serverEncryptedExtensionsBytes = result.handshakeBytesToSend else {
            XCTFail()
            return
        }
        try checkHandshakeBytes(&parser, handshakeBytes: serverEncryptedExtensionsBytes, expectedMessage: "encryptedExtensions")
        XCTAssertEqual(serverStateMachine.peerQUICTransportParameters, clientConfig.quicTransportParameters)

        // Read Encrypted Extensions
        clientStateMachine.receivedNetworkData(&serverEncryptedExtensionsBytes)
        XCTAssertNil(try clientStateMachine.processHandshake())
        XCTAssertEqual(clientStateMachine.peerQUICTransportParameters, serverConfig.quicTransportParameters)

        // Send Certificate
        result = try serverStateMachine.processHandshake()!
        guard var serverCertificateBytes = result.handshakeBytesToSend else {
            XCTFail()
            return
        }
        try checkHandshakeBytes(&parser, handshakeBytes: serverCertificateBytes, expectedMessage: "certificate")
        XCTAssertEqual(serverStateMachine.peerQUICTransportParameters, clientConfig.quicTransportParameters)

        // Read Server Certificate
        clientStateMachine.receivedNetworkData(&serverCertificateBytes)
        XCTAssertNil(try clientStateMachine.processHandshake())
        XCTAssertEqual(clientStateMachine.peerQUICTransportParameters, serverConfig.quicTransportParameters)

        // Send CertificateVerify
        result = try serverStateMachine.processHandshake()!
        guard var serverCertificateVerifyBytes = result.handshakeBytesToSend else {
            XCTFail()
            return
        }
        try checkHandshakeBytes(&parser, handshakeBytes: serverCertificateVerifyBytes, expectedMessage: "certificateVerify")
        XCTAssertEqual(serverStateMachine.peerQUICTransportParameters, clientConfig.quicTransportParameters)

        // Read Server CertificateVerify
        clientStateMachine.receivedNetworkData(&serverCertificateVerifyBytes)
        XCTAssertNil(try clientStateMachine.processHandshake())
        XCTAssertEqual(clientStateMachine.peerQUICTransportParameters, serverConfig.quicTransportParameters)

        // Send ServerFinished
        result = try serverStateMachine.processHandshake()!
        result.assertNewEncryptionLevel(.application, .write)
        guard var serverFinishedBytes = result.handshakeBytesToSend else {
            XCTFail()
            return
        }
        try checkHandshakeBytes(&parser, handshakeBytes: serverFinishedBytes, expectedMessage: "finished")
        XCTAssertEqual(serverStateMachine.peerQUICTransportParameters, clientConfig.quicTransportParameters)

        // Read ServerFinished and Send ClientFinished
        clientStateMachine.receivedNetworkData(&serverFinishedBytes)
        result = try clientStateMachine.processHandshake()!
        result.assertNewReadAndWriteEncryptionLevel(.application)
        XCTAssertNotNil(result.handshakeBytesToSend)

        var clientFinishedBytes = result.handshakeBytesToSend!
        var clientFinishedBytesCopy = result.handshakeBytesToSend!
        parser.appendBytes(&clientFinishedBytesCopy)
        guard let message = try parser.parseHandshakeMessage(), case .finished =
                message.message else {
            XCTFail()
            return
        }
        XCTAssertEqual(clientStateMachine.peerQUICTransportParameters, serverConfig.quicTransportParameters)

        // Read ClientFinished
        serverStateMachine.receivedNetworkData(&clientFinishedBytes)
        result = try serverStateMachine.processHandshake()!
        result.assertNewEncryptionLevel(.application, .read)
        XCTAssertEqual(serverStateMachine.stateDescription, "readyForData")
        XCTAssertEqual(serverStateMachine.peerQUICTransportParameters, clientConfig.quicTransportParameters)
    }

   func testCanReadALPNFullHandshake() throws {
       let clientConfig = configurationGenerator.getClientConfigWithOptions(alpn: ["protocolA"])
       let serverConfig = configurationGenerator.getServerConfigWithOptions(alpn: ["protocolB", "protocolA"])
        let expectedApplicationProtocol = "protocolA"

        var clientStateMachine = try HandshakeStateMachine(configuration: clientConfig)
        var serverStateMachine = try ServerHandshakeStateMachine(configuration: serverConfig)

        var parser = HandshakeMessageParser()

        XCTAssertNil(clientStateMachine.peerALPN)

        // Send Client Hello
        var clientHelloBytes = try clientStateMachine.startHandshake().handshakeBytesToSend!
        XCTAssertNil(clientStateMachine.peerALPN)

        // Read Client Hello and Send ServerHello
        XCTAssertEqual(serverStateMachine.stateDescription, "idle")
        serverStateMachine.receivedNetworkData(&clientHelloBytes)
        var result = try serverStateMachine.processHandshake()!
        result.assertNewReadAndWriteEncryptionLevel(.handshake)
        guard var serverHelloBytes = result.handshakeBytesToSend else {
            XCTFail()
            return
        }
        try checkHandshakeBytes(&parser, handshakeBytes: serverHelloBytes, expectedMessage: "serverHello")
        XCTAssertNil(clientStateMachine.peerALPN)

        // Read Server Hello
        clientStateMachine.receivedNetworkData(&serverHelloBytes)
        result = try clientStateMachine.processHandshake()!
        XCTAssertNil(result.handshakeBytesToSend)
        result.assertNewReadAndWriteEncryptionLevel(.handshake)
        XCTAssertNil(clientStateMachine.peerQUICTransportParameters)

        // Send Encrypted Extensions
        result = try serverStateMachine.processHandshake()!
        guard var serverEncryptedExtensionsBytes = result.handshakeBytesToSend else {
            XCTFail()
            return
        }
        try checkHandshakeBytes(&parser, handshakeBytes: serverEncryptedExtensionsBytes, expectedMessage: "encryptedExtensions")
        XCTAssertEqual(serverStateMachine.peerQUICTransportParameters, clientConfig.quicTransportParameters)

        // Read Encrypted Extensions
        clientStateMachine.receivedNetworkData(&serverEncryptedExtensionsBytes)
        XCTAssertNil(try clientStateMachine.processHandshake())
        XCTAssertEqual(clientStateMachine.peerALPN, expectedApplicationProtocol)

        // Send Certificate
        result = try serverStateMachine.processHandshake()!
        guard var serverCertificateBytes = result.handshakeBytesToSend else {
            XCTFail()
            return
        }
        try checkHandshakeBytes(&parser, handshakeBytes: serverCertificateBytes, expectedMessage: "certificate")

        // Read Server Certificate
        clientStateMachine.receivedNetworkData(&serverCertificateBytes)
        XCTAssertNil(try clientStateMachine.processHandshake())
        XCTAssertEqual(clientStateMachine.peerALPN, expectedApplicationProtocol)

        // Send CertificateVerify
        result = try serverStateMachine.processHandshake()!
        guard var serverCertificateVerifyBytes = result.handshakeBytesToSend else {
            XCTFail()
            return
        }
        try checkHandshakeBytes(&parser, handshakeBytes: serverCertificateVerifyBytes, expectedMessage: "certificateVerify")

        // Read Server CertificateVerify
        clientStateMachine.receivedNetworkData(&serverCertificateVerifyBytes)
        XCTAssertNil(try clientStateMachine.processHandshake())
        XCTAssertEqual(clientStateMachine.peerALPN, expectedApplicationProtocol)

        // Send ServerFinished
        result = try serverStateMachine.processHandshake()!
        result.assertNewEncryptionLevel(.application, .write)
        guard var serverFinishedBytes = result.handshakeBytesToSend else {
            XCTFail()
            return
        }
        try checkHandshakeBytes(&parser, handshakeBytes: serverFinishedBytes, expectedMessage: "finished")

        // Read ServerFinished and Send ClientFinished
        clientStateMachine.receivedNetworkData(&serverFinishedBytes)
        result = try clientStateMachine.processHandshake()!
        result.assertNewReadAndWriteEncryptionLevel(.application)
        XCTAssertNotNil(result.handshakeBytesToSend)

        var clientFinishedBytes = result.handshakeBytesToSend!
        var clientFinishedBytesCopy = result.handshakeBytesToSend!
        parser.appendBytes(&clientFinishedBytesCopy)
        guard let message = try parser.parseHandshakeMessage(), case .finished =
                message.message else {
            XCTFail()
            return
        }
        XCTAssertEqual(clientStateMachine.peerALPN, expectedApplicationProtocol)

        // Read ClientFinished
        serverStateMachine.receivedNetworkData(&clientFinishedBytes)
        result = try serverStateMachine.processHandshake()!
        result.assertNewEncryptionLevel(.application, .read)
        XCTAssertEqual(serverStateMachine.stateDescription, "readyForData")
    }

    func testALPNMismatch() throws {
        let clientConfig = configurationGenerator.getClientConfigWithOptions(alpn: ["protocolA"])
        let serverConfig = configurationGenerator.getServerConfigWithOptions(alpn: ["protocolB", "protocolC"])

        var clientStateMachine = try HandshakeStateMachine(configuration: clientConfig)
        var serverStateMachine = try ServerHandshakeStateMachine(configuration: serverConfig)

        // Send Client Hello
        var clientHelloBytes = try clientStateMachine.startHandshake().handshakeBytesToSend!

        // Read Client Hello and Send ServerHello
        XCTAssertEqual(serverStateMachine.stateDescription, "idle")
        serverStateMachine.receivedNetworkData(&clientHelloBytes)
        XCTAssertThrowsError(try serverStateMachine.processHandshake()) { error in
            XCTAssertEqual(error as? TLSError, .noApplicationProtocol)
        }
    }

    // MARK: - PQTLS Server Tests

    func testPQTLSClientToServerHandshake() throws {
        let clientConfig = configurationGenerator.getClientConfigWithOptions(
            fixedKeyExchangeGroup: .x25519MLKEM768
        )
        let serverConfig = configurationGenerator.getServerConfigWithOptions()
        var clientStateMachine = try HandshakeStateMachine(configuration: clientConfig)
        var serverStateMachine = try ServerHandshakeStateMachine(configuration: serverConfig)
        try runSuccessfulHandshake(clientStateMachine: &clientStateMachine, serverStateMachine: &serverStateMachine)
    }

    func testClassicalClientToPQTLSEnabledServer() throws {
        let clientConfig = configurationGenerator.getClientConfigWithOptions(
            fixedKeyExchangeGroup: .secp384
        )
        let serverConfig = configurationGenerator.getServerConfigWithOptions()
        var clientStateMachine = try HandshakeStateMachine(configuration: clientConfig)
        var serverStateMachine = try ServerHandshakeStateMachine(configuration: serverConfig)
        try runSuccessfulHandshake(clientStateMachine: &clientStateMachine, serverStateMachine: &serverStateMachine)
    }
}
