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

#if canImport(Foundation) && !SWIFTTLS_EMBEDDED
import Foundation
#endif

// Result type for async computations applied to the handshaker.
@_spi(SwiftTLSProtocol)
@available(SwiftTLS 0.1.0, *)
public struct PendingAsyncResult: Sendable {
    enum AsyncResult {
        case certificate(CertificateResult)
        case signature(SignatureResult)
        case verification(VerificationResult)
    }

    var asyncResult: AsyncResult

    public static func certificate(_ result: CertificateResult) -> Self {
        .init(asyncResult: .certificate(result))
    }

    public static func signature(_ result: SignatureResult) -> Self {
        .init(asyncResult: .signature(result))
    }

    public static func verification(_ result: VerificationResult) -> Self {
        .init(asyncResult: .verification(result))
    }
}

// List of opaque certificate data.
@_spi(SwiftTLSProtocol)
@available(SwiftTLS 0.1.0, *)
public struct CertificateList: Sendable, Hashable {
    public var type: CertificateType
    public var entries: [Data]

    public init(type: CertificateType, entries: [Data]) {
        self.type = type
        self.entries = entries
    }
}

// Information offered by the client during the handshake.
@_spi(SwiftTLSProtocol)
@available(SwiftTLS 0.1.0, *)
public struct PeerOffer: Sendable, Hashable {
    public var certificateTypes: [CertificateType]
    public var signatureAlgorithms: [UInt16]
    public var serverName: String?
    public var alpns: [String]?

    init(clientHello: ClientHello) {
        self.certificateTypes = clientHello.serverCertificateTypes
        self.signatureAlgorithms = clientHello.signatureAlgorithms
        self.serverName = clientHello.serverName
        self.alpns = clientHello.alpns
    }
}

// The result waiting indicates asynchronous work in the callback.
// The reason given for an unavailable certificate will be logged.
@_spi(SwiftTLSProtocol)
@available(SwiftTLS 0.1.0, *)
public enum CertificateResult: Sendable, Hashable {
    case available(CertificateList)
    case unavailable(reason: String)
    case waiting
}

// Information passed into the callback.
@_spi(SwiftTLSProtocol)
@available(SwiftTLS 0.1.0, *)
public struct CertificateInfo: Sendable {
    public var peerOffer: PeerOffer
    public var deliverResult: (@Sendable (CertificateResult) -> Void)?

    init(peerOffer: PeerOffer) {
        self.peerOffer = peerOffer
    }
}

// This callback should provide the certificate data to include in the
// certificate message sent by the server.
//
// Note: This callback must either return a result directly (available, unavailable)
//  or return waiting and call `deliverResult` with the pending result.
@_spi(SwiftTLSProtocol)
@available(SwiftTLS 0.1.0, *)
public typealias CertificateCallback = @Sendable (CertificateInfo) -> CertificateResult

// The result waiting indicates asynchronous work in the callback.
// The reason given for an unavailable signature will be logged.
@_spi(SwiftTLSProtocol)
@available(SwiftTLS 0.1.0, *)
public enum SignatureResult: Sendable, Hashable {
    case available(signature: Data, algorithm: UInt16)
    case unavailable(reason: String)
    case waiting
}

// Information passed into the callback.
@_spi(SwiftTLSProtocol)
@available(SwiftTLS 0.1.0, *)
public struct SignatureInfo: Sendable {
    public var transcriptHash: Data
    public var peerOffer: PeerOffer
    public var deliverResult: (@Sendable (SignatureResult) -> Void)?

    public init(transcriptHash: Data, peerOffer: PeerOffer) {
        self.transcriptHash = transcriptHash
        self.peerOffer = peerOffer
    }
}

// This callback should sign the provided transcript hash and return the
// signature along with the signature algorithm.
//
// Note: This callback must either return a result directly (available, unavailable)
//  or return waiting and call `deliverResult` with the pending result.
@_spi(SwiftTLSProtocol)
@available(SwiftTLS 0.1.0, *)
public typealias SignatureCallback = @Sendable (SignatureInfo) -> SignatureResult

// Bundles the callbacks for the server to customize the certificate messages.
@_spi(SwiftTLSProtocol)
@available(SwiftTLS 0.1.0, *)
public struct AsyncAuthenticator: Sendable {
    public var supportedCertificateTypes: [CertificateType]
    public var getCertificateChain: CertificateCallback
    public var signTranscriptHash: SignatureCallback

    public init(supportedCertificateTypes: [CertificateType], getCertificateChain: @escaping CertificateCallback, signTranscriptHash: @escaping  SignatureCallback) {
        self.init(certificateTypes: supportedCertificateTypes, certificateCallback: getCertificateChain, signatureCallback: signTranscriptHash)
    }

    private init(certificateTypes: [CertificateType], certificateCallback: @escaping CertificateCallback, signatureCallback: @escaping  SignatureCallback) {
        self.supportedCertificateTypes = certificateTypes
        self.getCertificateChain = certificateCallback
        self.signTranscriptHash = signatureCallback
    }
}

// Waiting indicates ongoing asynchronous work in the callback.
// The reason given for an invalid verification will be logged.
@_spi(SwiftTLSProtocol)
@available(SwiftTLS 0.1.0, *)
public enum VerificationResult: Sendable, Hashable {
    case valid
    case invalid(reason: String)
    case waiting
}

// Information to verify the certificates and signature presented by the peer.
@_spi(SwiftTLSProtocol)
@available(SwiftTLS 0.1.0, *)
public struct VerificationInfo: Sendable {
    public var certificates: CertificateList
    public var signatureAlgorithm: UInt16
    public var signature: Data
    public var transcriptHash: Data
    public var deliverResult: (@Sendable (VerificationResult) -> Void)?

    public init(certificates: CertificateList, signatureAlgorithm: UInt16, signature: Data, transcriptHash: Data) {
        self.certificates = certificates
        self.signatureAlgorithm = signatureAlgorithm
        self.signature = signature
        self.transcriptHash = transcriptHash
    }
}

// This callback should perform two operations:
//  1. Verify the certificate chain from the peer Certificate message.
//  2. Given the signature algorithm and the public key at the leaf of the
//     certificate chain, verify that the signature is valid for the
//     transcription hash.
//
// Note: This callback must either return a result directly (valid, invalid)
//  or return waiting and call `deliverResult` with the pending result.
@_spi(SwiftTLSProtocol)
@available(SwiftTLS 0.1.0, *)
public typealias VerificationCallback = @Sendable (VerificationInfo) -> VerificationResult

@_spi(SwiftTLSProtocol)
@available(SwiftTLS 0.1.0, *)
public struct AsyncVerifier: Sendable {
    public var availableCertificateTypes: [CertificateType]
    public var verifyHandshake: VerificationCallback

    public init(availableCertificateTypes: [CertificateType], verificationCallback: @escaping  VerificationCallback) {
        self.availableCertificateTypes = availableCertificateTypes
        self.verifyHandshake = verificationCallback
    }
}
