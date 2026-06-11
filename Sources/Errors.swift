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

#if !canImport(CryptoKit)
typealias CryptoKitMetaError = any Error
#endif

@available(anyAppleOS 26, *)
enum TLSError: Error, Equatable {
    case truncatedMessage
    case excessBytes
    case invalidMessageForExtension(messageType: HandshakeType, extensionType: ExtensionType)
    case handshakeError
    case handshakeUnexpectedRead
    case handshakeUnexpectedMessage
    case handshakeInvalidMessage
    case negotiationFailed
    case invalidSerializedSession
    case invalidSerializedImportedIdentity
    case insufficientBytes
    case exporterInvalidMessage
    case exporterInvalidState
    case certificateError
    case protocolVersion
    case missingExtension
    case unsupportedCertificate
    case helloRetryRequestPlaceholder
    case noApplicationProtocol
    case invalidApplicationProtocol
    case sessionMissingPeerCertificates // disallow session tickets when server authenticated with EPSK.
    case sessionMissingNegotiatedCipherSuiteOrGroup
    case missingTargetKDFs
    case importedIdentityTooLong
    case insufficientLengthForEPSK
    case serverMissingSigningKey
    case serverMissingSignature
    case serverMissingCertificate
    case missingPSKKeyExchangeModesExtension
    case unknownCiphersuite
    case decodeError
    case recordOverflow
    case incorrectNonceLength
    case startHandshakeCalledOnServer
    case decryptError
    case internalError(reason: String)
    case wrappedCryptoError
    case illegalParameter
    case ciphertextRecordTooShort
    case invalidAlertBeforeHandshakeStart
    case processNetworkDataErrorBeforeHandshakeStart
    case certificateRequired
    case unsupportedExtension
    case handshakeFailure
    case invalidConfigurationOptions
    case refKeySigningFailure
}

@available(anyAppleOS 26, *)
extension TLSError {
    static func wrappingCryptoError<Return, E:Error>(_ block: () throws(E) -> Return) throws(TLSError) -> Return {
        do {
            return try block()
        } catch {
            // Ideally CryptoKitMetaError will be Equatable so it can be embedded inside of the TLSError
            throw TLSError.wrappedCryptoError
        }
    }
}
