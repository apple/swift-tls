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

#if canImport(CryptoKit)
import CryptoKit
#elseif canImport(Crypto)
@preconcurrency import Crypto
#endif
#if canImport(Foundation) && !SWIFTTLS_EMBEDDED
import Foundation
#elseif canImport(SwiftSystem)
import SwiftSystem
#endif

#if canImport(Darwin) || SWIFTTLS_EXCLAVEKIT
import os.log
// Availability due to `os.log`'s `Logger`
@available(macOS 11, iOS 14, tvOS 14, watchOS 7, *)
private let logger = Logger(subsystem: "com.apple.security.swifttls", category: "TLSRecordHandler")
#elseif SWIFTTLS_EMBEDDED || SWIFTTLS_DRIVERKIT
private let logger = Logger(label: "com.apple.security.swifttls.RecordLayer")
#elseif canImport(Logging)
// Linux Logging
import Logging
private let logger = Logger(label: "com.apple.security.swifttls.RecordLayer")
#endif


// Availability due to `RawSpan`
@available(SwiftTLS 0.1.0, *)
struct TLSRecordHandler: ~Copyable {
    var stateMachine: TLSHandshakeStateMachine
    private var recordParser: TLSRecordParser
    private var recordProtector: TLSRecordProtector

    private var currentWriteEncryptionLevel: EncryptionLevel?
    private var currentReadEncryptionLevel: EncryptionLevel?
    // Set to true after first encrypted message received.
    // Before this occurs it is possible to get a plain text alert.
    // (e.g. Server could get a plain text alert from client
    // if the client had a problem with the Server Hello)
    private var receivedPeerEncryptedMessage: Bool = false

    private var pendingApplicationData: ByteBuffer // application data to send after handshake complete
    var pendingApplicationDataBytes: Int { self.pendingApplicationData.readableBytes }

    var receivedApplicationData: ByteBuffer // decrypted application data: pass to input handler (up the stack)

    var outgoingBytes: ByteBuffer // data to pass to output handler (down the stack to transport proto e.g. tcp)
    var outgoingBytesCount: Int { self.outgoingBytes.readableBytes }

    var bytesToReadCount: UInt32 { UInt32(self.recordParser.numberOfBytesToReadNext) }

    var writeEncryptionLevelIsEarlyData: Bool {
        if case .earlyData(_) = self.currentWriteEncryptionLevel {
            return true
        }
        return false
    }

    var getNegotiatedCiphersuite: Int {
        var res: UInt16 = 0
        switch self.stateMachine {
        case .client(let clientHandshakeStateMachine):
            res = clientHandshakeStateMachine.negotiatedCiphersuite ?? 0
#if !SWIFTTLS_CLIENT_ONLY
        case .server(let serverHandshakeStateMachine):
            res = serverHandshakeStateMachine.negotiatedCiphersuite ?? 0
#endif
        }
        return Int(res)
    }

    var getNegotiatedEPSK: Bool {
        switch self.stateMachine {
        case .client(let handshakeStateMachine):
            return handshakeStateMachine.negotiatedEPSK
#if !SWIFTTLS_CLIENT_ONLY
        case .server(let serverHandshakeStateMachine):
            return serverHandshakeStateMachine.negotiatedEPSK
#endif
        }
    }

    var getEPSKOffered: Bool {
        switch self.stateMachine {
        case .client(let handshakeStateMachine):
            return handshakeStateMachine.epskOffered
#if !SWIFTTLS_CLIENT_ONLY
        case .server(let serverHandshakeStateMachine):
            return serverHandshakeStateMachine.epskOffered
#endif
        }
    }

    var getNegotiatedGroup: String {
        var res:String? = nil
        switch self.stateMachine {
        case .client(let clientHandshakeStateMachine):
            res = clientHandshakeStateMachine.negotiatedGroup
#if !SWIFTTLS_CLIENT_ONLY
        case .server(let serverHandshakeStateMachine):
            res = serverHandshakeStateMachine.negotiatedGroup
#endif
        }
        return res ?? ""
    }

    mutating func writeOutput() -> Data? {
        if self.outgoingBytesCount == 0 {
            return nil
        }
        let out = self.outgoingBytes.readableBytesView
        self.outgoingBytes = ByteBuffer()
        return out
    }

    mutating func getOutputData(_ numBytes: Int) -> Data? {
        guard self.outgoingBytesCount > 0 else {
            return nil
        }
        if (numBytes >= self.outgoingBytesCount) {
            let out = self.outgoingBytes.readableBytesView
            self.outgoingBytes = ByteBuffer()
            return out
        } else {
            guard let bytes = self.outgoingBytes.readBytes(length: numBytes) else {
                return nil
            }
            return Data(bytes)
        }
    }

    mutating func getApplicationData(_ numBytes: Int) -> Data? {
        guard self.receivedApplicationData.readableBytes > 0 else {
            return nil
        }
        if (numBytes >= self.receivedApplicationData.readableBytes) {
            let data = self.receivedApplicationData.readableBytesView
            self.receivedApplicationData = ByteBuffer()
            return data
        } else {
            guard let bytes = self.receivedApplicationData.readBytes(length: numBytes) else {
                return nil
            }
            return Data(bytes)
        }
    }

    var applicationDataLength: Int { self.receivedApplicationData.readableBytes }

    private var negotiatedCiphersuite: UInt16? {
        switch self.stateMachine {
        case .client(let clientHandshakeStateMachine):
            return clientHandshakeStateMachine.negotiatedCiphersuite
#if !SWIFTTLS_CLIENT_ONLY
        case .server(let serverHandshakeStateMachine):
            return serverHandshakeStateMachine.negotiatedCiphersuite
#endif
        }
    }

    private var maxFragmentLength: UInt16 {
        return maxPlaintextFragmentLength
    }

    var handshakeComplete: Bool {
        switch self.stateMachine {
        case .client(let clientHandshakeStateMachine):
            return clientHandshakeStateMachine.handshakeComplete
#if !SWIFTTLS_CLIENT_ONLY
        case .server(let serverHandshakeStateMachine):
            return serverHandshakeStateMachine.handshakeComplete
#endif
        }
    }

    var handshakeStarted: Bool {
        switch self.stateMachine {
        case .client(let clientHandshakeStateMachine):
            return clientHandshakeStateMachine.handshakeStarted
#if !SWIFTTLS_CLIENT_ONLY
        case .server(let serverHandshakeStateMachine):
            return serverHandshakeStateMachine.handshakeStarted
#endif
        }
    }

    mutating func setDeliverResultCallback(_ handler: (@Sendable (PendingAsyncResult) -> Void)?) {
        switch self.stateMachine {
        case .client(var clientHandshakeStateMachine):
            clientHandshakeStateMachine.deliverResultCallback = handler
            self.stateMachine = .client(clientHandshakeStateMachine)
#if !SWIFTTLS_CLIENT_ONLY
        case .server(var serverHandshakeStateMachine):
            serverHandshakeStateMachine.deliverResultCallback = handler
            self.stateMachine = .server(serverHandshakeStateMachine)
#endif
        }
    }

    mutating func applyAsyncResult(_ result: PendingAsyncResult) {
        switch self.stateMachine {
        case .client(var clientHandshakeStateMachine):
            clientHandshakeStateMachine.applyAsyncResult(result)
            self.stateMachine = .client(clientHandshakeStateMachine)
#if !SWIFTTLS_CLIENT_ONLY
        case .server(var serverHandshakeStateMachine):
            serverHandshakeStateMachine.applyAsyncResult(result)
            self.stateMachine = .server(serverHandshakeStateMachine)
#endif
        }
    }

    /// RFC 9846 §5.1. True when a handshake message is only partially
    /// reassembled, i.e. we're mid-way through consuming a message
    /// split across records.
    private var hasBufferedHandshakeBytes: Bool {
        switch self.stateMachine {
        case .client(let clientHandshakeStateMachine):
            return clientHandshakeStateMachine.hasBufferedHandshakeBytes
#if !SWIFTTLS_CLIENT_ONLY
        case .server(let serverHandshakeStateMachine):
            return serverHandshakeStateMachine.hasBufferedHandshakeBytes
#endif
        }
    }

    var bufferedNetworkData: Int {
        return self.recordParser.numberOfBytesBuffered
    }

    init(stateMachine: TLSHandshakeStateMachine) {
        self.stateMachine = stateMachine
        self.recordParser = TLSRecordParser()
        self.recordProtector = TLSRecordProtector()
        self.receivedApplicationData = ByteBuffer()
        self.pendingApplicationData = ByteBuffer()
        self.outgoingBytes = ByteBuffer()
    }

    mutating func startHandshake() throws(TLSError) {
        guard case .client(var clientHandshakeStateMachine) = stateMachine else {
            logger.error("startHandshake called on server")
            throw TLSError.startHandshakeCalledOnServer
        }
        let result = try clientHandshakeStateMachine.startHandshake()
        try self.processPartialHandshakeResult(partialHandshakeResult: result)
        self.stateMachine = .client(clientHandshakeStateMachine)
    }

    private mutating func processHandshake(incomingBytes: inout InputBuffer) throws(TLSError) -> PartialHandshakeResult? {
        if self.alertWrote != nil || self.alertRead != nil {
            return nil
        }
        var result: PartialHandshakeResult? = nil
        switch self.stateMachine {
        case .client(var clientHandshakeStateMachine):
            do {
                result = try clientHandshakeStateMachine
                    .processHandshake(incomingBytes: &incomingBytes)
            } catch {
                self.stateMachine = .client(clientHandshakeStateMachine)
                throw(error)
            }
            self.stateMachine = .client(clientHandshakeStateMachine)
#if !SWIFTTLS_CLIENT_ONLY
        case .server(var serverHandshakeStateMachine):
            do {
                result = try serverHandshakeStateMachine
                    .processHandshake(incomingBytes: &incomingBytes)
            } catch {
                self.stateMachine = .server(serverHandshakeStateMachine)
                throw(error)
            }
            self.stateMachine = .server(serverHandshakeStateMachine)
#endif
        }
        return result
    }

    private mutating func addIncomingHandshakeBytes(_ bytes: RawSpan) {
        switch self.stateMachine {
        case .client(var clientHandshakeStateMachine):
            clientHandshakeStateMachine.receivedNetworkData(bytes)
            self.stateMachine = .client(clientHandshakeStateMachine)
#if !SWIFTTLS_CLIENT_ONLY
        case .server(var serverHandshakeStateMachine):
            serverHandshakeStateMachine.receivedNetworkData(bytes)
            self.stateMachine = .server(serverHandshakeStateMachine)
#endif
        }
    }

    private mutating func addIncomingHandshakeBytes(_ bytes: inout ByteBuffer) {
        addIncomingHandshakeBytes(bytes.readableBytesSpan)
    }

    // PartialHandshakeResult --> split to fragments --> protect with current keys --> update encryption secrets
    mutating func processPartialHandshakeResult(partialHandshakeResult: PartialHandshakeResult) throws(TLSError) {
        // if there are bytes to send
        if var handshakeBytesToSend = partialHandshakeResult.handshakeBytesToSend {
            // currently we put each message in a separate record (or multiple if too large to fit in one)
            while handshakeBytesToSend.readableBytes > 0 {
                let fragmentLength: Int = min(Int(self.maxFragmentLength), handshakeBytesToSend.readableBytes)
                guard let fragmentBuffer = handshakeBytesToSend.readSlice(length: fragmentLength)?.readableBytesView else {
                    throw TLSError.internalError(reason: "internal error reading fragment. readable bytes > 0 but bytes not read")
                }
                // if needed protect + turn into TLSCiphertext
                if self.currentWriteEncryptionLevel == nil || self.writeEncryptionLevelIsEarlyData {
                    // else turn into TLSPlainText
                    let record = TLSPlaintext(contentType: .handshake, fragment: [UInt8](fragmentBuffer))
                    self.outgoingBytes.writeRecord(record)
                } else {
                    let record = try fragmentBuffer.withBytes { (fragmentBufferBytes) throws(TLSError) in
                        try self.recordProtector.protect(
                            plaintext: fragmentBufferBytes,
                            actualContentType: .handshake
                        )
                    }
                    self.outgoingBytes.writeRecord(record)
                }
            }
        }
        try updateEncryptionSecrets(partialHandshakeResult)
    }

    private func calcNewKeyAndIV(newEncryptionLevel: EncryptionLevel) -> (SymmetricKey, [UInt8]){
        var secretKey: SymmetricKey
        switch newEncryptionLevel {
        case .earlyData(let secret),
            .handshake(let secret),
            .application(let secret):
            secretKey = secret
        }

        let newKey = HKDF<SHA384>.expandLabel(secret: secretKey,
                                 label: "key",
                                 context: [],
                                 length: TLSRecordProtector.writeAES256KeyLengthBytes)

        let newIV = HKDF<SHA384>.expandLabel(secret: secretKey,
                                 label: "iv",
                                 context: [],
                                 length: TLSRecordProtector.IVlengthBytes)
        return (newKey, [UInt8](newIV.withUnsafeBytes { Data($0) }))
    }

    private mutating func updateEncryptionSecrets(_ partialHandshakeResult: PartialHandshakeResult) throws(TLSError) {
        if let ciphersuite = self.negotiatedCiphersuite {
            self.recordProtector.setCiphersuite(ciphersuite: ciphersuite)
        }
        if let newReadEncryptionLevel = partialHandshakeResult.newReadEncryptionLevel {
            // RFC 9846 §5.1: "Implementations MUST verify that all messages
            // immediately preceding a key change align with a record boundary;
            // if not, then they MUST terminate the connection with an
            // 'unexpected_message' alert."
            guard !self.hasBufferedHandshakeBytes else {
                logger.error("key change requested while a handshake message is still being reassembled")
                throw TLSError.handshakeUnexpectedMessage
            }
            self.currentReadEncryptionLevel = newReadEncryptionLevel
            // the new encryption level contains the new secret
            // use that secret to derive the new key + iv

            let (newReadKey, newReadIV) = calcNewKeyAndIV(newEncryptionLevel: newReadEncryptionLevel)
            try self.recordProtector.updateReadKeyAndIV(newReadKey, newReadIV)
        }
        if let newWriteEncryptionLevel = partialHandshakeResult.newWriteEncryptionLevel {
            self.currentWriteEncryptionLevel = newWriteEncryptionLevel
            // the new encryption level contains the new secret
            // use that secret to derive the new key + iv

            // do not update for early data
            // as we do not support it over tcp at present.
            if case .earlyData(_) = newWriteEncryptionLevel {
                return
            }
            let (newWriteKey, newWriteIV) = calcNewKeyAndIV(newEncryptionLevel: newWriteEncryptionLevel)
            try self.recordProtector.updateWriteKeyAndIV(newWriteKey, newWriteIV)
        }
    }

    @_spi(SwiftTLSTesting)
    public mutating func setWriteSequenceNumberForTesting(_ value: UInt64) {
        self.recordProtector.setSequenceNumbersForTesting(write: value)
    }

    @_spi(SwiftTLSTesting)
    public mutating func setReadSequenceNumberForTesting(_ value: UInt64) {
        self.recordProtector.setSequenceNumbersForTesting(read: value)
    }

    @_spi(SwiftTLSTesting)
    public mutating func setReadKeyAndIVForTesting(_ key: SymmetricKey, _ iv: [UInt8], ciphersuite: UInt16) throws {
        self.recordProtector.setCiphersuite(ciphersuite: ciphersuite)
        try self.recordProtector.updateReadKeyAndIV(key, iv)
        self.currentReadEncryptionLevel = .application(secret: key)
    }

    mutating func protectForTesting(plaintext: [UInt8], actualContentType: ContentType) throws(TLSError) -> TLSCiphertext {
        try self.recordProtector.protect(plaintext: plaintext.span.bytes, actualContentType: actualContentType)
    }

    private mutating func parseOneRecord() throws(TLSError) -> TLSRecord? {
        // RFC 9846: a change_cipher_spec is only permitted after the first ClientHello
        // and before the peer's Finished. handshakeComplete flips after the peer's
        // Finished has been processed, so this is valid for every record parsed between.
        let changeCipherSpecPermitted = self.handshakeStarted && !self.handshakeComplete
        if self.currentReadEncryptionLevel != nil {
            do {
                guard let ciphertext =  try self.recordParser.parseCiphertextRecord(changeCipherSpecPermitted: changeCipherSpecPermitted) else {
                    return nil
                }
                self.receivedPeerEncryptedMessage = true
                return .ciphertext(ciphertext)
            } catch {
                if !self.receivedPeerEncryptedMessage {
                    #if SWIFTTLS_EXCLAVEKIT || SWIFTTLS_EXCLAVECORE
                    logger.debug("error parsing first potential ciphertext record: \(String(describing: error)). checking for plaintext alert.")
                    #else
                    logger.debug("error parsing first potential ciphertext record: \(error). checking for plaintext alert.")
                    #endif
                    // check for plaintext alert
                    guard let plaintext = try self.recordParser.parsePlaintextRecord(changeCipherSpecPermitted: changeCipherSpecPermitted) else {
                        return nil
                    }
                    if plaintext.contentType == .alert {
                        logger.debug("Received plaintext alert record")
                        return .plaintext(plaintext)
                    }
                }
                throw error
            }
        } else {
            guard let plaintext = try self.recordParser.parsePlaintextRecord(changeCipherSpecPermitted: changeCipherSpecPermitted) else {
                return nil
            }
            return .plaintext(plaintext)
        }
    }

    private mutating func processHandshakeInput(_ input: RawSpan) throws(TLSError) {
        var incomingBytes = InputBuffer(storage: input)

        // When we're done, save any unparsed bytes.
        defer {
            self.addIncomingHandshakeBytes(incomingBytes.readAll())
        }

        while let partialHandshakeResult = try self.processHandshake(incomingBytes: &incomingBytes) {
            try self.processPartialHandshakeResult(partialHandshakeResult: partialHandshakeResult)
        }

        if self.handshakeComplete {
            try sendApplicationData()
        }
    }

    mutating func continueHandshake() throws(TLSError) {
        try self.processHandshakeInput(RawSpan())
    }

    private mutating func sendApplicationData() throws(TLSError) {
        if self.alertWrote != nil || self.closureAlertWritten {
            return
        }
        // split message into fragments
        while pendingApplicationData.readableBytes > 0 {
            let fragmentLength: Int = min(Int(self.maxFragmentLength), pendingApplicationData.readableBytes)
            guard let fragmentBuffer = pendingApplicationData.readSlice(length: fragmentLength)?.readableBytesView else {
                throw TLSError.internalError(reason: "internal error reading fragment. readable bytes > 0 but bytes not read")
            }
            let ciphertext = try fragmentBuffer.withBytes { (fragmentBufferBytes) throws(TLSError) in
                try self.recordProtector.protect(
                    plaintext: fragmentBufferBytes,
                    actualContentType: .applicationData
                )
            }
            self.outgoingBytes.writeRecord(ciphertext)
        }
        // hard reset after draining buffer
        pendingApplicationData = ByteBuffer()
    }

    // Converts raw application data into protected records and writes them to outgoingBytes if HS complete.
    // If HS not yet complete they are buffered.
    mutating func addApplicationData(_ rawApplicationData: inout ByteBuffer) throws(TLSError) {
        pendingApplicationData.writeBuffer(&rawApplicationData)
        guard self.handshakeComplete else {
            return
        }
        try sendApplicationData()
    }

    var alertRead: Alert? = nil
    var alertWrote: Alert? = nil
    var closureAlertWritten: Bool = false
    var closureAlertRead: Bool = false
    var tlsError: TLSError? = nil

    var alertSentOrReceived: Bool { self.alertRead != nil || self.alertWrote != nil }
    var closureAlertReceived: Bool { self.closureAlertRead }

    mutating func sendCloseNotify() {
        do {
            try self.sendAlert(.closeNotify)
        } catch {
            #if SWIFTTLS_EXCLAVEKIT || SWIFTTLS_EXCLAVECORE
            logger.error("error sending close notify \(String(describing: error))")
            #else
            logger.error("error sending close notify \(error)")
            #endif
        }
    }

    private mutating func sendAlert(_ alert: Alert) throws(TLSError) {
        if alertWrote != nil || self.closureAlertWritten {
            return // don't send another
        }
        if alert == .closeNotify {
            self.closureAlertWritten = true
            logger.info("write alert close notify")
        } else {
            self.alertWrote = alert
            logger.error("write alert \(alert.description)")
        }
        var alertBuf = ByteBuffer()
        alertBuf.writeAlert(alert)
        // send plaintext alert unless we have the handshake or application level secret ready
        if self.currentWriteEncryptionLevel == nil || self.writeEncryptionLevelIsEarlyData {
            let record = TLSPlaintext(contentType: .alert, fragment: [UInt8](alertBuf.readableBytesView))
            self.outgoingBytes.writeRecord(record)
        } else {
            let record = try self.recordProtector.protect(plaintext: alertBuf.readableBytesSpan, actualContentType: .alert)
            self.outgoingBytes.writeRecord(record)
        }
    }

    private mutating func readAlert(_ input: RawSpan) throws(TLSError) {
        var buf = InputBuffer(storage: input)
        guard let alert = buf.readAlert() else {
            logger.error("alert record did not contain a complete alert message")
            throw TLSError.truncatedMessage
        }
        guard buf.byteCount == 0 else {
            logger.error("alert record contained trailing bytes after a complete alert message")
            throw TLSError.excessBytes
        }
        if alert == .closeNotify {
            self.closureAlertRead = true
            logger.info("read alert close notify")
        } else {
            self.alertRead = alert
            logger.error("read alert \(alert.description)")
        }
    }

    // TLSError -> Alert
    private func tlsErrorToAlert(error: TLSError) -> Alert {
        switch error {
        case .truncatedMessage:
            return .decodeError
        case .excessBytes:
            return .decodeError
        case .invalidMessageForExtension(messageType: _, extensionType: _):
            return .decodeError
        case .handshakeError:
            return .handshakeFailure
        case .handshakeUnexpectedRead:
            return .unexpectedMessage
        case .handshakeUnexpectedMessage:
            return .unexpectedMessage
        case .handshakeInvalidMessage:
            return .decodeError
        case .negotiationFailed:
            return .handshakeFailure
        case .invalidSerializedSession:
            return .illegalParameter
        case .invalidSerializedImportedIdentity:
            return .internalError
        case .insufficientBytes:
            return .internalError
        case .exporterInvalidMessage, .exporterInvalidState:
            // should never happen. exported authenticators only work with QUIC.
            return .internalError
        case .certificateError:
            return .badCertificate
        case .protocolVersion:
            return .protocolVersion
        case .missingExtension:
            return .missingExtension
        case .unsupportedCertificate:
            return .unsupportedCertificate
        case .helloRetryRequestPlaceholder:
            return .handshakeFailure
        case .noApplicationProtocol:
            return .noApplicationProtocol
        case .invalidApplicationProtocol:
            return .decodeError
        case .sessionMissingPeerCertificates:
            return .internalError
        case .sessionMissingNegotiatedCipherSuiteOrGroup:
            return .internalError
        case .missingTargetKDFs:
            return .internalError
        case .importedIdentityTooLong:
            return .internalError
        case .insufficientLengthForEPSK:
            return .internalError
        case .serverMissingSigningKey:
            return .internalError
        case .serverMissingSignature:
            return .internalError
        case .serverMissingCertificate:
            return .internalError
        case .missingPSKKeyExchangeModesExtension:
            return .missingExtension
        case .unknownCiphersuite:
            return .internalError
        case .decodeError:
            return .decodeError
        case .recordOverflow:
            return .recordOverflow
        case .incorrectNonceLength:
            return .decryptError
        case .startHandshakeCalledOnServer:
            return .internalError
        case .decryptError:
            return .decryptError
        case .badRecordMac:
            return .badRecordMac
        case .internalError(reason: _):
            return .internalError
        case .wrappedCryptoError:
            return .internalError
        case .illegalParameter:
            return .illegalParameter
        case .ciphertextRecordTooShort:
            return .decodeError
        case .invalidAlertBeforeHandshakeStart:
            return .internalError
        case .processNetworkDataErrorBeforeHandshakeStart:
            return .internalError
        case .certificateRequired:
            return .certificateRequired
        case .unsupportedExtension:
            return .unsupportedExtension
        case .handshakeFailure:
            return .handshakeFailure
        case .invalidConfigurationOptions:
            return .internalError
        case .refKeySigningFailure:
            return .internalError
        case .keyUsageLimitExceeded:
            return .internalError
        }
    }

    mutating func processNetworkData(networkDataIn: inout ByteBuffer) throws(TLSError) {
        if self.alertSentOrReceived {
            // ignore all data after sending receiving an alert
            self.recordParser.clearBufferedBytes()
            return
        }
        do {
            try networkDataIn.rewindOnNilOrError {(buffer: inout ByteBuffer) throws(TLSError) in
                self.recordParser.appendBytes(&buffer)
                // parse records until we've exhausted the buffer or can't parse a full record
                while self.recordParser.numberOfBytesBuffered > 0 {
                    if let record = try self.parseOneRecord() {
                        switch record {
                        case .ciphertext(let ciphertext):
                            // will only get a ciphertext if readEncryptionLevel > initial
                            // deprotect
                            let deprotectedRecord = try self.recordProtector.deprotect(ciphertext: ciphertext)
                            // RFC 9846 §5.1: Ensure handshake messages are not
                            // interleaved with other record types.
                            guard !self.hasBufferedHandshakeBytes || deprotectedRecord.actualContentType == .handshake else {
                                logger.error("received a non-handshake record while a handshake message is still being reassembled")
                                throw TLSError.handshakeUnexpectedMessage
                            }
                            switch deprotectedRecord.actualContentType {
                            case .applicationData:
                                guard self.handshakeComplete else {
                                    logger.error("got application data before handshake complete")
                                    throw TLSError.handshakeUnexpectedMessage
                                }
                                self.receivedApplicationData.writeBytes(deprotectedRecord.fragment)
                            case .alert:
                                // terminate connection if zero-length content is received (RFC 9846 §5.4)
                                guard !deprotectedRecord.fragment.isEmpty else {
                                    logger.error("received an alert record with zero-length content")
                                    throw TLSError.handshakeUnexpectedMessage
                                }
                                try self.readAlert(deprotectedRecord.fragment.span.bytes)
                            case .handshake:
                                // terminate connection if zero-length content is received (RFC 9846 §5.4)
                                guard !deprotectedRecord.fragment.isEmpty else {
                                    logger.error("received a handshake record with zero-length content")
                                    throw TLSError.handshakeUnexpectedMessage
                                }
                                try self.processHandshakeInput(deprotectedRecord.fragment.span.bytes)
                            case .changeCipherSpec:
                                logger.error("got an encrypted change cipher spec message")
                                throw TLSError.handshakeUnexpectedMessage
                            case .invalid:
                                logger.error("got an encrypted record with an invalid content type")
                                throw TLSError.handshakeUnexpectedMessage
                            default:
                                logger.error("got an encrypted record with an unrecognized content type")
                                throw TLSError.handshakeUnexpectedMessage
                            }
                        case .plaintext(let plaintext):
                            // will only get a plaintext if readEncryptionLevel == initial
                            // pass plaintext to handshaker
                            guard plaintext.contentType == .handshake ||
                                 plaintext.contentType == .alert else {
                                #if SWIFTTLS_EXCLAVECORE
                                logger.error("got a plaintext record with type not handshake or alert: \(String(describing: plaintext.contentType))")
                                #else
                                logger.error("got a plaintext record with type not handshake or alert: \(plaintext.contentType)")
                                #endif
                                throw TLSError.handshakeUnexpectedMessage
                            }
                            // RFC 9846 §5.1: Ensure handshake messages are not
                            // interleaved with other record types.
                            guard !self.hasBufferedHandshakeBytes || plaintext.contentType == .handshake else {
                                logger.error("received a non-handshake plaintext record while a handshake message is still being reassembled")
                                throw TLSError.handshakeUnexpectedMessage
                            }
                            let content = plaintext.content
                            if plaintext.contentType == .alert {
                                guard self.handshakeStarted else {
                                    throw TLSError.invalidAlertBeforeHandshakeStart
                                }
                                try self.readAlert(content.span.bytes)
                            } else {
                                try self.processHandshakeInput(content.span.bytes)
                            }
                        }
                    } else {
                        // break and wait for more data if we can't parse a full record
                        break
                    }
                }
            }
        } catch {
            #if SWIFTTLS_EXCLAVEKIT || SWIFTTLS_EXCLAVECORE
            logger.error("error processing network data: \(String(describing: error))")
            #else
            logger.error("error processing network data: \(error)")
            #endif
            guard self.handshakeStarted else {
                // If we haven't started a handshake we shouldn't send an alert.
                // Client should never get here (we always send client hello
                // before processing network data).
                // Server can get here if client sends something besides a valid
                // client hello as first message.
                let errString = self.stateMachine.isServer ?
                                "First data TLS server received did not match a valid Client Hello" :
                                "TLS client unexpectedly processed network data before sending client hello. This should never happen."
                logger.error("TLS error occurred from processing network data before handshake started: \(errString)")
                self.tlsError = TLSError.processNetworkDataErrorBeforeHandshakeStart
                throw TLSError.processNetworkDataErrorBeforeHandshakeStart
            }
            let alert = tlsErrorToAlert(error: error)
            if alert != .closeNotify {
                self.tlsError = error
            }
            try sendAlert(alert);
            throw error
        }
    }
}
