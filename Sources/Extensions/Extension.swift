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

enum Extension {
    case serverName(ServerName)
    case supportedGroups(SupportedGroups)
    case supportedVersions(SupportedVersions)
    case alpn(ApplicationLayerProtocolNegotiation)
    case keyShare(KeyShare)
    case earlyData(EarlyData)
    case signatureAlgorithms(SignatureAlgorithms)
    case clientCertificateType(CertificateTypeExt)
    case serverCertificateType(CertificateTypeExt)
    case quicTransportParameters(QUICTransportParameters)
    case preSharedKeyKexModes(PreSharedKeyKexModes)
    case preSharedKey(PreSharedKey)
    case ticketRequest(TicketRequest)
    case unknownExtension(ExtensionType, ByteBuffer)

    var type: ExtensionType {
        switch self {
        case .serverName:
            return .serverName
        case .supportedGroups:
            return .supportedGroups
        case .supportedVersions:
            return .supportedVersions
        case .alpn:
            return .applicationLayerProtocolNegotiation
        case .keyShare:
            return .keyShare
        case .earlyData:
            return .earlyData
        case .signatureAlgorithms:
            return .signatureAlgorithms
        case .clientCertificateType:
            return .clientCertificateType
        case .serverCertificateType:
            return .serverCertificateType
        case .quicTransportParameters:
            return .quicTransportParameters
        case .preSharedKeyKexModes:
            return .preSharedKeyKexModes
        case .preSharedKey:
            return .preSharedKey
        case .ticketRequest:
            return .ticketRequest
        case .unknownExtension(let type, _):
            return type
        }
    }
}

extension Extension: Hashable { }

extension InputBuffer {
    mutating func readExtension(messageType: HandshakeType, helloRetryRequest: Bool) throws(TLSError) -> Extension? {
        guard let type = self.readExtensionType() else {
            return nil
        }

        return try self.readVariableLengthVector(lengthFieldType: UInt16.self) { extensionData throws(TLSError) in
            switch type {
            case .serverName:
                return try .serverName(extensionData.readServerName(messageType: messageType))
            case .supportedGroups:
                return try .supportedGroups(extensionData.readSupportedGroups(messageType: messageType))
            case .supportedVersions:
                return try .supportedVersions(extensionData.readSupportedVersions(messageType: messageType))
            case .applicationLayerProtocolNegotiation:
                return try .alpn(extensionData.readALPN(messageType: messageType))
            case .earlyData:
                return try .earlyData(extensionData.readEarlyDataExtension(messageType: messageType))
            case .signatureAlgorithms:
                return try .signatureAlgorithms(extensionData.readSignatureAlgorithms(messageType: messageType))
            case .clientCertificateType:
                return try .clientCertificateType(extensionData.readCertificateType(messageType: messageType))
            case .serverCertificateType:
                return try .serverCertificateType(extensionData.readCertificateType(messageType: messageType))
            case .keyShare:
                return try .keyShare(extensionData.readKeyShare(messageType: messageType, helloRetryRequest: helloRetryRequest))
            case .quicTransportParameters:
                return try .quicTransportParameters(extensionData.readQUICTransportParameters(messageType: messageType))
            case .preSharedKeyKexModes:
                return try .preSharedKeyKexModes(extensionData.readPreSharedKeyKexModes(messageType: messageType))
            case .preSharedKey:
                return try .preSharedKey(extensionData.readPreSharedKey(messageType: messageType, helloRetryRequest: helloRetryRequest))
            case .ticketRequest:
                return try .ticketRequest(extensionData.readTicketRequestExtension(messageType: messageType))
            default:
                // We ignore unknown extensions - consume all remaining bytes
                return .unknownExtension(type, ByteBuffer(copying: extensionData.readAll()))
            }
        }
    }

    mutating func readExtensions(messageType: HandshakeType, helloRetryRequest: Bool) throws(TLSError) -> [Extension]? {
        try self.readVariableLengthVector(lengthFieldType: UInt16.self) { buffer throws(TLSError) in
            var extensions = Array<Extension>()

            while let ext = try buffer.readExtension(messageType: messageType, helloRetryRequest: helloRetryRequest) {
                extensions.append(ext)
            }

            return extensions
        }
    }
}

extension ByteBuffer {
    @discardableResult
    mutating func writeExtension(_ ext: Extension) -> Int {
        var written = self.writeExtensionType(ext.type)
        written += self.writeVariableLengthVector(lengthFieldType: UInt16.self) { buffer in
            switch ext {
            case .serverName(let serverName):
                return buffer.writeServerName(serverName)
            case .supportedGroups(let supportedGroups):
                return buffer.writeSupportedGroups(supportedGroups)
            case .supportedVersions(let supportedVersions):
                return buffer.writeSupportedVersions(supportedVersions)
            case .alpn(let alpn):
                return buffer.writeALPN(alpn)
            case .keyShare(let share):
                return buffer.writeKeyShare(share)
            case .earlyData(let earlyData):
                return buffer.writeEarlyDataExtension(earlyData)
            case .signatureAlgorithms(let algorithms):
                return buffer.writeSignatureAlgorithms(algorithms)
            case .clientCertificateType(let certificateType):
                return buffer.writeCertificateType(certificateType)
            case .serverCertificateType(let certificateType):
                return buffer.writeCertificateType(certificateType)
            case .quicTransportParameters(let quicTransportParameters):
                return buffer.writeQUICTransportParameters(quicTransportParameters)
            case .preSharedKeyKexModes(let kexModes):
                return buffer.writePreSharedKeyKexModes(kexModes)
            case .preSharedKey(let psk):
                return buffer.writePreSharedKey(psk)
            case .ticketRequest(let ticketRequest):
                return buffer.writeTicketRequestExtension(ticketRequest)
            case .unknownExtension(_, let extensionData):
                return buffer.writeImmutableBuffer(extensionData)
            }
        }
        return written
    }
}
