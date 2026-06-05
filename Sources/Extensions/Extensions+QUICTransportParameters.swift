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

extension Extension {
    // For consistency with other implementations, we don't introspect this field at all.
    struct QUICTransportParameters {
        var opaqueOffer: ByteBuffer
    }
}

extension Extension.QUICTransportParameters: Hashable { }

extension InputBuffer {
    mutating func readQUICTransportParameters(messageType: HandshakeType) throws(TLSError) -> Extension.QUICTransportParameters {
        switch messageType {
        case .clientHello, .encryptedExtensions:
            // Convert remaining bytes to ByteBuffer
            return Extension.QUICTransportParameters(opaqueOffer: ByteBuffer(copying: self.readAll()))
        default:
            throw TLSError.invalidMessageForExtension(messageType: messageType, extensionType: .quicTransportParameters)
        }
    }
}

extension ByteBuffer {
    @discardableResult
    mutating func writeQUICTransportParameters(_ transportParameters: Extension.QUICTransportParameters) -> Int {
        return self.writeImmutableBuffer(transportParameters.opaqueOffer)
    }
}
