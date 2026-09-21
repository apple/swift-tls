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

// Wrappers over older Crypto functions when span-based APIs are not available.
// This path exists for compatibility, but is significantly less efficient.

#if !DISABLE_SHIM_CRYPTO_SPAN_APIS
#if canImport(Foundation) && !SWIFTTLS_EMBEDDED
import Foundation
#elseif canImport(SwiftSystem)
import SwiftSystem
#endif

#if !canImport(CryptoKit) && canImport(Crypto)
@preconcurrency import Crypto
#else
import CryptoKit
#endif

// Availability due to `RawSpan`
@available(SwiftTLS 0.1.0, *)
extension AES.GCM.Nonce {
    init(copying bytes: RawSpan) throws(CryptoKitMetaError) {
        self = try bytes.withUnsafeBytes { nonceBuffer throws(CryptoKitMetaError) in
            try AES.GCM.Nonce(data: nonceBuffer)
        }
    }
}

// Availability due to `RawSpan`
@available(SwiftTLS 0.1.0, *)
extension AES.GCM {
    static func seal(
        inPlace message: inout MutableRawSpan,
        using key: SymmetricKey,
        nonce: AES.GCM.Nonce,
        authenticating authenticatedData: RawSpan? = nil,
        tag: inout OutputRawSpan
    ) throws(CryptoKitMetaError) {
        let sealedBox = try message.withUnsafeBytes { messageBufferIn throws(CryptoKitMetaError) in
            let messageBuffer: any DataProtocol
            if messageBufferIn.count > 0 {
                messageBuffer = messageBufferIn
            } else {
                messageBuffer = [UInt8]()
            }
            if let authenticatedData {
                return try authenticatedData.withUnsafeBytes { authenticatedDataBuffer throws(CryptoKitMetaError) in
                    try seal(messageBuffer, using: key, nonce: nonce, authenticating: authenticatedDataBuffer)
                }
            } else {
                return try seal(messageBuffer, using: key, nonce: nonce)
            }
        }

        message.withUnsafeMutableBytes { messageBytes in
            if messageBytes.isEmpty {
                return
            }
            sealedBox.ciphertext.copyBytes(to: messageBytes)
        }

        tag.withUnsafeMutableBytes { tagBuffer, initializedCount in
            sealedBox.tag.copyBytes(to: tagBuffer)
            initializedCount += sealedBox.tag.count
        }
    }

    static func open(
        inPlace message: inout MutableRawSpan,
        using key: SymmetricKey,
        nonce: AES.GCM.Nonce,
        authenticating authenticatedData: RawSpan? = nil,
        tag: RawSpan
    ) throws(CryptoKitMetaError) {
        let sealedBox = try message.withUnsafeBytes { messageBuffer in
            try tag.withUnsafeBytes { tagBuffer throws(CryptoKitMetaError) in
                try AES.GCM.SealedBox(nonce: nonce, ciphertext: messageBuffer, tag: tagBuffer)
            }
        }

        let plaintext: Data
        if let authenticatedData {
            plaintext = try authenticatedData.withUnsafeBytes { authenticatedDataBuffer throws(CryptoKitMetaError) in
                try open(sealedBox, using: key, authenticating: authenticatedDataBuffer)
            }
        } else {
            plaintext = try open(sealedBox, using: key)
        }

        message.withUnsafeMutableBytes { messageBuffer in
            if messageBuffer.isEmpty {
                return
            }
            plaintext.copyBytes(to: messageBuffer)
        }
    }
}
#endif
