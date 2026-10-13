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
#if canImport(CryptoKit)
import CryptoKit
#elseif canImport(Crypto)
@preconcurrency import Crypto
#endif

// Availability due to `CryptoKit`'s `HKDF`
@available(macOS 11, iOS 14, tvOS 14, watchOS 7, *)
extension HKDF {
    static func expandLabel<SecretBytes: ContiguousBytes, ContextBytes: ContiguousBytes>(secret: SecretBytes, label: String, context: ContextBytes, length: Int) -> SymmetricKey {
        // We need to build HkdfLabel:
        //
        // struct {
        //   uint16 length = Length;
        //   opaque label<7..255> = "tls13 " + Label;
        //   opaque context<0..255> = Context;
        // } HkdfLabel
        //
        // We reserve the whole space.
        //
        // Consider avoiding this array and synthesizing a weird DataProtocol type instead. It's a lot of work, but may
        // plausibly be slightly faster.
        var serializedLabel = Array<UInt8>()
        serializedLabel.reserveCapacity(2 + 256 + 256)

        let labelCount = Self.labelPrefix.utf8.count + label.utf8.count

        let shortLength = UInt16(length)
        serializedLabel.append(UInt8(truncatingIfNeeded: shortLength >> 8))
        serializedLabel.append(UInt8(truncatingIfNeeded: shortLength))

        serializedLabel.append(UInt8(labelCount))
        serializedLabel.append(contentsOf: Self.labelPrefix.utf8)
        serializedLabel.append(contentsOf: label.utf8)

        context.withUnsafeBytes { contextPointer in
            serializedLabel.append(UInt8(contextPointer.count))
            serializedLabel.append(contentsOf: contextPointer)
        }

        return Self.expand(pseudoRandomKey: secret, info: serializedLabel, outputByteCount: length)
    }

    static func deriveSecret<SecretBytes: ContiguousBytes>(secret: SecretBytes, label: String, transcriptHash: H.Digest) -> SymmetricKey {
        return Self.expandLabel(secret: secret, label: label, context: transcriptHash, length: H.Digest.byteCount)
    }

    /// Derives exporter key material, per RFC 8446 section 7.5. Returns `nil` if `label` or
    /// `length` is out of range.
    static func tlsExporter<SecretBytes: ContiguousBytes, ContextBytes: ContiguousBytes>(
        secret: SecretBytes,
        label: String,
        context: ContextBytes,
        length: Int
    ) -> SymmetricKey? {
        // RFC 5869 caps HKDF-Expand at 255 blocks and HkdfLabel caps the prefixed label at 255
        // bytes; both would trap further down rather than fail gracefully.
        guard length > 0, length <= 255 * H.Digest.byteCount,
              Self.labelPrefix.utf8.count + label.utf8.count <= 255 else {
            return nil
        }

        var hasher = H()
        context.withUnsafeBytes { hasher.update(bufferPointer: $0) }
        let contextHash = hasher.finalize()

        let derivedSecret = Self.deriveSecret(secret: secret, label: label, transcriptHash: H.zeroHash)
        return Self.expandLabel(secret: derivedSecret, label: "exporter", context: contextHash, length: length)
    }

    static var labelPrefix: String {
        return "tls13 "
    }

    static func extract(inputKeyMaterial ikm: SymmetricKey, salt: SymmetricKey) -> HashedAuthenticationCode<H> {
        // This wrapper helps us deal with the fact that these types don't neatly fit into what CryptoKit wants.
        return salt.withUnsafeBytes { saltPointer in
            #if SWIFTTLS_EXCLAVEKIT
            Self.extract(inputKeyMaterial: ikm, salt: Data(saltPointer))
            #else
            Self.extract(inputKeyMaterial: ikm, salt: saltPointer)
            #endif
        }
    }
}
