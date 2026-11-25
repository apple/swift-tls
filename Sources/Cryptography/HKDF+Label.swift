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

// Availability due to `Swift`'s `OutputRawSpan`, which `HKDFLabel` uses
@available(SwiftTLS 0.1.0, *)
extension HKDF {
    static func expandLabel<SecretBytes: ContiguousBytes, ContextBytes: ContiguousBytes>(secret: SecretBytes, label: String, context: ContextBytes, length: Int) -> SymmetricKey {
        guard let hkdfLabel = HKDFLabel(label: label, outputLength: length) else {
            preconditionFailure("HkdfLabel for label \"\(label)\" and output length \(length) exceeds its field limits")
        }

        return hkdfLabel.withSerializedInfo(using: context) { info in
            info.withUnsafeBytes { infoBytes in
                Self.expand(pseudoRandomKey: secret, info: infoBytes, outputByteCount: length)
            }
        }
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
              HKDFLabel(label: label, outputLength: length) != nil else {
            return nil
        }

        var hasher = H()
        context.withUnsafeBytes { hasher.update(bufferPointer: $0) }
        let contextHash = hasher.finalize()

        let derivedSecret = Self.deriveSecret(secret: secret, label: label, transcriptHash: H.zeroHash)
        return Self.expandLabel(secret: derivedSecret, label: "exporter", context: contextHash, length: length)
    }

}

// Availability due to `CryptoKit`'s `HKDF`
@available(macOS 11, iOS 14, tvOS 14, watchOS 7, *)
extension HKDF {
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

/// The `HkdfLabel` structure of RFC 8446 Section 7.1, which is the `info` input of `HKDF-Expand-Label`:
///
///     struct {
///       uint16 length = Length;
///       opaque label<7..255> = "tls13 " + Label;
///       opaque context<0..255> = Context;
///     } HkdfLabel
// Availability due to `Swift`'s `OutputRawSpan`
@available(SwiftTLS 0.1.0, *)
struct HKDFLabel {
    private static let prefix = "tls13 "

    private let label: String
    private let prefixedLabelByteCount: UInt8
    private let outputLength: UInt16

    /// Returns `nil` if the prefixed `label` is longer than 255 bytes or `outputLength` does not fit in a `UInt16`.
    init?(label: String, outputLength: Int) {
        guard let prefixedLabelByteCount = UInt8(exactly: Self.prefix.utf8.count + label.utf8.count),
              let outputLength = UInt16(exactly: outputLength) else {
            return nil
        }

        self.label = label
        self.prefixedLabelByteCount = prefixedLabelByteCount
        self.outputLength = outputLength
    }

    /// Passes the serialized `HkdfLabel` bytes for this label and `context` to `body`. The bytes are only
    /// valid for the duration of that call.
    ///
    /// Traps if `context` is longer than 255 bytes.
    func withSerializedInfo<Context: ContiguousBytes, Result>(
        using context: Context,
        _ body: (RawSpan) -> Result
    ) -> Result {
        return context.withUnsafeBytes { contextBytes in
            let contextByteCount = UInt8(contextBytes.count)
            // 2 bytes of length, a 1-byte label length, the label, a 1-byte context length, and the context.
            let serializedByteCount = 2 &+ 1 &+ Int(self.prefixedLabelByteCount) &+ 1 &+ Int(contextByteCount)

            return withTemporaryAllocationOfBytes(
                capacity: serializedByteCount,
                fill: { outputSpan in
                    outputSpan.append(UInt8(truncatingIfNeeded: self.outputLength >> 8))
                    outputSpan.append(UInt8(truncatingIfNeeded: self.outputLength))

                    outputSpan.append(self.prefixedLabelByteCount)
                    outputSpan.append(contentsOf: Self.prefix.utf8.span.bytes)
                    outputSpan.append(contentsOf: self.label.utf8.span.bytes)

                    outputSpan.append(contextByteCount)
                    outputSpan.append(contentsOf: contextBytes.bytes)
                },
                use: body
            )
        }
    }
}
