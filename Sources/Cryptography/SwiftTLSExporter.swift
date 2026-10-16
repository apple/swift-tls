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

/// Derives exporter key material for a completed TLS connection, per RFC 8446 section 7.5.
///
/// A snapshot, not a live handle: it captures the exporter master secret at handshake completion,
/// so it stays valid — and usable from any thread — after the connection closes. The master secret
/// itself never leaves this type, since it can generate every exporter key for the connection.
@_spi(SwiftTLSProtocol)
// Availability due to `CryptoKit`'s `HKDF`
@available(SwiftTLS 0.1.0, *)
public final class SwiftTLSExporter: Sendable {
    /// Closes over the negotiated hash function, so callers do not have to name it.
    private let derive: @Sendable (String, [UInt8], Int) -> SymmetricKey?

    init<HF: HashFunction>(exporterMasterSecret: SymmetricKey, hashFunction: HF.Type) {
        self.derive = { label, context, length in
            HKDF<HF>.tlsExporter(secret: exporterMasterSecret, label: label, context: context, length: length)
        }
    }

    #if canImport(CryptoKit)
    public func exportKeyingMaterial(label: String, context: [UInt8], length: Int) -> CryptoKit.SymmetricKey? {
        return self.derive(label, context, length)
    }
    #elseif canImport(Crypto)
    public func exportKeyingMaterial(label: String, context: [UInt8], length: Int) -> Crypto.SymmetricKey? {
        return self.derive(label, context, length)
    }
    #endif

    public var exportKeyingMaterialFunction: @Sendable (String, [UInt8], Int) -> [UInt8]? {
        { label, context, length in
            self.derive(label, context, length)?.withUnsafeBytes { [UInt8]($0) }
        }
    }
}
