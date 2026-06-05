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

/// This type provides an opaque wrapper around the various public key types.
/// Roughly based on Swift Certificate `PublicKey`
struct PublicKey {
    
    var backing: BackingPublicKey

    internal init(backing: BackingPublicKey) {
        self.backing = backing
    }

    /// Construct a public key wrapping a P256 public key.
    /// - Parameter p256: The P256 public key to wrap.
    init(_ p256: P256.Signing.PublicKey) {
        self.backing = .p256(p256)
    }
}

extension PublicKey {
    var derRepresentation: Data {
        self.backing.derRepresentation()
    }
}

extension PublicKey: Hashable {}

extension PublicKey: Sendable {}

extension PublicKey: CustomStringConvertible {
    var description: String {
        switch self.backing {
        case .p256:
            return "P256.PublicKey"
        }
    }
}

extension PublicKey {
    enum BackingPublicKey: Hashable, Sendable {
        case p256(P256.Signing.PublicKey)

        static func == (lhs: BackingPublicKey, rhs: BackingPublicKey) -> Bool {
            switch (lhs, rhs) {
            case (.p256(let l), .p256(let r)):
                return l.rawRepresentation == r.rawRepresentation
            }
        }

        func hash(into hasher: inout Hasher) {
            switch self {
            case .p256(let digest):
                hasher.combine(0)
                hasher.combine(digest.rawRepresentation)
            }
        }

        func derRepresentation() -> Data {
            switch self {
            case .p256(let key):
                return key.derRepresentation
            }
        }
    }
}
