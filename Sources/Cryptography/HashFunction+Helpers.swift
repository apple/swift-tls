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
@preconcurrency @unsafe import Crypto
#endif

// Availability due to `CryptoKit`'s `HashFunction`
@available(macOS 10.15, iOS 13, tvOS 13, watchOS 6, *)
extension HashFunction {
    static var zeroHash: Self.Digest {
        return Self().finalize()
    }
}

// Availability due to `CryptoKit`'s `HMAC`
@available(macOS 10.15, iOS 13, tvOS 13, watchOS 6, *)
extension HMAC {
    static func authenticationCode<Bytes: ContiguousBytes>(bytes: Bytes, using key: SymmetricKey) -> HashedAuthenticationCode<H> {
        return unsafe bytes.withUnsafeBytes {
            unsafe Self.authenticationCode(for: $0, using: key)
        }
    }
}
