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

@available(SwiftTLS 0.1.0, *)
struct PartialHandshakeResult {
    var handshakeBytesToSend: ByteBuffer?

    var newWriteEncryptionLevel: EncryptionLevel?

    var newReadEncryptionLevel: EncryptionLevel?

    var sessionTicket: Data?
}

/// Information about a new encryption level.
///
/// This is provided whenever the encryption level changes. It represents the new encryption level, as well
/// as the data associated with that encryption level.
///
/// Each new encryption level brings new secrets.
///
/// Note that this excludes the "initial" level. That level is implicit: until you observe one
/// of these values, the connection remains at the `initial` level.
@available(macOS 10.15, iOS 13, tvOS 13, watchOS 6, *)
enum EncryptionLevel {
    case earlyData(secret: SymmetricKey)
    case handshake(secret: SymmetricKey)
    case application(secret: SymmetricKey)

    var description: String {
        switch self {
        case .earlyData(_): return "earlyData"
        case .handshake(_): return "handshake"
        case .application(_): return "application"
        }
    }
}
