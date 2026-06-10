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

struct NamedGroup: RawRepresentable, Sendable {
    var rawValue: UInt16

    init(rawValue: UInt16) {
        self.rawValue = rawValue
    }
}

extension NamedGroup {
    static let secp256 = NamedGroup(rawValue: 0x0017)
    static let secp384 = NamedGroup(rawValue: 0x0018)
    static let x25519 = NamedGroup(rawValue: 0x001D)
    static let x25519MLKEM768 = NamedGroup(rawValue: 0x11ec)
}

extension NamedGroup: Hashable { }

extension NamedGroup: CustomStringConvertible {
    var description: String {
        switch self {
        case .secp256:
            return ".secp256"
        case .secp384:
            return ".secp384"
        case .x25519:
            return ".x25519"
        case .x25519MLKEM768:
            return ".x25519MLKEM768"
        default:
            return "NamedGroup(rawValue: \(self.rawValue))"
        }
    }

    var metadataDescription: String {
        switch self {
        case .secp256:
            return "P-256"
        case .secp384:
            return "P-384"
        case .x25519:
            return "X25519"
        case .x25519MLKEM768:
            return "X25519MLKEM768"
        default:
            return "NamedGroup(rawValue: \(self.rawValue))"
        }
    }
}



@available(SwiftTLS 0.1.0, *)
extension InputBuffer {
    mutating func readNamedGroup() -> NamedGroup? {
        return self.readInteger().map { NamedGroup(rawValue: $0) }
    }
}

@available(SwiftTLS 0.1.0, *)
extension ByteBuffer {
    @discardableResult
    mutating func writeNamedGroup(_ namedGroup: NamedGroup) -> Int {
        return self.writeInteger(namedGroup.rawValue)
    }
}
