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

struct ContentType: RawRepresentable {
    var rawValue: UInt8

    init(rawValue: UInt8) {
        self.rawValue = rawValue
    }
}

extension ContentType {
    static let invalid = ContentType(rawValue: 0)
    static let changeCipherSpec = ContentType(rawValue: 20)
    static let alert = ContentType(rawValue: 21)
    static let handshake = ContentType(rawValue: 22)
    static let applicationData = ContentType(rawValue: 23)
}

extension ContentType: Hashable { }

extension ContentType: CustomStringConvertible {
    var description: String {
        switch self {
        case .invalid:
            return ".invalid"
        case .changeCipherSpec:
            return ".changeCipherSpec"
        case .alert:
            return ".alert"
        case .handshake:
            return ".handshake"
        case .applicationData:
            return ".applicationData"
        default:
            return "ContentType(rawValue: \(self.rawValue))"
        }
    }
}

@available(SwiftTLS 0.1.0, *)
extension InputBuffer {
    mutating func readContentType() -> ContentType? {
        return self.readInteger().map { ContentType(rawValue: $0) }
    }
}

@available(SwiftTLS 0.1.0, *)
extension ByteBuffer {
    @discardableResult
    mutating func writeContentType(_ type: ContentType) -> Int {
        return self.writeInteger(type.rawValue)
    }

    @discardableResult
    mutating func setContentType(_ type: ContentType, at index: Int) -> Int {
        return self.setInteger(type.rawValue, at: index)
    }
}
