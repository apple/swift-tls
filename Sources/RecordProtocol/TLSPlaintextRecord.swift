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

// Availability due to `RawSpan`
@available(SwiftTLS 0.1.0, *)
struct TLSPlaintext: TLSRecordProtocol, Hashable {
    let contentType: ContentType
    let protocolVersion: ProtocolVersion
    var content: [UInt8] { self.fragment }

    let fragment: [UInt8]

    init(contentType: ContentType, protocolVersion: ProtocolVersion = .tlsv12 , fragment: [UInt8]) {
        self.contentType = contentType
        self.protocolVersion = protocolVersion
        self.fragment = fragment
    }

    init(contentType: ContentType, protocolVersion: ProtocolVersion = .tlsv12 , fragment: RawSpan) {
        self.contentType = contentType
        self.protocolVersion = protocolVersion
        self.fragment = [UInt8](copying: fragment)
    }
}
