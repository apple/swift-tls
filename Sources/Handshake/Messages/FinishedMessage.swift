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

struct FinishedMessage {
    var verifyData: ByteBuffer

    init(verifyData: ByteBuffer) {
        self.verifyData = verifyData
    }
}

extension FinishedMessage: Hashable { }

extension FinishedMessage: HandshakeMessageProtocol {
    static var handshakeType: HandshakeType {
        .finished
    }

    func write(into buffer: inout ByteBuffer) -> Int {
        return buffer.writeImmutableBuffer(self.verifyData)
    }

    init(bytes: inout InputBuffer) throws(TLSError) {
        self = FinishedMessage(verifyData: ByteBuffer(copying: bytes.readAll()))
    }
}
