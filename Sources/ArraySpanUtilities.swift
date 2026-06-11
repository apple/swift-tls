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

@available(anyAppleOS 26, *)
extension Array where Element == UInt8 {
    /// Creates an array by copying the bytes of the given raw span.
    ///
    /// The span must contain exactly `count` bytes.
    init(copying bytes: RawSpan) {
        self.init(unsafeUninitializedCapacity: bytes.byteCount) { outputBuffer, initializedCount in
            bytes.withUnsafeBytes { inputBuffer in
                UnsafeMutableRawBufferPointer(outputBuffer).copyMemory(from: inputBuffer)
            }
            initializedCount = bytes.byteCount
        }
    }
}

@available(anyAppleOS 26, *)
extension InlineArray where Element == UInt8 {
    /// Creates an inline array by copying the bytes of the given raw span.
    ///
    /// The span must contain exactly `count` bytes.
    init(copying bytes: RawSpan) {
        precondition(count == bytes.byteCount)
        self.init { outputSpan in
            for i in 0..<count {
                outputSpan.append(bytes.unsafeLoad(fromByteOffset: i, as: UInt8.self))
            }
        }
    }
}

@available(anyAppleOS 26, *)
extension Hasher {
    mutating func combine(bytes: RawSpan) {
        bytes.withUnsafeBytes { buffer in
            self.combine(bytes: buffer)
        }
    }
}

@available(anyAppleOS 26, *)
extension InlineArray where Element: Equatable {
    static func ==(lhs: Self, rhs: Self) -> Bool {
        for i in lhs.indices {
            if lhs[i] != rhs[i] {
                return false
            }
        }

        return true
    }
}

@available(anyAppleOS 26, *)
extension OutputRawSpan {
    /// Appends the contents of the given raw span to this output span.
    mutating func append(contentsOf bytes: RawSpan) {
        for i in 0..<bytes.byteCount {
            append(bytes.unsafeLoad(fromByteOffset: i, as: UInt8.self))
        }
    }
}

@available(anyAppleOS 26, *)
extension RawSpan {
    subscript(index: Int) -> UInt8 {
        unsafeLoad(fromByteOffset: index, as: UInt8.self)
    }
}
