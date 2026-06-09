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

extension Data {
    /// Creates a `Data` instance by copying the raw bytes from the given span.
    init(copying bytes: RawSpan) {
        if bytes.byteCount == 0 {
            self = Data()
        } else {
            self = bytes.withUnsafeBytes { buffer in
                Data(
                    UnsafeBufferPointer<UInt8>(
                        start: buffer.baseAddress!.assumingMemoryBound(to: UInt8.self),
                        count: buffer.count
                    )
                )
            }
        }
    }

    /// Appends the contents of the given span to this `Data` instance.
    mutating func append(contentsOf bytes: RawSpan) {
        bytes.withUnsafeBytes { buffer in
            self.append(contentsOf: buffer)
        }
    }

    /// Calls `body` with a `RawSpan` describing the bytes.
    ///
    /// Used as a workaround for SwiftSystem's `Data` missing the `bytes` property.
    func withBytes<R, E: Error>(_ body: (RawSpan) throws(E) -> R) throws(E) -> R {
        let result: Result<R, E> = self.withUnsafeBytes { bufferPointer in
            do throws(E) {
                return .success(try body(bufferPointer.bytes))
            } catch {
                return .failure(error)
            }
        }

        return try result.get()
    }
}

// Workaround for ExclaveKit's Foundation missing DataProtocol APIs.
//
// Use this wrapper to turn an UnsafeRawBufferPointer into something that conforms to
// DataProtocol. This whole type should go away once the issue is fixed.
struct UnsafeRawBufferPointerWrapper: DataProtocol, RandomAccessCollection, ContiguousBytes {
    var wrapped: UnsafeRawBufferPointer

    typealias Element = UInt8
    typealias Index = Int
    typealias Regions = CollectionOfOne<UnsafeRawBufferPointerWrapper>

    var regions: CollectionOfOne<UnsafeRawBufferPointerWrapper> {
        CollectionOfOne(self)
    }

    var startIndex: Int { wrapped.startIndex }
    var endIndex: Int { wrapped.endIndex }

    subscript(index: Int) -> UInt8 {
        get {
            wrapped[index]
        }
    }

    #if $Embedded
    func withUnsafeBytes<R, E>(_ body: (UnsafeRawBufferPointer) throws(E) -> R) throws(E) -> R {
        try wrapped.withUnsafeBytes(body)
    }
    #else
    func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        try wrapped.withUnsafeBytes(body)
    }
    #endif
}
