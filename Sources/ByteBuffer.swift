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

#if SWIFTTLS_EXCLAVEKIT
extension Data {
    static func ==(lhs: Data, rhs: Data) -> Bool {
        return lhs.elementsEqual(rhs)
    }
}
#endif

/// A type that brings over many of the conveniences of SwiftNIO's `ByteBuffer`, reimplemented on `Data`.
///
/// This is not a truly hardened version of NIO's ByteBuffer. It lacks some flexibility, but it's
/// good enough for what we need.
@available(SwiftTLS 0.1.0, *)
struct ByteBuffer {
    private var backingData: Data
    private(set) var readerIndex: Data.Index

    // This is a divergence from NIO's bytebuffer, but if we never move the writer index then we can avoid
    // needing anything else.
    var writerIndex: Data.Index {
        return self.backingData.endIndex
    }

    init() {
        self.init(data: Data())
    }

    init(data: Data) {
        self.backingData = data
        self.readerIndex = data.startIndex
    }

    init<Bytes: Sequence>(bytes: Bytes) where Bytes.Element == UInt8 {
        self = ByteBuffer(data: Data(bytes))
    }

    init(copying bytes: RawSpan) {
        self = ByteBuffer(data: Data(copying: bytes))
    }

    init(copying bytes: borrowing InputBuffer) {
        self.init(copying: bytes.bytes)
    }

    var readableBytes: Int {
        return self.writerIndex - self.readerIndex
    }

    /// The readable bytes exposed as a `RawSpan`.
    var readableBytesSpan: RawSpan {
        let startOffset = self.readerIndex - self.backingData.startIndex
        let endOffset = startOffset + self.readableBytes

        #if (canImport(Foundation) && !SWIFTTLS_EMBEDDED) || !canImport(SwiftSystem)
        return self.backingData.bytes.extracting(startOffset..<endOffset)
        #else /*canImport(SwiftSystem)*/

        // Workaround for SwiftSystem version of Data missing the "bytes" property
        if let pointer = self.backingData.withContiguousStorageIfAvailable({ $0 }) {
            let rebased = UnsafeBufferPointer(rebasing: pointer[startOffset..<endOffset])
            return _overrideLifetime(RawSpan(_unsafeElements: rebased), borrowing: self)
        } else {
            return RawSpan()
        }
        #endif
    }

    @discardableResult
    mutating func writeInteger<IntegerType: FixedWidthInteger>(_ integer: IntegerType, as: IntegerType.Type = IntegerType.self) -> Int {
        let byteWidth = IntegerType.byteWidth
        var networkByteOrder = integer.bigEndian
        withUnsafeBytes(of: &networkByteOrder) {
            precondition($0.count == byteWidth)
            self.backingData.append(contentsOf: $0)
        }

        return byteWidth
    }

    @discardableResult
    mutating func setInteger<IntegerType: FixedWidthInteger>(_ integer: IntegerType, at index: Data.Index, as: IntegerType.Type = IntegerType.self) -> Int {
        // Valiate we have space.
        let byteWidth = IntegerType.byteWidth
        let endIndex = index + byteWidth

        precondition(index >= self.readerIndex)
        precondition(endIndex <= self.writerIndex)

        var networkByteOrder = integer.bigEndian
        withUnsafeBytes(of: &networkByteOrder) {
            precondition($0.count == byteWidth)
            self.backingData.replaceSubrange(index..<endIndex, with: $0)
        }

        return byteWidth
    }

    mutating func readInteger<IntegerType: FixedWidthInteger>(as: IntegerType.Type = IntegerType.self) -> IntegerType? {
        var value = IntegerType.zero
        let byteCount = IntegerType.byteWidth
        let endIndex = self.readerIndex + byteCount

        guard self.writerIndex >= endIndex else {
            return nil
        }
        defer {
            self.readerIndex = endIndex
        }

        _ = withUnsafeMutableBytes(of: &value) {
            #if canImport(Foundation) && !SWIFTTLS_EMBEDDED
            self.backingData.copyBytes(to: $0, from: self.readerIndex..<endIndex)
            #else
            // SwiftSystem Data is missing copyBytes(to: from:)
            $0.copyBytes(from: self.backingData[self.readerIndex..<endIndex])
            #endif
        }
        return IntegerType(bigEndian: value)
    }

    @discardableResult
    mutating func writeImmutableBuffer(_ buffer: ByteBuffer) -> Int {
        let sliceToAppend = buffer.backingData[buffer.readerIndex...]
        self.backingData.append(sliceToAppend)
        return sliceToAppend.count
    }

    @discardableResult
    mutating func setImmutableBuffer(_ buffer: ByteBuffer, at index: Int) -> Int {
        precondition(index <= self.writerIndex && index >= self.backingData.startIndex)
        let sliceToInsert = buffer.backingData[buffer.readerIndex...]

        // Unchecked math here is safe because we validate the index is in the range already.
        let bytesToOverwrite = min(sliceToInsert.count, self.writerIndex &- index)
        let replacementRange = index..<(index &+ bytesToOverwrite)
        self.backingData[replacementRange] = sliceToInsert
        return sliceToInsert.count
    }

    @discardableResult
    mutating func writeBuffer(_ buffer: inout ByteBuffer) -> Int {
        defer {
            buffer.readerIndex = buffer.writerIndex
        }
        return self.writeImmutableBuffer(buffer)
    }

    mutating func readSlice(length: Int) -> ByteBuffer? {
        let endIndex = self.readerIndex + length
        guard endIndex <= self.writerIndex else {
            return nil
        }

        let slice = self.backingData[self.readerIndex..<endIndex]
        self.readerIndex = endIndex
        return ByteBuffer(data: slice)
    }

    var readableBytesView: Data {
        return self.backingData[self.readerIndex..<self.writerIndex]
    }

    mutating func readBytes(length: Int) -> [UInt8]? {
        let endIndex = self.readerIndex + length
        guard endIndex <= self.writerIndex else {
            return nil
        }
        defer {
            self.readerIndex = endIndex
        }
        return Array(self.backingData[self.readerIndex..<endIndex])
    }

    @discardableResult
    mutating func writeBytes(_ bytes: RawSpan) -> Int {
        self.backingData.append(contentsOf: bytes)
        return bytes.byteCount
    }

    @discardableResult
    mutating func writeBytes(_ bytes: [UInt8]) -> Int {
        return writeBytes(bytes.span.bytes)
    }

    @discardableResult
    mutating func writeBytes<Bytes: Collection>(_ bytes: Bytes) -> Int where Bytes.Element == UInt8 {
        self.backingData.append(contentsOf: bytes)
        return bytes.count
    }

    mutating func moveReaderIndex(to newIndex: Data.Index) {
        precondition(newIndex >= self.backingData.startIndex)
        precondition(newIndex <= self.backingData.endIndex)

        self.readerIndex = newIndex
    }

    mutating func moveWriterIndex(forwardBy distance: Int) {
        self.backingData.append(contentsOf: repeatElement(0, count: distance))
    }
}

@available(SwiftTLS 0.1.0, *)
extension ByteBuffer {
    @discardableResult
    mutating func writeVariableLengthVector<LengthField: FixedWidthInteger>(
        lengthFieldType: LengthField.Type, _ writer: (inout ByteBuffer) -> Int
    ) -> Int {
        // Reserve the place
        let lengthIndex = self.writerIndex
        let lengthLength = self.writeInteger(.zero, as: LengthField.self)
        let bodyLength = writer(&self)
        self.setInteger(LengthField(bodyLength), at: lengthIndex)
        return lengthLength + bodyLength
    }

    // I was too lazy to implement FixedWidthInteger for a UInt24, given that it's not really what we need.
    @discardableResult
    mutating func writeVariableLengthVectorUInt24(
        _ writer: (inout ByteBuffer) -> Int
    ) -> Int {
        // Reserve the place
        let lengthIndex = self.writerIndex
        let lengthLength = self.writeUInt24(0)
        let bodyLength = writer(&self)
        self.setUInt24(bodyLength, at: lengthIndex)
        return lengthLength + bodyLength
    }


    mutating func rewindOnNilOrError<ResultType, E:Error>(_ block: (inout ByteBuffer) throws(E) -> ResultType?) throws(E) -> ResultType? {
        let original = self

        do {
            if let result = try block(&self) {
                return result
            } else {
                self = original
                return nil
            }
        } catch {
            self = original
            throw error
        }
    }

    @discardableResult
    mutating func writeUInt24(_ length: Int) -> Int {
        precondition(length < (1 << 24))
        let high = UInt8(truncatingIfNeeded: (length >> 16))
        let low = UInt16(truncatingIfNeeded: length)

        return self.writeInteger(high) + self.writeInteger(low)
    }

    @discardableResult
    mutating func setUInt24(_ length: Int, at index: Int) -> Int {
        precondition(length < (1 << 24))
        let high = UInt8(truncatingIfNeeded: (length >> 16))
        let low = UInt16(truncatingIfNeeded: length)

        var written = self.setInteger(high, at: index)
        written += self.setInteger(low, at: index + written)
        return written
    }
}

@available(SwiftTLS 0.1.0, *)
extension ByteBuffer: Hashable {
    static func ==(lhs: ByteBuffer, rhs: ByteBuffer) -> Bool {
        return lhs.readableBytesView == rhs.readableBytesView
    }

    func hash(into hasher: inout Hasher) {
        hasher.combine(self.readableBytesView)
    }
}

@available(SwiftTLS 0.1.0, *)
extension ByteBuffer {
    /// Execute the given `body` function with an input buffer that can access
    /// the readable part of the byte buffer. Bytes consumed from the input
    /// buffer are also consumed from this byte buffer.
    ///
    /// Use this when you have a byte buffer and want to read from it.
    mutating func withInputBuffer<R: ~Copyable, E: Error>(
        body: (inout InputBuffer) throws(E) -> R
    ) throws(E) -> R {
        var inputBuffer = InputBuffer(
            storage: self.readableBytesSpan
        )

        do {
            let result = try body(&inputBuffer)

            // Advance the reader index
            self.readerIndex += inputBuffer.position

            return result
        } catch {
            // Advance the reader index
            self.readerIndex += inputBuffer.position

            throw error
        }
    }
}

extension FixedWidthInteger {
    static var byteWidth: Int {
        return (Self.bitWidth + 7) / 8
    }
}
