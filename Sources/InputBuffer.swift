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

/// A type that consumes data from an input buffer without modifying or copying
/// it.
///
/// This type is non-escapable, so it can refer to data that is borrowed from
/// a client, such as incoming network data. It is non-copyable to ensure that
/// it is always clear which code is actively reading the data, preventing
/// mistakes where the same data is processed multiple times unnecessarily.
struct InputBuffer: ~Escapable, ~Copyable {
    /// Reference to the underlying storage that we're reading from.
    private let storage: RawSpan

    /// The current reading position within the storage.
    var position: Int = 0

    @_lifetime(copy storage)
    init(storage: RawSpan, position: Int = 0) {
        self.storage = storage
        self.position = position
    }

    /// Determine the number of remaining, readable bytes.
    var byteCount: Int { storage.byteCount - position }

    /// Access all of the remaining, readable bytes
    var bytes: RawSpan {
        @_lifetime(borrow self)
        get {
            storage.extracting(position...)
        }
    }
}

// MARK: Reading
extension InputBuffer {
    /// Read the given number of bytes from the input buffer,
    /// consuming those bytes and returning them in the resulting
    /// input buffer. If there aren't enough bytes in the original
    /// buffer, returns nil.
    @_lifetime(copy self)
    mutating func read(length: Int) -> InputBuffer? {
        guard self.byteCount >= length else {
            return nil
        }

        // Always update the position to account for the bytes we
        // read.
        defer {
            position += length
        }

        return InputBuffer(
            storage: storage
                .extracting(droppingFirst: position)
                .extracting(first: length)
        )
    }

    /// Read all of the remaining bytes from the input buffer.
    @_lifetime(copy self)
    mutating func readAll() -> RawSpan {
        defer {
            position = storage.byteCount
        }

        return storage.extracting(droppingFirst: position)
    }

    /// Read a value of the given type, consuming the bytes that make up that
    /// value.
    ///
    /// Note: BitwiseCopyable isn't quite the right constraint. We
    /// need to know that all bit patterns of the type's size are
    /// valid values of that type.
    mutating func read<Value: BitwiseCopyable>(as type: Value.Type) -> Value? {
        let byteCount = MemoryLayout<Value>.size

        // Read enough bytes for the value.
        guard let bytes = self.read(length: byteCount) else {
            return nil
        }

        // Copy those bytes into a temporary value.
        let align = MemoryLayout<Value>.alignment
        return withUnsafeTemporaryAllocation(byteCount: byteCount, alignment: align) { valueBuffer in
            var outputSpan = OutputRawSpan(
                buffer: valueBuffer,
                initializedCount: 0
            )
            bytes.copy(to: &outputSpan)
            let bytesWritten = outputSpan.finalize(for: valueBuffer)
            precondition(bytesWritten == byteCount)
            return valueBuffer.load(as: Value.self)
        }
    }

    /// Read an integer in big-endian ordering from the buffer.
    mutating func readInteger<IntegerType: FixedWidthInteger & BitwiseCopyable>(as: IntegerType.Type = IntegerType.self) -> IntegerType? {
        // Read the integer.
        guard let value = read(as: IntegerType.self) else {
            return nil
        }

        // Convert from big-endian.
        return IntegerType(bigEndian: value)
    }

    /// Read a 24-bit integer in big-endian ordering from the buffer.
    mutating func readUInt24() -> Int? {
        return rewindOnNilOrError { buffer in
            guard let high = buffer.readInteger(as: UInt8.self),
                  let low = buffer.readInteger(as: UInt16.self) else {
                return nil
            }

            return Int(high) << 16 | Int(low)
        }
    }

    /// Yup, double optional! Is this really necessary?
    ///
    /// Yes. The underlying data is necessarily optional: it may be there or it may not. But _also_ we may not
    /// have enough data in the buffer to read either the optional discriminator or the main data. In this case, we
    /// need another layer of optionality. The "outer" optional is whether there was enough data in the buffer:
    /// the "inner" optional is the underlying data type.
    mutating func readOptional<DataType: ~Copyable, E: Error>(_ readFunction: (inout InputBuffer) throws(E) -> DataType?) throws(E) -> DataType?? {
        guard let discriminator = self.readInteger(as: UInt8.self) else {
            return nil
        }

        if discriminator == 0 {
            // We have the bytes, it's nil.
            return .some(nil)
        }

        if let data = try readFunction(&self) {
            return .some(data)
        } else {
            return nil
        }
    }

    mutating func readLengthPrefixed<
        LengthField: FixedWidthInteger & BitwiseCopyable, DataType: ~Copyable, E:Error
    >(
        lengthAs: LengthField.Type = UInt64.self,
        _ readFunction: (inout InputBuffer) throws(E) -> DataType?
    ) throws(E) -> DataType? {
        guard let length = self.readInteger(as: LengthField.self) else {
            return nil
        }

        guard var slice = self.read(length: Int(length)), let result = try readFunction(&slice) else {
            return nil
        }

        return result
    }

    /// Read a variable-length vector with a length field, passing the vector's
    /// contents to the provided reader closure.
    mutating func readVariableLengthVector<LengthField: FixedWidthInteger & BitwiseCopyable, ResultType: ~Copyable>(
        lengthFieldType: LengthField.Type, _ reader: (inout InputBuffer) throws(TLSError) -> ResultType
    ) throws(TLSError) -> ResultType? {
        return try self.rewindOnNilOrError { buffer throws(TLSError) in
            guard let length = buffer.readInteger(as: LengthField.self),
                  var slice = buffer.read(length: Int(length)) else {
                return nil
            }

            let result = try reader(&slice)
            guard slice.byteCount == 0 else {
                throw TLSError.excessBytes
            }

            return result
        }
    }

    /// Read a variable-length vector with a 24-bit length field, passing the
    /// vector's contents to the provided reader closure.
    mutating func readVariableLengthVectorUInt24<ResultType: ~Copyable>(
        _ reader: (inout InputBuffer) throws(TLSError) -> ResultType
    ) throws(TLSError) -> ResultType? {
        return try self.rewindOnNilOrError { buffer throws(TLSError) in
            guard let length = buffer.readUInt24(),
                  var slice = buffer.read(length: length) else {
                return nil
            }

            let result = try reader(&slice)
            guard slice.byteCount == 0 else {
                throw TLSError.excessBytes
            }

            return result
        }
    }
}

// MARK: Tentative reading
extension InputBuffer {
    /// Execute the given body to allow it to read from this split
    /// input buffer (provided as an argument). If the body returns
    /// nil or throws an error, this input buffer will rewind to
    /// the original position.
    mutating func rewindOnNilOrError<ResultType: ~Copyable, E:Error>(
        _ body: (inout InputBuffer) throws(E) -> ResultType?
    ) throws(E) -> ResultType? {
        let originalPosition = self.position

        do {
            guard let result = try body(&self)  else {
                self.position = originalPosition
                return nil
            }

            return result
        } catch {
            self.position = originalPosition
            throw error
        }
    }
}

// MARK: Seeking
extension InputBuffer {
    /// Seek to a specific position.
    mutating func seek(to position: Int) {
        precondition(position >= 0 && position <= storage.byteCount)
        self.position = position
    }
}

// MARK: Copying out data
extension InputBuffer {
    /// Copies the bytes from the buffer into the given raw
    /// output span. This operation will copy
    /// min(byteCount, output.freeCapacity) bytes, returning the
    /// number of bytes written.
    ///
    /// Note that this operation does not consume any bytes.
    @discardableResult
    func copy(to output: inout OutputRawSpan) -> Int {
        let bytesToWrite = min(byteCount, output.freeCapacity)
        output.append(contentsOf: bytes.extracting(first: bytesToWrite))
        return bytesToWrite
    }
}
