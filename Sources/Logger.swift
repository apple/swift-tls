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

#if SWIFTTLS_EMBEDDED || SWIFTTLS_DRIVERKIT

// This is a temporary placeholder while the real Embedded Swift Logging system is being developed
struct Logger: Sendable {
    init(label: StaticString) {
        self.prefix = label
    }

    // Log to serial
    func log(
        _ message: @autoclosure () -> StreamingSerialMessage,
        terminator: StaticString = "\n"
    ) {}

    func error(
        _ message: @autoclosure () -> StreamingSerialMessage,
        terminator: StaticString = "\n"
    ) {}

    func info(
        _ message: @autoclosure () -> StreamingSerialMessage,
        terminator: StaticString = "\n"
    ) {}

    func warning(
        _ message: @autoclosure () -> StreamingSerialMessage,
        terminator: StaticString = "\n"
    ) {}

    func notice(
        _ message: @autoclosure () -> StreamingSerialMessage,
        terminator: StaticString = "\n"
    ) {}

    // Log to serial, but only in debug builds.
    func debug(
        _ message: @autoclosure () -> StreamingSerialMessage,
        terminator: StaticString = "\n"
    ) {
        #if BUILD_CONFIG_DEBUG
            self.log(message(), terminator: terminator)
        #endif
    }

    let prefix: StaticString
}

/// An implementation of `CharacterPrinter` that calls `putchar` to write to serial.
struct SerialPrinter: CharacterPrinter {
    init() {}

    func write(rawByte: UInt8) {
    }

    func write(contentsOf: Self) {
        // Don't need to handle nested SerialPrinter objects: they will have
        // already written out to serial.
    }
}
//
// String interpolation objects cast to this type will be streamed
// to serial via calls to `putchar`.
typealias StreamingSerialMessage = StreamingMessage<SerialPrinter>

#endif
