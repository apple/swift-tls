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

#if hasFeature(Embedded) || TEST_EMBED || SWIFTTLS_EXCLAVECORE || SWIFTTLS_DRIVERKIT
internal typealias TimeInterval = Double

internal struct EmbeddedDateStub: Equatable, Comparable {
    static func < (lhs: EmbeddedDateStub, rhs: EmbeddedDateStub) -> Bool {
        fatalError("EmbeddedDateStub should not be used. < not supported.")
    }

    internal var timeIntervalSinceReferenceDate: TimeInterval {
        fatalError("EmbeddedDateStub should not be used. timeIntervalSinceReferenceDate not supported.")    }

    init () {
        fatalError("EmbeddedDateStub should not be used. init() not supported")
    }

    init(timeIntervalSinceReferenceDate: TimeInterval) {
        fatalError("EmbeddedDateStub should not be used. init(timeIntervalSinceReferenceDate:) not supported")
    }

    func addingTimeInterval(_ timeInterval: TimeInterval) -> EmbeddedDateStub {
        fatalError("EmbeddedDateStub should not be used. addingTimeInterval() not supported")
    }

    func timeIntervalSince(_ date: EmbeddedDateStub) -> TimeInterval {
        fatalError("EmbeddedDateStub should not be used. timeIntervalSince() not supported")
    }
}
// stub out Date so SwiftTLS will build with Embedded Swift.
internal typealias Date = EmbeddedDateStub
#endif

/// This protocol exists for testing purposes only, and is declared internal for that reason.
///
/// This method defines a way to get hold of time. In release builds, we always use Foundation for this, but
/// when testing we want a way to stub out the results.
internal protocol SwiftTLSClock {
    func now() -> Date
}

struct SwiftTLSDefaultClock: SwiftTLSClock {
    func now() -> Date {
        return Date()
    }
}
