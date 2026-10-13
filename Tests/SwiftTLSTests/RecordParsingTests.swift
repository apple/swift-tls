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

import XCTest
#if canImport(SwiftTLS) && !SWIFTTLS_BUILTIN_TESTS
@testable import SwiftTLS
#endif

#if canImport(Darwin)
import os.log
// Availability due to `os.log`'s `Logger`
@available(macOS 11, iOS 14, tvOS 14, watchOS 7, *)
private let logger = Logger(subsystem: "com.apple.security.swifttls", category: "RecordLayerTests")
#elseif canImport(Logging)
// Linux Logging
import Logging
private let logger = Logger(label: "com.apple.security.swifttls.RecordLayerTests")
#endif

#if canImport(CryptoKit)
import CryptoKit
#elseif canImport(Crypto)
@preconcurrency import Crypto
#endif

#if canImport(Foundation)
import Foundation
#endif

// Availability due to `RawSpan`
@available(SwiftTLS 0.1.0, *)
class RecordParsingTests: XCTestCase {
    var buffer: ByteBuffer!
    var recordParser: TLSRecordParser = TLSRecordParser()
    var messageParser: TLSMessageParser = TLSMessageParser()

    override func setUp() {
        self.buffer = ByteBuffer()
        self.recordParser = TLSRecordParser()
        self.messageParser = TLSMessageParser()
    }

    override func tearDown() {
        self.buffer = nil
    }

    static let oneRTTClientHelloFullRecord: [UInt8] =
                [// ContentType: handshake(22)
                0x16,

                // Legacy Protocol Version = TLS 1.0
                0x03, 0x01,

                // Length = 196 bytes
                0x00, 0xc4,

                // Content
                0x01, 0x00, 0x00, 0xc0, 0x03, 0x03, 0xcb, 0x34, 0xec,
                0xb1, 0xe7, 0x81, 0x63, 0xba, 0x1c, 0x38, 0xc6, 0xda, 0xcb, 0x19, 0x6a, 0x6d, 0xff,
                0xa2, 0x1a, 0x8d, 0x99, 0x12, 0xec, 0x18, 0xa2, 0xef, 0x62, 0x83, 0x02, 0x4d, 0xec,
                0xe7, 0x00, 0x00, 0x06, 0x13, 0x01, 0x13, 0x03, 0x13, 0x02, 0x01, 0x00, 0x00, 0x91,
                0x00, 0x00, 0x00, 0x0b, 0x00, 0x09, 0x00, 0x00, 0x06, 0x73, 0x65, 0x72, 0x76, 0x65,
                0x72, 0xff, 0x01, 0x00, 0x01, 0x00, 0x00, 0x0a, 0x00, 0x14, 0x00, 0x12, 0x00, 0x1d,
                0x00, 0x17, 0x00, 0x18, 0x00, 0x19, 0x01, 0x00, 0x01, 0x01, 0x01, 0x02, 0x01, 0x03,
                0x01, 0x04, 0x00, 0x23, 0x00, 0x00, 0x00, 0x33, 0x00, 0x26, 0x00, 0x24, 0x00, 0x1d,
                0x00, 0x20, 0x99, 0x38, 0x1d, 0xe5, 0x60, 0xe4, 0xbd, 0x43, 0xd2, 0x3d, 0x8e, 0x43,
                0x5a, 0x7d, 0xba, 0xfe, 0xb3, 0xc0, 0x6e, 0x51, 0xc1, 0x3c, 0xae, 0x4d, 0x54, 0x13,
                0x69, 0x1e, 0x52, 0x9a, 0xaf, 0x2c, 0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04, 0x00,
                0x0d, 0x00, 0x20, 0x00, 0x1e, 0x04, 0x03, 0x05, 0x03, 0x06, 0x03, 0x02, 0x03, 0x08,
                0x04, 0x08, 0x05, 0x08, 0x06, 0x04, 0x01, 0x05, 0x01, 0x06, 0x01, 0x02, 0x01, 0x04,
                0x02, 0x05, 0x02, 0x06, 0x02, 0x02, 0x02, 0x00, 0x2d, 0x00, 0x02, 0x01, 0x01, 0x00,
                0x1c, 0x00, 0x02, 0x40, 0x01]

        static let oneRTTClientHelloPayload: [UInt8] = [0x01, 0x00, 0x00, 0xc0, 0x03, 0x03, 0xcb, 0x34, 0xec,
                0xb1, 0xe7, 0x81, 0x63, 0xba, 0x1c, 0x38, 0xc6, 0xda, 0xcb, 0x19, 0x6a, 0x6d, 0xff,
                0xa2, 0x1a, 0x8d, 0x99, 0x12, 0xec, 0x18, 0xa2, 0xef, 0x62, 0x83, 0x02, 0x4d, 0xec,
                0xe7, 0x00, 0x00, 0x06, 0x13, 0x01, 0x13, 0x03, 0x13, 0x02, 0x01, 0x00, 0x00, 0x91,
                0x00, 0x00, 0x00, 0x0b, 0x00, 0x09, 0x00, 0x00, 0x06, 0x73, 0x65, 0x72, 0x76, 0x65,
                0x72, 0xff, 0x01, 0x00, 0x01, 0x00, 0x00, 0x0a, 0x00, 0x14, 0x00, 0x12, 0x00, 0x1d,
                0x00, 0x17, 0x00, 0x18, 0x00, 0x19, 0x01, 0x00, 0x01, 0x01, 0x01, 0x02, 0x01, 0x03,
                0x01, 0x04, 0x00, 0x23, 0x00, 0x00, 0x00, 0x33, 0x00, 0x26, 0x00, 0x24, 0x00, 0x1d,
                0x00, 0x20, 0x99, 0x38, 0x1d, 0xe5, 0x60, 0xe4, 0xbd, 0x43, 0xd2, 0x3d, 0x8e, 0x43,
                0x5a, 0x7d, 0xba, 0xfe, 0xb3, 0xc0, 0x6e, 0x51, 0xc1, 0x3c, 0xae, 0x4d, 0x54, 0x13,
                0x69, 0x1e, 0x52, 0x9a, 0xaf, 0x2c, 0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04, 0x00,
                0x0d, 0x00, 0x20, 0x00, 0x1e, 0x04, 0x03, 0x05, 0x03, 0x06, 0x03, 0x02, 0x03, 0x08,
                0x04, 0x08, 0x05, 0x08, 0x06, 0x04, 0x01, 0x05, 0x01, 0x06, 0x01, 0x02, 0x01, 0x04,
                0x02, 0x05, 0x02, 0x06, 0x02, 0x02, 0x02, 0x00, 0x2d, 0x00, 0x02, 0x01, 0x01, 0x00,
                0x1c, 0x00, 0x02, 0x40, 0x01]

        static let oneRTTServerHelloFullRecord: [UInt8] =
                [0x16, 0x03, 0x03, 0x00, 0x5a, 0x02, 0x00, 0x00, 0x56, 0x03, 0x03, 0xa6, 0xaf, 0x06,
                0xa4, 0x12, 0x18, 0x60, 0xdc, 0x5e, 0x6e, 0x60, 0x24, 0x9c, 0xd3, 0x4c, 0x95, 0x93,
                0x0c, 0x8a, 0xc5, 0xcb, 0x14, 0x34, 0xda, 0xc1, 0x55, 0x77, 0x2e, 0xd3, 0xe2, 0x69,
                0x28, 0x00, 0x13, 0x01, 0x00, 0x00, 0x2e, 0x00, 0x33, 0x00, 0x24, 0x00, 0x1d, 0x00,
                0x20, 0xc9, 0x82, 0x88, 0x76, 0x11, 0x20, 0x95, 0xfe, 0x66, 0x76, 0x2b, 0xdb, 0xf7,
                0xc6, 0x72, 0xe1, 0x56, 0xd6, 0xcc, 0x25, 0x3b, 0x83, 0x3d, 0xf1, 0xdd, 0x69, 0xb1,
                0xb0, 0x4e, 0x75, 0x1f, 0x0f, 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04]

        static let oneRTTServerHelloPayload: [UInt8] =
                [0x02, 0x00, 0x00, 0x56, 0x03, 0x03, 0xa6, 0xaf, 0x06, 0xa4, 0x12, 0x18, 0x60, 0xdc,
                0x5e, 0x6e, 0x60, 0x24, 0x9c, 0xd3, 0x4c, 0x95, 0x93, 0x0c, 0x8a, 0xc5, 0xcb, 0x14,
                0x34, 0xda, 0xc1, 0x55, 0x77, 0x2e, 0xd3, 0xe2, 0x69, 0x28, 0x00, 0x13, 0x01, 0x00,
                0x00, 0x2e, 0x00, 0x33, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20, 0xc9, 0x82, 0x88, 0x76,
                0x11, 0x20, 0x95, 0xfe, 0x66, 0x76, 0x2b, 0xdb, 0xf7, 0xc6, 0x72, 0xe1, 0x56, 0xd6,
                0xcc, 0x25, 0x3b, 0x83, 0x3d, 0xf1, 0xdd, 0x69, 0xb1, 0xb0, 0x4e, 0x75, 0x1f, 0x0f,
                0x00, 0x2b, 0x00, 0x02, 0x03, 0x04]

        static let oneRTTServerSecondFlightFullRecord: [UInt8] =
                [0x17, 0x03, 0x03, 0x02, 0xa2, 0xd1, 0xff, 0x33, 0x4a, 0x56, 0xf5, 0xbf, 0xf6, 0x59,
                0x4a, 0x07, 0xcc, 0x87, 0xb5, 0x80, 0x23, 0x3f, 0x50, 0x0f, 0x45, 0xe4, 0x89, 0xe7,
                0xf3, 0x3a, 0xf3, 0x5e, 0xdf, 0x78, 0x69, 0xfc, 0xf4, 0x0a, 0xa4, 0x0a, 0xa2, 0xb8,
                0xea, 0x73, 0xf8, 0x48, 0xa7, 0xca, 0x07, 0x61, 0x2e, 0xf9, 0xf9, 0x45, 0xcb, 0x96,
                0x0b, 0x40, 0x68, 0x90, 0x51, 0x23, 0xea, 0x78, 0xb1, 0x11, 0xb4, 0x29, 0xba, 0x91,
                0x91, 0xcd, 0x05, 0xd2, 0xa3, 0x89, 0x28, 0x0f, 0x52, 0x61, 0x34, 0xaa, 0xdc, 0x7f,
                0xc7, 0x8c, 0x4b, 0x72, 0x9d, 0xf8, 0x28, 0xb5, 0xec, 0xf7, 0xb1, 0x3b, 0xd9, 0xae,
                0xfb, 0x0e, 0x57, 0xf2, 0x71, 0x58, 0x5b, 0x8e, 0xa9, 0xbb, 0x35, 0x5c, 0x7c, 0x79,
                0x02, 0x07, 0x16, 0xcf, 0xb9, 0xb1, 0x18, 0x3e, 0xf3, 0xab, 0x20, 0xe3, 0x7d, 0x57,
                0xa6, 0xb9, 0xd7, 0x47, 0x76, 0x09, 0xae, 0xe6, 0xe1, 0x22, 0xa4, 0xcf, 0x51, 0x42,
                0x73, 0x25, 0x25, 0x0c, 0x7d, 0x0e, 0x50, 0x92, 0x89, 0x44, 0x4c, 0x9b, 0x3a, 0x64,
                0x8f, 0x1d, 0x71, 0x03, 0x5d, 0x2e, 0xd6, 0x5b, 0x0e, 0x3c, 0xdd, 0x0c, 0xba, 0xe8,
                0xbf, 0x2d, 0x0b, 0x22, 0x78, 0x12, 0xcb, 0xb3, 0x60, 0x98, 0x72, 0x55, 0xcc, 0x74,
                0x41, 0x10, 0xc4, 0x53, 0xba, 0xa4, 0xfc, 0xd6, 0x10, 0x92, 0x8d, 0x80, 0x98, 0x10,
                0xe4, 0xb7, 0xed, 0x1a, 0x8f, 0xd9, 0x91, 0xf0, 0x6a, 0xa6, 0x24, 0x82, 0x04, 0x79,
                0x7e, 0x36, 0xa6, 0xa7, 0x3b, 0x70, 0xa2, 0x55, 0x9c, 0x09, 0xea, 0xd6, 0x86, 0x94,
                0x5b, 0xa2, 0x46, 0xab, 0x66, 0xe5, 0xed, 0xd8, 0x04, 0x4b, 0x4c, 0x6d, 0xe3, 0xfc,
                0xf2, 0xa8, 0x94, 0x41, 0xac, 0x66, 0x27, 0x2f, 0xd8, 0xfb, 0x33, 0x0e, 0xf8, 0x19,
                0x05, 0x79, 0xb3, 0x68, 0x45, 0x96, 0xc9, 0x60, 0xbd, 0x59, 0x6e, 0xea, 0x52, 0x0a,
                0x56, 0xa8, 0xd6, 0x50, 0xf5, 0x63, 0xaa, 0xd2, 0x74, 0x09, 0x96, 0x0d, 0xca, 0x63,
                0xd3, 0xe6, 0x88, 0x61, 0x1e, 0xa5, 0xe2, 0x2f, 0x44, 0x15, 0xcf, 0x95, 0x38, 0xd5,
                0x1a, 0x20, 0x0c, 0x27, 0x03, 0x42, 0x72, 0x96, 0x8a, 0x26, 0x4e, 0xd6, 0x54, 0x0c,
                0x84, 0x83, 0x8d, 0x89, 0xf7, 0x2c, 0x24, 0x46, 0x1a, 0xad, 0x6d, 0x26, 0xf5, 0x9e,
                0xca, 0xba, 0x9a, 0xcb, 0xbb, 0x31, 0x7b, 0x66, 0xd9, 0x02, 0xf4, 0xf2, 0x92, 0xa3,
                0x6a, 0xc1, 0xb6, 0x39, 0xc6, 0x37, 0xce, 0x34, 0x31, 0x17, 0xb6, 0x59, 0x62, 0x22,
                0x45, 0x31, 0x7b, 0x49, 0xee, 0xda, 0x0c, 0x62, 0x58, 0xf1, 0x00, 0xd7, 0xd9, 0x61,
                0xff, 0xb1, 0x38, 0x64, 0x7e, 0x92, 0xea, 0x33, 0x0f, 0xae, 0xea, 0x6d, 0xfa, 0x31,
                0xc7, 0xa8, 0x4d, 0xc3, 0xbd, 0x7e, 0x1b, 0x7a, 0x6c, 0x71, 0x78, 0xaf, 0x36, 0x87,
                0x90, 0x18, 0xe3, 0xf2, 0x52, 0x10, 0x7f, 0x24, 0x3d, 0x24, 0x3d, 0xc7, 0x33, 0x9d,
                0x56, 0x84, 0xc8, 0xb0, 0x37, 0x8b, 0xf3, 0x02, 0x44, 0xda, 0x8c, 0x87, 0xc8, 0x43,
                0xf5, 0xe5, 0x6e, 0xb4, 0xc5, 0xe8, 0x28, 0x0a, 0x2b, 0x48, 0x05, 0x2c, 0xf9, 0x3b,
                0x16, 0x49, 0x9a, 0x66, 0xdb, 0x7c, 0xca, 0x71, 0xe4, 0x59, 0x94, 0x26, 0xf7, 0xd4,
                0x61, 0xe6, 0x6f, 0x99, 0x88, 0x2b, 0xd8, 0x9f, 0xc5, 0x08, 0x00, 0xbe, 0xcc, 0xa6,
                0x2d, 0x6c, 0x74, 0x11, 0x6d, 0xbd, 0x29, 0x72, 0xfd, 0xa1, 0xfa, 0x80, 0xf8, 0x5d,
                0xf8, 0x81, 0xed, 0xbe, 0x5a, 0x37, 0x66, 0x89, 0x36, 0xb3, 0x35, 0x58, 0x3b, 0x59,
                0x91, 0x86, 0xdc, 0x5c, 0x69, 0x18, 0xa3, 0x96, 0xfa, 0x48, 0xa1, 0x81, 0xd6, 0xb6,
                0xfa, 0x4f, 0x9d, 0x62, 0xd5, 0x13, 0xaf, 0xbb, 0x99, 0x2f, 0x2b, 0x99, 0x2f, 0x67,
                0xf8, 0xaf, 0xe6, 0x7f, 0x76, 0x91, 0x3f, 0xa3, 0x88, 0xcb, 0x56, 0x30, 0xc8, 0xca,
                0x01, 0xe0, 0xc6, 0x5d, 0x11, 0xc6, 0x6a, 0x1e, 0x2a, 0xc4, 0xc8, 0x59, 0x77, 0xb7,
                0xc7, 0xa6, 0x99, 0x9b, 0xbf, 0x10, 0xdc, 0x35, 0xae, 0x69, 0xf5, 0x51, 0x56, 0x14,
                0x63, 0x6c, 0x0b, 0x9b, 0x68, 0xc1, 0x9e, 0xd2, 0xe3, 0x1c, 0x0b, 0x3b, 0x66, 0x76,
                0x30, 0x38, 0xeb, 0xba, 0x42, 0xf3, 0xb3, 0x8e, 0xdc, 0x03, 0x99, 0xf3, 0xa9, 0xf2,
                0x3f, 0xaa, 0x63, 0x97, 0x8c, 0x31, 0x7f, 0xc9, 0xfa, 0x66, 0xa7, 0x3f, 0x60, 0xf0,
                0x50, 0x4d, 0xe9, 0x3b, 0x5b, 0x84, 0x5e, 0x27, 0x55, 0x92, 0xc1, 0x23, 0x35, 0xee,
                0x34, 0x0b, 0xbc, 0x4f, 0xdd, 0xd5, 0x02, 0x78, 0x40, 0x16, 0xe4, 0xb3, 0xbe, 0x7e,
                0xf0, 0x4d, 0xda, 0x49, 0xf4, 0xb4, 0x40, 0xa3, 0x0c, 0xb5, 0xd2, 0xaf, 0x93, 0x98,
                0x28, 0xfd, 0x4a, 0xe3, 0x79, 0x4e, 0x44, 0xf9, 0x4d, 0xf5, 0xa6, 0x31, 0xed, 0xe4,
                0x2c, 0x17, 0x19, 0xbf, 0xda, 0xbf, 0x02, 0x53, 0xfe, 0x51, 0x75, 0xbe, 0x89, 0x8e,
                0x75, 0x0e, 0xdc, 0x53, 0x37, 0x0d, 0x2b]

        static let oneRTTServerSecondFlightEncryptedPayload: [UInt8] =
                [0xd1, 0xff, 0x33, 0x4a, 0x56, 0xf5, 0xbf, 0xf6, 0x59,
                0x4a, 0x07, 0xcc, 0x87, 0xb5, 0x80, 0x23, 0x3f, 0x50, 0x0f, 0x45, 0xe4, 0x89, 0xe7,
                0xf3, 0x3a, 0xf3, 0x5e, 0xdf, 0x78, 0x69, 0xfc, 0xf4, 0x0a, 0xa4, 0x0a, 0xa2, 0xb8,
                0xea, 0x73, 0xf8, 0x48, 0xa7, 0xca, 0x07, 0x61, 0x2e, 0xf9, 0xf9, 0x45, 0xcb, 0x96,
                0x0b, 0x40, 0x68, 0x90, 0x51, 0x23, 0xea, 0x78, 0xb1, 0x11, 0xb4, 0x29, 0xba, 0x91,
                0x91, 0xcd, 0x05, 0xd2, 0xa3, 0x89, 0x28, 0x0f, 0x52, 0x61, 0x34, 0xaa, 0xdc, 0x7f,
                0xc7, 0x8c, 0x4b, 0x72, 0x9d, 0xf8, 0x28, 0xb5, 0xec, 0xf7, 0xb1, 0x3b, 0xd9, 0xae,
                0xfb, 0x0e, 0x57, 0xf2, 0x71, 0x58, 0x5b, 0x8e, 0xa9, 0xbb, 0x35, 0x5c, 0x7c, 0x79,
                0x02, 0x07, 0x16, 0xcf, 0xb9, 0xb1, 0x18, 0x3e, 0xf3, 0xab, 0x20, 0xe3, 0x7d, 0x57,
                0xa6, 0xb9, 0xd7, 0x47, 0x76, 0x09, 0xae, 0xe6, 0xe1, 0x22, 0xa4, 0xcf, 0x51, 0x42,
                0x73, 0x25, 0x25, 0x0c, 0x7d, 0x0e, 0x50, 0x92, 0x89, 0x44, 0x4c, 0x9b, 0x3a, 0x64,
                0x8f, 0x1d, 0x71, 0x03, 0x5d, 0x2e, 0xd6, 0x5b, 0x0e, 0x3c, 0xdd, 0x0c, 0xba, 0xe8,
                0xbf, 0x2d, 0x0b, 0x22, 0x78, 0x12, 0xcb, 0xb3, 0x60, 0x98, 0x72, 0x55, 0xcc, 0x74,
                0x41, 0x10, 0xc4, 0x53, 0xba, 0xa4, 0xfc, 0xd6, 0x10, 0x92, 0x8d, 0x80, 0x98, 0x10,
                0xe4, 0xb7, 0xed, 0x1a, 0x8f, 0xd9, 0x91, 0xf0, 0x6a, 0xa6, 0x24, 0x82, 0x04, 0x79,
                0x7e, 0x36, 0xa6, 0xa7, 0x3b, 0x70, 0xa2, 0x55, 0x9c, 0x09, 0xea, 0xd6, 0x86, 0x94,
                0x5b, 0xa2, 0x46, 0xab, 0x66, 0xe5, 0xed, 0xd8, 0x04, 0x4b, 0x4c, 0x6d, 0xe3, 0xfc,
                0xf2, 0xa8, 0x94, 0x41, 0xac, 0x66, 0x27, 0x2f, 0xd8, 0xfb, 0x33, 0x0e, 0xf8, 0x19,
                0x05, 0x79, 0xb3, 0x68, 0x45, 0x96, 0xc9, 0x60, 0xbd, 0x59, 0x6e, 0xea, 0x52, 0x0a,
                0x56, 0xa8, 0xd6, 0x50, 0xf5, 0x63, 0xaa, 0xd2, 0x74, 0x09, 0x96, 0x0d, 0xca, 0x63,
                0xd3, 0xe6, 0x88, 0x61, 0x1e, 0xa5, 0xe2, 0x2f, 0x44, 0x15, 0xcf, 0x95, 0x38, 0xd5,
                0x1a, 0x20, 0x0c, 0x27, 0x03, 0x42, 0x72, 0x96, 0x8a, 0x26, 0x4e, 0xd6, 0x54, 0x0c,
                0x84, 0x83, 0x8d, 0x89, 0xf7, 0x2c, 0x24, 0x46, 0x1a, 0xad, 0x6d, 0x26, 0xf5, 0x9e,
                0xca, 0xba, 0x9a, 0xcb, 0xbb, 0x31, 0x7b, 0x66, 0xd9, 0x02, 0xf4, 0xf2, 0x92, 0xa3,
                0x6a, 0xc1, 0xb6, 0x39, 0xc6, 0x37, 0xce, 0x34, 0x31, 0x17, 0xb6, 0x59, 0x62, 0x22,
                0x45, 0x31, 0x7b, 0x49, 0xee, 0xda, 0x0c, 0x62, 0x58, 0xf1, 0x00, 0xd7, 0xd9, 0x61,
                0xff, 0xb1, 0x38, 0x64, 0x7e, 0x92, 0xea, 0x33, 0x0f, 0xae, 0xea, 0x6d, 0xfa, 0x31,
                0xc7, 0xa8, 0x4d, 0xc3, 0xbd, 0x7e, 0x1b, 0x7a, 0x6c, 0x71, 0x78, 0xaf, 0x36, 0x87,
                0x90, 0x18, 0xe3, 0xf2, 0x52, 0x10, 0x7f, 0x24, 0x3d, 0x24, 0x3d, 0xc7, 0x33, 0x9d,
                0x56, 0x84, 0xc8, 0xb0, 0x37, 0x8b, 0xf3, 0x02, 0x44, 0xda, 0x8c, 0x87, 0xc8, 0x43,
                0xf5, 0xe5, 0x6e, 0xb4, 0xc5, 0xe8, 0x28, 0x0a, 0x2b, 0x48, 0x05, 0x2c, 0xf9, 0x3b,
                0x16, 0x49, 0x9a, 0x66, 0xdb, 0x7c, 0xca, 0x71, 0xe4, 0x59, 0x94, 0x26, 0xf7, 0xd4,
                0x61, 0xe6, 0x6f, 0x99, 0x88, 0x2b, 0xd8, 0x9f, 0xc5, 0x08, 0x00, 0xbe, 0xcc, 0xa6,
                0x2d, 0x6c, 0x74, 0x11, 0x6d, 0xbd, 0x29, 0x72, 0xfd, 0xa1, 0xfa, 0x80, 0xf8, 0x5d,
                0xf8, 0x81, 0xed, 0xbe, 0x5a, 0x37, 0x66, 0x89, 0x36, 0xb3, 0x35, 0x58, 0x3b, 0x59,
                0x91, 0x86, 0xdc, 0x5c, 0x69, 0x18, 0xa3, 0x96, 0xfa, 0x48, 0xa1, 0x81, 0xd6, 0xb6,
                0xfa, 0x4f, 0x9d, 0x62, 0xd5, 0x13, 0xaf, 0xbb, 0x99, 0x2f, 0x2b, 0x99, 0x2f, 0x67,
                0xf8, 0xaf, 0xe6, 0x7f, 0x76, 0x91, 0x3f, 0xa3, 0x88, 0xcb, 0x56, 0x30, 0xc8, 0xca,
                0x01, 0xe0, 0xc6, 0x5d, 0x11, 0xc6, 0x6a, 0x1e, 0x2a, 0xc4, 0xc8, 0x59, 0x77, 0xb7,
                0xc7, 0xa6, 0x99, 0x9b, 0xbf, 0x10, 0xdc, 0x35, 0xae, 0x69, 0xf5, 0x51, 0x56, 0x14,
                0x63, 0x6c, 0x0b, 0x9b, 0x68, 0xc1, 0x9e, 0xd2, 0xe3, 0x1c, 0x0b, 0x3b, 0x66, 0x76,
                0x30, 0x38, 0xeb, 0xba, 0x42, 0xf3, 0xb3, 0x8e, 0xdc, 0x03, 0x99, 0xf3, 0xa9, 0xf2,
                0x3f, 0xaa, 0x63, 0x97, 0x8c, 0x31, 0x7f, 0xc9, 0xfa, 0x66, 0xa7, 0x3f, 0x60, 0xf0,
                0x50, 0x4d, 0xe9, 0x3b, 0x5b, 0x84, 0x5e, 0x27, 0x55, 0x92, 0xc1, 0x23, 0x35, 0xee,
                0x34, 0x0b, 0xbc, 0x4f, 0xdd, 0xd5, 0x02, 0x78, 0x40, 0x16, 0xe4, 0xb3, 0xbe, 0x7e,
                0xf0, 0x4d, 0xda, 0x49, 0xf4, 0xb4, 0x40, 0xa3, 0x0c, 0xb5, 0xd2, 0xaf, 0x93, 0x98,
                0x28, 0xfd, 0x4a, 0xe3, 0x79, 0x4e, 0x44, 0xf9, 0x4d, 0xf5, 0xa6, 0x31, 0xed, 0xe4,
                0x2c, 0x17, 0x19, 0xbf, 0xda, 0xbf, 0x02, 0x53, 0xfe, 0x51, 0x75, 0xbe, 0x89, 0x8e,
                0x75, 0x0e, 0xdc, 0x53, 0x37, 0x0d, 0x2b]

        // unencrypted 657 octets
        static let oneRTTServerSecondFlightPayload: [UInt8] =
                [0x08, 0x00, 0x00, 0x24, 0x00, 0x22, 0x00, 0x0a, 0x00, 0x14, 0x00, 0x12, 0x00, 0x1d,
                0x00, 0x17, 0x00, 0x18, 0x00, 0x19, 0x01, 0x00, 0x01, 0x01, 0x01, 0x02, 0x01, 0x03,
                0x01, 0x04, 0x00, 0x1c, 0x00, 0x02, 0x40, 0x01, 0x00, 0x00, 0x00, 0x00, 0x0b, 0x00,
                0x01, 0xb9, 0x00, 0x00, 0x01, 0xb5, 0x00, 0x01, 0xb0, 0x30, 0x82, 0x01, 0xac, 0x30,
                0x82, 0x01, 0x15, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x01, 0x02, 0x30, 0x0d, 0x06,
                0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x30, 0x0e,
                0x31, 0x0c, 0x30, 0x0a, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x03, 0x72, 0x73, 0x61,
                0x30, 0x1e, 0x17, 0x0d, 0x31, 0x36, 0x30, 0x37, 0x33, 0x30, 0x30, 0x31, 0x32, 0x33,
                0x35, 0x39, 0x5a, 0x17, 0x0d, 0x32, 0x36, 0x30, 0x37, 0x33, 0x30, 0x30, 0x31, 0x32,
                0x33, 0x35, 0x39, 0x5a, 0x30, 0x0e, 0x31, 0x0c, 0x30, 0x0a, 0x06, 0x03, 0x55, 0x04,
                0x03, 0x13, 0x03, 0x72, 0x73, 0x61, 0x30, 0x81, 0x9f, 0x30, 0x0d, 0x06, 0x09, 0x2a,
                0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x81, 0x8d, 0x00,
                0x30, 0x81, 0x89, 0x02, 0x81, 0x81, 0x00, 0xb4, 0xbb, 0x49, 0x8f, 0x82, 0x79, 0x30,
                0x3d, 0x98, 0x08, 0x36, 0x39, 0x9b, 0x36, 0xc6, 0x98, 0x8c, 0x0c, 0x68, 0xde, 0x55,
                0xe1, 0xbd, 0xb8, 0x26, 0xd3, 0x90, 0x1a, 0x24, 0x61, 0xea, 0xfd, 0x2d, 0xe4, 0x9a,
                0x91, 0xd0, 0x15, 0xab, 0xbc, 0x9a, 0x95, 0x13, 0x7a, 0xce, 0x6c, 0x1a, 0xf1, 0x9e,
                0xaa, 0x6a, 0xf9, 0x8c, 0x7c, 0xed, 0x43, 0x12, 0x09, 0x98, 0xe1, 0x87, 0xa8, 0x0e,
                0xe0, 0xcc, 0xb0, 0x52, 0x4b, 0x1b, 0x01, 0x8c, 0x3e, 0x0b, 0x63, 0x26, 0x4d, 0x44,
                0x9a, 0x6d, 0x38, 0xe2, 0x2a, 0x5f, 0xda, 0x43, 0x08, 0x46, 0x74, 0x80, 0x30, 0x53,
                0x0e, 0xf0, 0x46, 0x1c, 0x8c, 0xa9, 0xd9, 0xef, 0xbf, 0xae, 0x8e, 0xa6, 0xd1, 0xd0,
                0x3e, 0x2b, 0xd1, 0x93, 0xef, 0xf0, 0xab, 0x9a, 0x80, 0x02, 0xc4, 0x74, 0x28, 0xa6,
                0xd3, 0x5a, 0x8d, 0x88, 0xd7, 0x9f, 0x7f, 0x1e, 0x3f, 0x02, 0x03, 0x01, 0x00, 0x01,
                0xa3, 0x1a, 0x30, 0x18, 0x30, 0x09, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x04, 0x02, 0x30,
                0x00, 0x30, 0x0b, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x04, 0x04, 0x03, 0x02, 0x05, 0xa0,
                0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05,
                0x00, 0x03, 0x81, 0x81, 0x00, 0x85, 0xaa, 0xd2, 0xa0, 0xe5, 0xb9, 0x27, 0x6b, 0x90,
                0x8c, 0x65, 0xf7, 0x3a, 0x72, 0x67, 0x17, 0x06, 0x18, 0xa5, 0x4c, 0x5f, 0x8a, 0x7b,
                0x33, 0x7d, 0x2d, 0xf7, 0xa5, 0x94, 0x36, 0x54, 0x17, 0xf2, 0xea, 0xe8, 0xf8, 0xa5,
                0x8c, 0x8f, 0x81, 0x72, 0xf9, 0x31, 0x9c, 0xf3, 0x6b, 0x7f, 0xd6, 0xc5, 0x5b, 0x80,
                0xf2, 0x1a, 0x03, 0x01, 0x51, 0x56, 0x72, 0x60, 0x96, 0xfd, 0x33, 0x5e, 0x5e, 0x67,
                0xf2, 0xdb, 0xf1, 0x02, 0x70, 0x2e, 0x60, 0x8c, 0xca, 0xe6, 0xbe, 0xc1, 0xfc, 0x63,
                0xa4, 0x2a, 0x99, 0xbe, 0x5c, 0x3e, 0xb7, 0x10, 0x7c, 0x3c, 0x54, 0xe9, 0xb9, 0xeb,
                0x2b, 0xd5, 0x20, 0x3b, 0x1c, 0x3b, 0x84, 0xe0, 0xa8, 0xb2, 0xf7, 0x59, 0x40, 0x9b,
                0xa3, 0xea, 0xc9, 0xd9, 0x1d, 0x40, 0x2d, 0xcc, 0x0c, 0xc8, 0xf8, 0x96, 0x12, 0x29,
                0xac, 0x91, 0x87, 0xb4, 0x2b, 0x4d, 0xe1, 0x00, 0x00, 0x0f, 0x00, 0x00, 0x84, 0x08,
                0x04, 0x00, 0x80, 0x5a, 0x74, 0x7c, 0x5d, 0x88, 0xfa, 0x9b, 0xd2, 0xe5, 0x5a, 0xb0,
                0x85, 0xa6, 0x10, 0x15, 0xb7, 0x21, 0x1f, 0x82, 0x4c, 0xd4, 0x84, 0x14, 0x5a, 0xb3,
                0xff, 0x52, 0xf1, 0xfd, 0xa8, 0x47, 0x7b, 0x0b, 0x7a, 0xbc, 0x90, 0xdb, 0x78, 0xe2,
                0xd3, 0x3a, 0x5c, 0x14, 0x1a, 0x07, 0x86, 0x53, 0xfa, 0x6b, 0xef, 0x78, 0x0c, 0x5e,
                0xa2, 0x48, 0xee, 0xaa, 0xa7, 0x85, 0xc4, 0xf3, 0x94, 0xca, 0xb6, 0xd3, 0x0b, 0xbe,
                0x8d, 0x48, 0x59, 0xee, 0x51, 0x1f, 0x60, 0x29, 0x57, 0xb1, 0x54, 0x11, 0xac, 0x02,
                0x76, 0x71, 0x45, 0x9e, 0x46, 0x44, 0x5c, 0x9e, 0xa5, 0x8c, 0x18, 0x1e, 0x81, 0x8e,
                0x95, 0xb8, 0xc3, 0xfb, 0x0b, 0xf3, 0x27, 0x84, 0x09, 0xd3, 0xbe, 0x15, 0x2a, 0x3d,
                0xa5, 0x04, 0x3e, 0x06, 0x3d, 0xda, 0x65, 0xcd, 0xf5, 0xae, 0xa2, 0x0d, 0x53, 0xdf,
                0xac, 0xd4, 0x2f, 0x74, 0xf3, 0x14, 0x00, 0x00, 0x20, 0x9b, 0x9b, 0x14, 0x1d, 0x90,
                0x63, 0x37, 0xfb, 0xd2, 0xcb, 0xdc, 0xe7, 0x1d, 0xf4, 0xde, 0xda, 0x4a, 0xb4, 0x2c,
                0x30, 0x95, 0x72, 0xcb, 0x7f, 0xff, 0xee, 0x54, 0x54, 0xb7, 0x8f, 0x07, 0x18]

    static let oneRTTClientSecondFlightHSPayload: [UInt8] =
                [0x14, 0x00, 0x00, 0x20, 0xa8, 0xec, 0x43, 0x6d, 0x67, 0x76, 0x34, 0xae, 0x52, 0x5a,
                0xc1, 0xfc, 0xeb, 0xe1, 0x1a, 0x03, 0x9e, 0xc1, 0x76, 0x94, 0xfa, 0xc6, 0xe9, 0x85,
                0x27, 0xb6, 0x42, 0xf2, 0xed, 0xd5, 0xce, 0x61]

    static let oneRTTClientSecondFlightHSFullRecord: [UInt8] =
                [0x17, 0x03, 0x03, 0x00, 0x35, 0x75, 0xec, 0x4d, 0xc2, 0x38, 0xcc, 0xe6, 0x0b, 0x29,
                0x80, 0x44, 0xa7, 0x1e, 0x21, 0x9c, 0x56, 0xcc, 0x77, 0xb0, 0x51, 0x7f, 0xe9, 0xb9,
                0x3c, 0x7a, 0x4b, 0xfc, 0x44, 0xd8, 0x7f, 0x38, 0xf8, 0x03, 0x38, 0xac, 0x98, 0xfc,
                0x46, 0xde, 0xb3, 0x84, 0xbd, 0x1c, 0xae, 0xac, 0xab, 0x68, 0x67, 0xd7, 0x26, 0xc4,
                0x05, 0x46]

    static let oneRTTServerNewSessionTicketPayload: [UInt8] =
                [0x04, 0x00, 0x00, 0xc9, 0x00, 0x00, 0x00, 0x1e, 0xfa, 0xd6, 0xaa, 0xc5, 0x02, 0x00,
                0x00, 0x00, 0xb2, 0x2c, 0x03, 0x5d, 0x82, 0x93, 0x59, 0xee, 0x5f, 0xf7, 0xaf, 0x4e,
                0xc9, 0x00, 0x00, 0x00, 0x00, 0x26, 0x2a, 0x64, 0x94, 0xdc, 0x48, 0x6d, 0x2c, 0x8a,
                0x34, 0xcb, 0x33, 0xfa, 0x90, 0xbf, 0x1b, 0x00, 0x70, 0xad, 0x3c, 0x49, 0x88, 0x83,
                0xc9, 0x36, 0x7c, 0x09, 0xa2, 0xbe, 0x78, 0x5a, 0xbc, 0x55, 0xcd, 0x22, 0x60, 0x97,
                0xa3, 0xa9, 0x82, 0x11, 0x72, 0x83, 0xf8, 0x2a, 0x03, 0xa1, 0x43, 0xef, 0xd3, 0xff,
                0x5d, 0xd3, 0x6d, 0x64, 0xe8, 0x61, 0xbe, 0x7f, 0xd6, 0x1d, 0x28, 0x27, 0xdb, 0x27,
                0x9c, 0xce, 0x14, 0x50, 0x77, 0xd4, 0x54, 0xa3, 0x66, 0x4d, 0x4e, 0x6d, 0xa4, 0xd2,
                0x9e, 0xe0, 0x37, 0x25, 0xa6, 0xa4, 0xda, 0xfc, 0xd0, 0xfc, 0x67, 0xd2, 0xae, 0xa7,
                0x05, 0x29, 0x51, 0x3e, 0x3d, 0xa2, 0x67, 0x7f, 0xa5, 0x90, 0x6c, 0x5b, 0x3f, 0x7d,
                0x8f, 0x92, 0xf2, 0x28, 0xbd, 0xa4, 0x0d, 0xda, 0x72, 0x14, 0x70, 0xf9, 0xfb, 0xf2,
                0x97, 0xb5, 0xae, 0xa6, 0x17, 0x64, 0x6f, 0xac, 0x5c, 0x03, 0x27, 0x2e, 0x97, 0x07,
                0x27, 0xc6, 0x21, 0xa7, 0x91, 0x41, 0xef, 0x5f, 0x7d, 0xe6, 0x50, 0x5e, 0x5b, 0xfb,
                0xc3, 0x88, 0xe9, 0x33, 0x43, 0x69, 0x40, 0x93, 0x93, 0x4a, 0xe4, 0xd3, 0x57, 0x00,
                0x08, 0x00, 0x2a, 0x00, 0x04, 0x00, 0x00, 0x04, 0x00]

        static let oneRTTServerNewSessionTicketEncryptedPayload: [UInt8] =
                [0x3a, 0x6b, 0x8f, 0x90, 0x41, 0x4a, 0x97, 0xd6, 0x95,
                0x9c, 0x34, 0x87, 0x68, 0x0d, 0xe5, 0x13, 0x4a, 0x2b, 0x24, 0x0e, 0x6c, 0xff, 0xac,
                0x11, 0x6e, 0x95, 0xd4, 0x1d, 0x6a, 0xf8, 0xf6, 0xb5, 0x80, 0xdc, 0xf3, 0xd1, 0x1d,
                0x63, 0xc7, 0x58, 0xdb, 0x28, 0x9a, 0x01, 0x59, 0x40, 0x25, 0x2f, 0x55, 0x71, 0x3e,
                0x06, 0x1d, 0xc1, 0x3e, 0x07, 0x88, 0x91, 0xa3, 0x8e, 0xfb, 0xcf, 0x57, 0x53, 0xad,
                0x8e, 0xf1, 0x70, 0xad, 0x3c, 0x73, 0x53, 0xd1, 0x6d, 0x9d, 0xa7, 0x73, 0xb9, 0xca,
                0x7f, 0x2b, 0x9f, 0xa1, 0xb6, 0xc0, 0xd4, 0xa3, 0xd0, 0x3f, 0x75, 0xe0, 0x9c, 0x30,
                0xba, 0x1e, 0x62, 0x97, 0x2a, 0xc4, 0x6f, 0x75, 0xf7, 0xb9, 0x81, 0xbe, 0x63, 0x43,
                0x9b, 0x29, 0x99, 0xce, 0x13, 0x06, 0x46, 0x15, 0x13, 0x98, 0x91, 0xd5, 0xe4, 0xc5,
                0xb4, 0x06, 0xf1, 0x6e, 0x3f, 0xc1, 0x81, 0xa7, 0x7c, 0xa4, 0x75, 0x84, 0x00, 0x25,
                0xdb, 0x2f, 0x0a, 0x77, 0xf8, 0x1b, 0x5a, 0xb0, 0x5b, 0x94, 0xc0, 0x13, 0x46, 0x75,
                0x5f, 0x69, 0x23, 0x2c, 0x86, 0x51, 0x9d, 0x86, 0xcb, 0xee, 0xac, 0x87, 0xaa, 0xc3,
                0x47, 0xd1, 0x43, 0xf9, 0x60, 0x5d, 0x64, 0xf6, 0x50, 0xdb, 0x4d, 0x02, 0x3e, 0x70,
                0xe9, 0x52, 0xca, 0x49, 0xfe, 0x51, 0x37, 0x12, 0x1c, 0x74, 0xbc, 0x26, 0x97, 0x68,
                0x7e, 0x24, 0x87, 0x46, 0xd6, 0xdf, 0x35, 0x30, 0x05, 0xf3, 0xbc, 0xe1, 0x86, 0x96,
                0x12, 0x9c, 0x81, 0x53, 0x55, 0x6b, 0x3b, 0x6c, 0x67, 0x79, 0xb3, 0x7b, 0xf1, 0x59,
                0x85, 0x68, 0x4f]

    static let oneRTTServerNewSessionTicketFullRecord: [UInt8] =
                [0x17, 0x03, 0x03, 0x00, 0xde, 0x3a, 0x6b, 0x8f, 0x90, 0x41, 0x4a, 0x97, 0xd6, 0x95,
                0x9c, 0x34, 0x87, 0x68, 0x0d, 0xe5, 0x13, 0x4a, 0x2b, 0x24, 0x0e, 0x6c, 0xff, 0xac,
                0x11, 0x6e, 0x95, 0xd4, 0x1d, 0x6a, 0xf8, 0xf6, 0xb5, 0x80, 0xdc, 0xf3, 0xd1, 0x1d,
                0x63, 0xc7, 0x58, 0xdb, 0x28, 0x9a, 0x01, 0x59, 0x40, 0x25, 0x2f, 0x55, 0x71, 0x3e,
                0x06, 0x1d, 0xc1, 0x3e, 0x07, 0x88, 0x91, 0xa3, 0x8e, 0xfb, 0xcf, 0x57, 0x53, 0xad,
                0x8e, 0xf1, 0x70, 0xad, 0x3c, 0x73, 0x53, 0xd1, 0x6d, 0x9d, 0xa7, 0x73, 0xb9, 0xca,
                0x7f, 0x2b, 0x9f, 0xa1, 0xb6, 0xc0, 0xd4, 0xa3, 0xd0, 0x3f, 0x75, 0xe0, 0x9c, 0x30,
                0xba, 0x1e, 0x62, 0x97, 0x2a, 0xc4, 0x6f, 0x75, 0xf7, 0xb9, 0x81, 0xbe, 0x63, 0x43,
                0x9b, 0x29, 0x99, 0xce, 0x13, 0x06, 0x46, 0x15, 0x13, 0x98, 0x91, 0xd5, 0xe4, 0xc5,
                0xb4, 0x06, 0xf1, 0x6e, 0x3f, 0xc1, 0x81, 0xa7, 0x7c, 0xa4, 0x75, 0x84, 0x00, 0x25,
                0xdb, 0x2f, 0x0a, 0x77, 0xf8, 0x1b, 0x5a, 0xb0, 0x5b, 0x94, 0xc0, 0x13, 0x46, 0x75,
                0x5f, 0x69, 0x23, 0x2c, 0x86, 0x51, 0x9d, 0x86, 0xcb, 0xee, 0xac, 0x87, 0xaa, 0xc3,
                0x47, 0xd1, 0x43, 0xf9, 0x60, 0x5d, 0x64, 0xf6, 0x50, 0xdb, 0x4d, 0x02, 0x3e, 0x70,
                0xe9, 0x52, 0xca, 0x49, 0xfe, 0x51, 0x37, 0x12, 0x1c, 0x74, 0xbc, 0x26, 0x97, 0x68,
                0x7e, 0x24, 0x87, 0x46, 0xd6, 0xdf, 0x35, 0x30, 0x05, 0xf3, 0xbc, 0xe1, 0x86, 0x96,
                0x12, 0x9c, 0x81, 0x53, 0x55, 0x6b, 0x3b, 0x6c, 0x67, 0x79, 0xb3, 0x7b, 0xf1, 0x59,
                0x85, 0x68, 0x4f]

    static let oneRTTClientApplicationDataPayload: [UInt8] =
                [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
                0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29,
                0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31]

    static let oneRTTClientApplicationDataFullRecord: [UInt8] =
                [0x17, 0x03, 0x03, 0x00, 0x43, 0xa2, 0x3f, 0x70, 0x54, 0xb6, 0x2c, 0x94, 0xd0, 0xaf,
                0xfa, 0xfe, 0x82, 0x28, 0xba, 0x55, 0xcb, 0xef, 0xac, 0xea, 0x42, 0xf9, 0x14, 0xaa,
                0x66, 0xbc, 0xab, 0x3f, 0x2b, 0x98, 0x19, 0xa8, 0xa5, 0xb4, 0x6b, 0x39, 0x5b, 0xd5,
                0x4a, 0x9a, 0x20, 0x44, 0x1e, 0x2b, 0x62, 0x97, 0x4e, 0x1f, 0x5a, 0x62, 0x92, 0xa2,
                0x97, 0x70, 0x14, 0xbd, 0x1e, 0x3d, 0xea, 0xe6, 0x3a, 0xee, 0xbb, 0x21, 0x69, 0x49,
                0x15, 0xe4]

    static let oneRTTServerApplicationDataPayload: [UInt8] =
                [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
                0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29,
                0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31]

    static let oneRTTServerApplicationDataFullRecord: [UInt8] =
                [0x17, 0x03, 0x03, 0x00, 0x43, 0x2e, 0x93, 0x7e, 0x11, 0xef, 0x4a, 0xc7, 0x40, 0xe5,
                0x38, 0xad, 0x36, 0x00, 0x5f, 0xc4, 0xa4, 0x69, 0x32, 0xfc, 0x32, 0x25, 0xd0, 0x5f,
                0x82, 0xaa, 0x1b, 0x36, 0xe3, 0x0e, 0xfa, 0xf9, 0x7d, 0x90, 0xe6, 0xdf, 0xfc, 0x60,
                0x2d, 0xcb, 0x50, 0x1a, 0x59, 0xa8, 0xfc, 0xc4, 0x9c, 0x4b, 0xf2, 0xe5, 0xf0, 0xa2,
                0x1c, 0x00, 0x47, 0xc2, 0xab, 0xf3, 0x32, 0x54, 0x0d, 0xd0, 0x32, 0xe1, 0x67, 0xc2,
                0x95, 0x5d]

    static let oneRTTServerApplicationDataEncryptedPayload: [UInt8] =
                [0x2e, 0x93, 0x7e, 0x11, 0xef, 0x4a, 0xc7, 0x40, 0xe5,
                0x38, 0xad, 0x36, 0x00, 0x5f, 0xc4, 0xa4, 0x69, 0x32, 0xfc, 0x32, 0x25, 0xd0, 0x5f,
                0x82, 0xaa, 0x1b, 0x36, 0xe3, 0x0e, 0xfa, 0xf9, 0x7d, 0x90, 0xe6, 0xdf, 0xfc, 0x60,
                0x2d, 0xcb, 0x50, 0x1a, 0x59, 0xa8, 0xfc, 0xc4, 0x9c, 0x4b, 0xf2, 0xe5, 0xf0, 0xa2,
                0x1c, 0x00, 0x47, 0xc2, 0xab, 0xf3, 0x32, 0x54, 0x0d, 0xd0, 0x32, 0xe1, 0x67, 0xc2,
                0x95, 0x5d]

    static let oneRTTClientAlertPayload: [UInt8] = [0x01, 0x00]

    static let oneRTTClientAlertFullRecord: [UInt8] =
                [0x17, 0x03, 0x03, 0x00, 0x13, 0xc9, 0x87, 0x27, 0x60, 0x65, 0x56, 0x66, 0xb7, 0x4d,
                0x7f, 0xf1, 0x15, 0x3e, 0xfd, 0x6d, 0xb6, 0xd0, 0xb0, 0xe3]

    static let oneRTTServerAlertPayload: [UInt8] = [0x01, 0x00]

    static let oneRTTServerAlertFullRecord: [UInt8] =
                [0x17, 0x03, 0x03, 0x00, 0x13, 0xb5, 0x8f, 0xd6, 0x71, 0x66, 0xeb, 0xf5, 0x99, 0xd2,
                0x47, 0x20, 0xcf, 0xbe, 0x7e, 0xfa, 0x7a, 0x88, 0x64, 0xa9]

    static let oneRTTServerHandshakeWriteKey: [UInt8] =
                [0x3f, 0xce, 0x51, 0x60, 0x09, 0xc2, 0x17, 0x27, 0xd0, 0xf2, 0xe4, 0xe8, 0x6e, 0xe4,
                0x03, 0xbc]

    static let oneRTTServerHandshakeWriteIV: [UInt8] =
                [0x5d, 0x31, 0x3e, 0xb2, 0x67, 0x12, 0x76, 0xee, 0x13, 0x00, 0x0b, 0x30]

    static let oneRTTClientHandshakeWriteKey: [UInt8] =
                [0xdb, 0xfa, 0xa6, 0x93, 0xd1, 0x76, 0x2c, 0x5b, 0x66, 0x6a, 0xf5, 0xd9, 0x50, 0x25,
                0x8d, 0x01]

    static let oneRTTClientHandshakeWriteIV: [UInt8] =
                [0x5b, 0xd3, 0xc7, 0x1b, 0x83, 0x6e, 0x0b, 0x76, 0xbb, 0x73, 0x26, 0x5f]

    static let oneRTTServerApplicationDataWriteKey: [UInt8] =
                [0x9f, 0x02, 0x28, 0x3b, 0x6c, 0x9c, 0x07, 0xef, 0xc2, 0x6b, 0xb9, 0xf2, 0xac, 0x92,
                0xe3, 0x56]

    static let oneRTTServerApplicationDataIV: [UInt8] =
                [0xcf, 0x78, 0x2b, 0x88, 0xdd, 0x83, 0x54, 0x9a, 0xad, 0xf1, 0xe9, 0x84]

    static let oneRTTClientApplicationDataWriteKey: [UInt8] =
                [0x17, 0x42, 0x2d, 0xda, 0x59, 0x6e, 0xd5, 0xd9, 0xac, 0xd8, 0x90, 0xe3, 0xc6, 0x3f,
                0x50, 0x51]

    static let oneRTTClientApplicationDataWriteIV: [UInt8] =
                [0x5b, 0x78, 0x92, 0x3d, 0xee, 0x08, 0x57, 0x90, 0x33, 0xe5, 0x23, 0xd9]

    func testParseRecordNoBuffer() throws {
        XCTAssertEqual(recordParser.numberOfBytesBuffered, 0)
        XCTAssertNil(try recordParser.parsePlaintextRecord())
    }

    func testParseRecordShortBuffer() throws {
        var buf = ByteBuffer(bytes: [0x16, 0x03, 0x01, 0x01])
        recordParser.appendBytes(&buf)
        XCTAssertEqual(recordParser.numberOfBytesBuffered, 4)
        XCTAssertNil(try recordParser.parsePlaintextRecord())
        XCTAssertEqual(recordParser.numberOfBytesBuffered, 4)
    }

    func testParseUnknownProtocolVersion() throws {
        var buf = ByteBuffer(bytes: [0x16, 0x03, 0x05, 0x00, 0x00])
        recordParser.appendBytes(&buf)
        XCTAssertEqual(recordParser.numberOfBytesBuffered, 5)
        XCTAssertNoThrow(try recordParser.parsePlaintextRecord())
        XCTAssertEqual(recordParser.numberOfBytesBuffered, 0)
    }

    func testParseUnknownContentType() throws {
        var buf = ByteBuffer(bytes: [0x07, 0x03, 0x01, 0x00, 0x00])
        recordParser.appendBytes(&buf)
        XCTAssertEqual(recordParser.numberOfBytesBuffered, 5)
        XCTAssertNoThrow(try recordParser.parsePlaintextRecord())
        XCTAssertEqual(recordParser.numberOfBytesBuffered, 0)
    }

    func testParseRecordContentLengthTooLarge() throws {
        let contentType = ContentType.handshake
        let legacyProtocolVersion = ProtocolVersion.tlsv10
        let actualContentLength = RecordParsingTests.oneRTTClientHelloPayload.count
        buffer.writeContentType(contentType)
        buffer.writeProtocolVersion(legacyProtocolVersion)
        buffer.writeInteger(UInt16(actualContentLength + 1), as: UInt16.self) // make slightly too large
        buffer.writeBytes(RecordParsingTests.oneRTTClientHelloPayload)
        recordParser.appendBytes(&buffer)
        // parser returns nil because it does not yet have a full record to read according to content length
        XCTAssertNil(try recordParser.parsePlaintextRecord())
        XCTAssertEqual(recordParser.numberOfBytesBuffered, RecordParsingTests.oneRTTClientHelloFullRecord.count)
        // writing one more byte will allow the parser to parse the record
        buffer.writeBytes(Array([0x01]))
        recordParser.appendBytes(&buffer)
        guard let _ = try recordParser.parsePlaintextRecord() else {
            XCTFail("failed to parse record")
            return
        }
        XCTAssertEqual(recordParser.numberOfBytesBuffered, 0)
    }

    func testParseRecordContentLengthTooSmall() throws {
        let contentType = ContentType.handshake
        let legacyProtocolVersion = ProtocolVersion.tlsv10
        let payload = RecordParsingTests.oneRTTClientHelloPayload
        let actualContentLength = payload.count
        buffer.writeContentType(contentType)
        buffer.writeProtocolVersion(legacyProtocolVersion)
        buffer.writeInteger(UInt16(actualContentLength - 1), as: UInt16.self) // make slightly too small
        buffer.writeBytes(payload)
        recordParser.appendBytes(&buffer)
        XCTAssertEqual(recordParser.numberOfBytesBuffered, RecordParsingTests.oneRTTClientHelloFullRecord.count)
        guard let plainText = try recordParser.parsePlaintextRecord() else {
            XCTFail("failed to parse record")
            return
        }
        XCTAssertEqual(recordParser.numberOfBytesBuffered, 1)
        var contentCopy = ByteBuffer(data: Data(plainText.content))
        messageParser.appendBytes(&contentCopy)
        // can't parse the client hello yet because only N-1 bytes received by messageParser
        XCTAssertNil(try messageParser.parseHandshakeMessage())
    }

    func testParseUnprotectedApplicationDataFails() throws {
        let contentType = ContentType.applicationData // set to application data
        let legacyProtocolVersion = ProtocolVersion.tlsv10
        let payload = RecordParsingTests.oneRTTClientHelloPayload
        let actualContentLength = payload.count
        buffer.writeContentType(contentType)
        buffer.writeProtocolVersion(legacyProtocolVersion)
        buffer.writeInteger(UInt16(actualContentLength), as: UInt16.self)
        buffer.writeBytes(payload)
        recordParser.appendBytes(&buffer)
        XCTAssertEqual(recordParser.numberOfBytesBuffered, RecordParsingTests.oneRTTClientHelloFullRecord.count)
        XCTAssertThrowsError(try recordParser.parsePlaintextRecord()) { error in XCTAssertEqual(error as? TLSError, TLSError.decodeError)
        }
    }

    func testParseTooLargePlaintextFails() throws {
        let contentType = ContentType.handshake
        let legacyProtocolVersion = ProtocolVersion.tlsv10
        let payload = RecordParsingTests.oneRTTClientHelloPayload
        buffer.writeContentType(contentType)
        buffer.writeProtocolVersion(legacyProtocolVersion)
        buffer.writeInteger(maxPlaintextFragmentLength + 1, as: UInt16.self)
        buffer.writeBytes(payload)
        recordParser.appendBytes(&buffer)
        XCTAssertEqual(recordParser.numberOfBytesBuffered, RecordParsingTests.oneRTTClientHelloFullRecord.count)
        XCTAssertThrowsError(try recordParser.parsePlaintextRecord()) { error in XCTAssertEqual(error as? TLSError, TLSError.recordOverflow)
        }
    }

    func testParseTooLargeCiphertextFails() throws {
        let contentType = ContentType.handshake
        let legacyProtocolVersion = ProtocolVersion.tlsv12
        let payload = RecordParsingTests.oneRTTServerSecondFlightPayload
        buffer.writeContentType(contentType)
        buffer.writeProtocolVersion(legacyProtocolVersion)
        buffer.writeInteger(maxCiphertextEncryptedRecordLength + 1, as: UInt16.self)
        buffer.writeBytes(payload)
        recordParser.appendBytes(&buffer)
        XCTAssertEqual(recordParser.numberOfBytesBuffered, RecordParsingTests.oneRTTServerSecondFlightPayload.count + 5)
        XCTAssertThrowsError(try recordParser.parseCiphertextRecord()) { error in XCTAssertEqual(error as? TLSError, TLSError.recordOverflow)
        }
    }

    func testParseTooLargeInnerPlaintextFails() throws {
        let key = SymmetricKey(size: SymmetricKeySize.bits128)
        let nonce = Nonce([12 of UInt8](repeating: 0).span.bytes)
        let plaintext = [UInt8](repeating: 2, count: Int(maxPlaintextFragmentLength) + 1)
        let innerPlaintext = TLSInnerPlaintext(content: plaintext.span.bytes, contentType: .handshake, paddingLength: 0)
        let ad = additionalData(ciphertextLength: innerPlaintext.length + TLSRecordProtector.aesTagLengthBytes)
        let ciphertextRecord = try TLSCiphertext(writeKey: key, nonce: nonce, innerPlaintext:innerPlaintext, additionalData: ad.span.bytes)
        buffer.writeRecord(ciphertextRecord)
        recordParser.appendBytes(&buffer)
        guard let ciphertext = try recordParser.parseCiphertextRecord() else {
            XCTFail()
            return
        }
        XCTAssertThrowsError(try ciphertext.deprotect(peerWriteKey: key, nonce: nonce, aeadExpansionLength: TLSRecordProtector.aesTagLengthBytes)) { error in XCTAssertEqual(error as? TLSError, TLSError.recordOverflow)}
    }

    func testParseMaxLengthCiphertextPasses() throws {
        let key = SymmetricKey(size: SymmetricKeySize.bits128)
        let nonce = Nonce([12 of UInt8](repeating: 0).span.bytes)
        let plaintext = [UInt8](repeating: 2, count: Int(maxPlaintextFragmentLength))
        let innerPlaintext = TLSInnerPlaintext(content: plaintext.span.bytes, contentType: .handshake, paddingLength: 0)
        let ad = additionalData(ciphertextLength: innerPlaintext.length + TLSRecordProtector.aesTagLengthBytes)
        let ciphertextRecord = try TLSCiphertext(writeKey: key, nonce: nonce, innerPlaintext:innerPlaintext, additionalData: ad.span.bytes)
        buffer.writeRecord(ciphertextRecord)
        recordParser.appendBytes(&buffer)
        guard let ciphertext = try recordParser.parseCiphertextRecord() else {
            XCTFail()
            return
        }
        XCTAssertNoThrow(try ciphertext.deprotect(peerWriteKey: key, nonce: nonce, aeadExpansionLength: TLSRecordProtector.aesTagLengthBytes))
    }

    func runTLSParserFullRecord(fullRecord: inout ByteBuffer) throws {
        recordParser.appendBytes(&fullRecord)
        XCTAssertEqual(recordParser.numberOfBytesBuffered, fullRecord.readableBytes)
        guard let plainText = try recordParser.parsePlaintextRecord() else {
            XCTFail("failed to parse record")
            return
        }
        var contentCopy = ByteBuffer(data: Data(plainText.content))
        messageParser.appendBytes(&contentCopy)
        // the whole message is in one record
        guard let message = try messageParser.parseHandshakeMessage(), case .clientHello(_) = message else {
            XCTFail("failed to parse client hello message")
            return
        }
        _ = try messageParser.parseHandshakeMessage()
        XCTAssertEqual(recordParser.numberOfBytesBuffered, 0)
    }

    func testParseClientHelloFullRecordSuccess() throws {
        recordParser.appendBytes(RecordParsingTests.oneRTTClientHelloFullRecord)
        XCTAssertEqual(recordParser.numberOfBytesBuffered, RecordParsingTests.oneRTTClientHelloFullRecord.count)
        guard let plainText = try recordParser.parsePlaintextRecord() else {
            XCTFail("failed to parse record")
            return
        }
        var contentCopy = ByteBuffer(data: Data(plainText.content))
        messageParser.appendBytes(&contentCopy)
        // the whole message is in one record
        guard let message = try messageParser.parseHandshakeMessage(), case .clientHello(_) = message else {
            XCTFail("failed to parse client hello message")
            return
        }
        _ = try messageParser.parseHandshakeMessage()
        XCTAssertEqual(recordParser.numberOfBytesBuffered, 0)
    }

    func testParseThreeGoodRecords() throws {
        var totalBytes = RecordParsingTests.oneRTTClientHelloFullRecord.count
        recordParser.appendBytes(RecordParsingTests.oneRTTClientHelloFullRecord)

        totalBytes += RecordParsingTests.oneRTTServerHelloFullRecord.count
        recordParser.appendBytes(RecordParsingTests.oneRTTServerHelloFullRecord)

        totalBytes += RecordParsingTests.oneRTTServerSecondFlightFullRecord.count
        recordParser.appendBytes(RecordParsingTests.oneRTTServerSecondFlightFullRecord)

        XCTAssertEqual(recordParser.numberOfBytesBuffered, totalBytes)
        guard let plainText = try recordParser.parsePlaintextRecord() else {
            XCTFail("failed to parse record")
            return
        }
        var contentCopy = ByteBuffer(data: Data(plainText.content))
        messageParser.appendBytes(&contentCopy)
        guard let plainText = try recordParser.parsePlaintextRecord() else {
            XCTFail("failed to parse record")
            return
        }
        contentCopy = ByteBuffer(data: Data(plainText.content))
        messageParser.appendBytes(&contentCopy)
        guard let _ = try recordParser.parseCiphertextRecord() else {
            XCTFail("failed to parse record")
            return
        }
        XCTAssertEqual(recordParser.numberOfBytesBuffered, 0)
    }

    func testParseServerHelloFullRecordSuccess() throws {
        recordParser.appendBytes(RecordParsingTests.oneRTTServerHelloFullRecord)
        XCTAssertEqual(recordParser.numberOfBytesBuffered, RecordParsingTests.oneRTTServerHelloFullRecord.count)
        guard let plainText = try recordParser.parsePlaintextRecord() else {
            XCTFail("failed to parse record")
            return
        }
        var contentCopy = ByteBuffer(data: Data(plainText.content))
        messageParser.appendBytes(&contentCopy)
        // the whole message is in one record
        guard let message = try messageParser.parseHandshakeMessage(), case .serverHello(_) = message else {
            XCTFail("failed to parse server hello message")
            return
        }
        XCTAssertEqual(recordParser.numberOfBytesBuffered, 0)
    }

    func testParseServerSecondFlightFullRecordSuccess() throws {
        // the record contains the EE, Certificate, CertificateVerify, and Finished messages
        recordParser.appendBytes(RecordParsingTests.oneRTTServerSecondFlightFullRecord)
        XCTAssertEqual(recordParser.numberOfBytesBuffered, RecordParsingTests.oneRTTServerSecondFlightFullRecord.count)
        guard let cipherText = try recordParser.parseCiphertextRecord() else {
            XCTFail("failed to parse record")
            return
        }
        XCTAssertEqual(recordParser.numberOfBytesBuffered, 0)

        let key = SymmetricKey(data: RecordParsingTests.oneRTTServerHandshakeWriteKey)
        let serverIV: [UInt8] = RecordParsingTests.oneRTTServerHandshakeWriteIV
        let nonce = calculateTLSRecordNonce(iv: serverIV, seqno: 0)
        let deprotectedRecord = try cipherText.deprotect(peerWriteKey: key, nonce: nonce, aeadExpansionLength: TLSRecordProtector.aesTagLengthBytes)

        messageParser.appendBytes(deprotectedRecord.fragment)
        guard let message = try messageParser.parseHandshakeMessage(), case .encryptedExtensions(_) = message else {
            XCTFail("failed to parse server EE")
            return
        }
        guard let message = try messageParser.parseHandshakeMessage(), case .certificate(_) = message else {
            XCTFail("failed to parse server certificate")
            return
        }
        guard let message = try messageParser.parseHandshakeMessage(), case .certificateVerify(_) = message else {
            XCTFail("failed to parse server certificate verify")
            return
        }
        guard let message = try messageParser.parseHandshakeMessage(), case .finished(_) = message else {
            XCTFail("failed to parse server finished")
            return
        }
    }

    func testSerializePlaintextRecord() throws {
        let record = TLSPlaintext(contentType: .handshake, protocolVersion: .tlsv10, fragment: RecordParsingTests.oneRTTClientHelloPayload)
        var buffer = ByteBuffer(bytes: [])
        buffer.writeRecord(record)
        XCTAssertEqual(buffer, ByteBuffer(bytes: RecordParsingTests.oneRTTClientHelloFullRecord))
    }

    func testSerializeCiphertextRecord() throws {
        let record = TLSCiphertext(encryptedRecord: RecordParsingTests.oneRTTServerSecondFlightEncryptedPayload)
        var buffer = ByteBuffer(bytes: [])
        buffer.writeRecord(record)
        XCTAssertEqual(buffer, ByteBuffer(bytes: RecordParsingTests.oneRTTServerSecondFlightFullRecord))
    }

    func testProtectAndDeprotectBasic() throws {
        let key = SymmetricKey(size: SymmetricKeySize.bits128)
        let nonce = Nonce([12 of UInt8](repeating: 0).span.bytes)
        let plaintext: [UInt8] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06]
        let innerPlaintext = TLSInnerPlaintext(content: plaintext.span.bytes, contentType: .handshake, paddingLength: 0)
        let ad = additionalData(ciphertextLength: innerPlaintext.length + TLSRecordProtector.aesTagLengthBytes)
        let ciphertextRecord = try TLSCiphertext(writeKey: key, nonce: nonce, innerPlaintext:innerPlaintext, additionalData: ad.span.bytes)
        let result = try ciphertextRecord.deprotect(peerWriteKey: key, nonce: nonce, aeadExpansionLength: TLSRecordProtector.aesTagLengthBytes)
        XCTAssertEqual(plaintext, result.fragment)
    }

    func testProtectAndDeprotectServerSecondFlight() throws {
        let key = SymmetricKey(data: RecordParsingTests.oneRTTServerHandshakeWriteKey)
        let server_iv: [UInt8] = RecordParsingTests.oneRTTServerHandshakeWriteIV
        let nonce = calculateTLSRecordNonce(iv: server_iv, seqno: 0)
        let innerPlaintext = TLSInnerPlaintext(content: RecordParsingTests.oneRTTServerSecondFlightPayload.span.bytes, contentType: .handshake, paddingLength: 0)
        let ad = additionalData(ciphertextLength: innerPlaintext.length + TLSRecordProtector.aesTagLengthBytes)
        let cipherText = try TLSCiphertext(writeKey: key, nonce: nonce, innerPlaintext:innerPlaintext, additionalData: ad.span.bytes)

        let result = try cipherText.deprotect(peerWriteKey: key, nonce: nonce, aeadExpansionLength: TLSRecordProtector.aesTagLengthBytes)
        XCTAssertEqual(RecordParsingTests.oneRTTServerSecondFlightPayload, result.fragment)
    }

    func testDeprotect() throws {
        let key = SymmetricKey(data: RecordParsingTests.oneRTTServerHandshakeWriteKey)
        let server_iv: [UInt8] = RecordParsingTests.oneRTTServerHandshakeWriteIV
        let nonce = calculateTLSRecordNonce(iv: server_iv, seqno: 0)

        recordParser.appendBytes(RecordParsingTests.oneRTTServerSecondFlightFullRecord)
        XCTAssertEqual(recordParser.numberOfBytesBuffered, RecordParsingTests.oneRTTServerSecondFlightFullRecord.count)
        guard let cipherText = try recordParser.parseCiphertextRecord() else {
            XCTFail("failed to parse record")
            return
        }
        let result = try cipherText.deprotect(peerWriteKey: key, nonce: nonce, aeadExpansionLength: TLSRecordProtector.aesTagLengthBytes)
        XCTAssertEqual(RecordParsingTests.oneRTTServerSecondFlightPayload, result.fragment)
    }

    func testProtectAndDeprotectRecordWithPadding() throws {
        // unfortunately no traces for records with padding, so making one here
        let key = SymmetricKey(data: RecordParsingTests.oneRTTServerHandshakeWriteKey)
        let server_iv: [UInt8] = RecordParsingTests.oneRTTServerHandshakeWriteIV
        let nonce = calculateTLSRecordNonce(iv: server_iv, seqno: 0)
        let innerPlaintext = TLSInnerPlaintext(content: RecordParsingTests.oneRTTServerSecondFlightPayload.span.bytes, contentType: .handshake, paddingLength: 5)
        let ad = additionalData(ciphertextLength: innerPlaintext.length + TLSRecordProtector.aesTagLengthBytes)
        let cipherText = try TLSCiphertext(writeKey: key, nonce: nonce, innerPlaintext:innerPlaintext, additionalData: ad.span.bytes)

        let result = try cipherText.deprotect(peerWriteKey: key, nonce: nonce, aeadExpansionLength: TLSRecordProtector.aesTagLengthBytes)
        XCTAssertEqual(RecordParsingTests.oneRTTServerSecondFlightPayload, result.fragment)
    }

    // Protect `content` and serialize the resulting record -- header and all --
    // so a test can tamper with the header bytes before parsing them back.
    private func protectedRecordBytes(key: SymmetricKey, nonce: Nonce, content: [UInt8]) throws -> [UInt8] {
        let innerPlaintext = TLSInnerPlaintext(content: content.span.bytes, contentType: .applicationData, paddingLength: 0)
        let ad = additionalData(ciphertextLength: innerPlaintext.length + TLSRecordProtector.aesTagLengthBytes)
        let record = try TLSCiphertext(writeKey: key, nonce: nonce, innerPlaintext: innerPlaintext, additionalData: ad.span.bytes)
        var buffer = ByteBuffer()
        buffer.writeRecord(record)
        guard let bytes = buffer.readBytes(length: buffer.readableBytes) else {
            throw TLSError.internalError(reason: "failed to serialize protected record")
        }
        return bytes
    }

    // Control for the two tampering tests below: an untouched record still
    // deprotects to the original fragment.
    func testUnmodifiedRecordHeaderDeprotects() throws {
        let key = SymmetricKey(data: RecordParsingTests.oneRTTServerHandshakeWriteKey)
        let nonce = calculateTLSRecordNonce(iv: RecordParsingTests.oneRTTServerHandshakeWriteIV, seqno: 0)
        let content = [UInt8]("record payload".utf8)
        let record = try protectedRecordBytes(key: key, nonce: nonce, content: content)
        XCTAssertEqual(record[0], ContentType.applicationData.rawValue)

        recordParser.appendBytes(record)
        guard let ciphertext = try recordParser.parseCiphertextRecord() else {
            XCTFail("failed to parse record")
            return
        }
        let result = try ciphertext.deprotect(peerWriteKey: key, nonce: nonce, aeadExpansionLength: TLSRecordProtector.aesTagLengthBytes)
        XCTAssertEqual(result.fragment, content)
        XCTAssertEqual(result.actualContentType, .applicationData)
    }

    // Ensure the AEAD additional_data is the record header as received, so that
    // rewriting the outer content type in transit breaks authentication instead
    // of being silently accepted.
    //
    // RFC 9846 §5.2: "additional_data = TLSCiphertext.opaque_type ||
    // TLSCiphertext.legacy_record_version || TLSCiphertext.length" and "If
    // decryption fails, the receiver MUST terminate the connection with a
    // 'bad_record_mac' alert."
    func testTamperedOuterContentTypeFailsDeprotection() throws {
        let key = SymmetricKey(data: RecordParsingTests.oneRTTServerHandshakeWriteKey)
        let nonce = calculateTLSRecordNonce(iv: RecordParsingTests.oneRTTServerHandshakeWriteIV, seqno: 0)
        var record = try protectedRecordBytes(key: key, nonce: nonce, content: [UInt8]("record payload".utf8))

        // application_data(23) -> alert(21)
        record[0] = ContentType.alert.rawValue

        recordParser.appendBytes(record)
        guard let ciphertext = try recordParser.parseCiphertextRecord() else {
            XCTFail("failed to parse record")
            return
        }
        XCTAssertThrowsError(try ciphertext.deprotect(peerWriteKey: key, nonce: nonce, aeadExpansionLength: TLSRecordProtector.aesTagLengthBytes)) { error in
            XCTAssertEqual(error as? TLSError, .badRecordMac)
        }
    }

    // As above, for the legacy_record_version bytes of the received header.
    //
    // RFC 9846 §5.2: "The value of TLSCiphertext.legacy_record_version is
    // included in the additional data for deprotection."
    func testTamperedLegacyRecordVersionFailsDeprotection() throws {
        let key = SymmetricKey(data: RecordParsingTests.oneRTTServerHandshakeWriteKey)
        let nonce = calculateTLSRecordNonce(iv: RecordParsingTests.oneRTTServerHandshakeWriteIV, seqno: 0)
        var record = try protectedRecordBytes(key: key, nonce: nonce, content: [UInt8]("record payload".utf8))

        // 0x0303 -> 0xabcd
        record[1] = 0xab
        record[2] = 0xcd

        recordParser.appendBytes(record)
        guard let ciphertext = try recordParser.parseCiphertextRecord() else {
            XCTFail("failed to parse record")
            return
        }
        XCTAssertThrowsError(try ciphertext.deprotect(peerWriteKey: key, nonce: nonce, aeadExpansionLength: TLSRecordProtector.aesTagLengthBytes)) { error in
            XCTAssertEqual(error as? TLSError, .badRecordMac)
        }
    }

    // A peer that authenticates a non-application_data outer type produces a
    // record that passes AEAD authentication but still carries an outer type
    // TLSCiphertext is never allowed to have.
    //
    // RFC 9846 §5: "If a TLS implementation receives an unexpected record type,
    // it MUST terminate the connection with an 'unexpected_message' alert."
    func testAuthenticatedNonApplicationDataOuterTypeIsRejected() throws {
        let key = SymmetricKey(data: RecordParsingTests.oneRTTServerHandshakeWriteKey)
        let nonce = calculateTLSRecordNonce(iv: RecordParsingTests.oneRTTServerHandshakeWriteIV, seqno: 0)
        let content = [UInt8]("record payload".utf8)
        let innerPlaintext = TLSInnerPlaintext(content: content.span.bytes, contentType: .applicationData, paddingLength: 0)
        let ciphertextLength = innerPlaintext.length + TLSRecordProtector.aesTagLengthBytes

        // Build the additional data over an outer type of handshake(22) rather
        // than the mandated application_data(23).
        var adBuffer = ByteBuffer()
        adBuffer.writeContentType(.handshake)
        adBuffer.writeProtocolVersion(.tlsv12)
        adBuffer.writeInteger(UInt16(ciphertextLength), as: UInt16.self)
        guard let ad = adBuffer.readBytes(length: adBuffer.readableBytes) else {
            XCTFail("failed to build additional data")
            return
        }
        let record = try TLSCiphertext(writeKey: key, nonce: nonce, innerPlaintext: innerPlaintext, additionalData: ad.span.bytes)

        // Serialize with a matching handshake(22) header so the AEAD verifies.
        buffer.writeContentType(.handshake)
        buffer.writeProtocolVersion(.tlsv12)
        buffer.writeInteger(UInt16(record.encryptedRecord.count), as: UInt16.self)
        buffer.writeBytes(record.encryptedRecord)
        recordParser.appendBytes(&buffer)

        guard let ciphertext = try recordParser.parseCiphertextRecord() else {
            XCTFail("failed to parse record")
            return
        }
        XCTAssertThrowsError(try ciphertext.deprotect(peerWriteKey: key, nonce: nonce, aeadExpansionLength: TLSRecordProtector.aesTagLengthBytes)) { error in
            XCTAssertEqual(error as? TLSError, .handshakeUnexpectedMessage)
        }
    }

    // Ensure TLSInnerPlaintext does not exceed 2^14 + 1 octets, even if
    // the plaintext fragment is less than 2^14 + 1 octets.
    //
    // RFC 9846 §5.4: "the full encoded TLSInnerPlaintext MUST NOT exceed
    // 2^14 + 1 octets."
    func testProtectRejectsInnerPlaintextExceedingMaxPlaintextFragmentLengthPlusOne() throws {
        let key = SymmetricKey(size: .bits128)
        let iv = [UInt8](repeating: 0, count: TLSRecordProtector.IVlengthBytes)
        var protector = try TLSRecordProtector(writeKey: key, writeIV: iv, ciphersuite: .TLS_AES_128_GCM_SHA256)

        // innerPlaintext.length = 16384 + 1 (type) + 200 (padding) = 16585,
        // which exceeds maxPlaintextFragmentLength + 1 (16385); the overall
        // ciphertext (16585 + 16 tag = 16601) is still under
        // maxCiphertextEncryptedRecordLength (16640).
        let content = [UInt8](repeating: 0xAB, count: Int(maxPlaintextFragmentLength))
        XCTAssertThrowsError(try protector.protect(plaintext: content.span.bytes, actualContentType: .handshake, paddingLength: 200)) { error in
            guard let tlsError = error as? TLSError, case .internalError = tlsError else {
                XCTFail("expected TLSError.internalError, got \(error)")
                return
            }
        }
    }

    // Ensure we permit innerPlaintext.length = 2^14 + 1
    //
    // RFC 9846 §5.4: "the full encoded TLSInnerPlaintext MUST NOT exceed
    // 2^14 + 1 octets."
    func testProtectAllowsInnerPlaintextAtExactlyMaxPlaintextFragmentLengthPlusOne() throws {
        let key = SymmetricKey(size: .bits128)
        let iv = [UInt8](repeating: 0, count: TLSRecordProtector.IVlengthBytes)
        var protector = try TLSRecordProtector(writeKey: key, writeIV: iv, ciphersuite: .TLS_AES_128_GCM_SHA256)

        let content = [UInt8](repeating: 0xAB, count: Int(maxPlaintextFragmentLength))
        XCTAssertNoThrow(try protector.protect(plaintext: content.span.bytes, actualContentType: .handshake, paddingLength: 0))
    }

    // Ensure padding octets are set to all zeros before encrypting. To check
    // this, decrypt the record with CryptoKit AES.GCM and not deprotect()
    // so we can recover and inspect padding bytes. Use CryptoKit because
    // deprotect() will strip padding bytes before returning.
    //
    // RFC 9846 §5.4: "Padding octets MUST be set to all zeros before
    // encrypting."
    func testProtectZeroesOutPaddingBeforeEncrypting() throws {
        let key = SymmetricKey(data: RecordParsingTests.oneRTTServerHandshakeWriteKey)
        let server_iv: [UInt8] = RecordParsingTests.oneRTTServerHandshakeWriteIV
        let nonce = calculateTLSRecordNonce(iv: server_iv, seqno: 0)
        let content = RecordParsingTests.oneRTTServerSecondFlightPayload
        let paddingLength = 5
        let innerPlaintext = TLSInnerPlaintext(content: content.span.bytes, contentType: .handshake, paddingLength: paddingLength)
        let ad = additionalData(ciphertextLength: innerPlaintext.length + TLSRecordProtector.aesTagLengthBytes)
        let cipherText = try TLSCiphertext(writeKey: key, nonce: nonce, innerPlaintext: innerPlaintext, additionalData: ad.span.bytes)

        let nonceBytes = [UInt8](copying: nonce.bytes)
        let cryptoKitNonce = try AES.GCM.Nonce(data: Data(nonceBytes))

        let tagSize = TLSRecordProtector.aesTagLengthBytes
        let encryptedRecord = cipherText.encryptedRecord
        let rawCiphertext = Data(encryptedRecord.prefix(encryptedRecord.count - tagSize))
        let tag = Data(encryptedRecord.suffix(tagSize))
        let sealedBox = try AES.GCM.SealedBox(nonce: cryptoKitNonce, ciphertext: rawCiphertext, tag: tag)
        let rawPlaintext = [UInt8](try AES.GCM.open(sealedBox, using: key, authenticating: [UInt8](copying: ad.span.bytes)))

        // rawPlaintext = content || content-type byte || padding, untouched.
        XCTAssertEqual(rawPlaintext.count, content.count + 1 + paddingLength)
        XCTAssertEqual(rawPlaintext[content.count], ContentType.handshake.rawValue)
        for i in (content.count + 1)..<rawPlaintext.count {
            XCTAssertEqual(rawPlaintext[i], 0, "padding byte at offset \(i - content.count - 1) was not zero")
        }
    }

    func testProtect() throws {
        let key = SymmetricKey(data: RecordParsingTests.oneRTTServerHandshakeWriteKey)
        let server_iv: [UInt8] = RecordParsingTests.oneRTTServerHandshakeWriteIV
        let nonce = calculateTLSRecordNonce(iv: server_iv, seqno: 0)
        let innerPlaintext = TLSInnerPlaintext(content: RecordParsingTests.oneRTTServerSecondFlightPayload.span.bytes, contentType: .handshake, paddingLength: 0)
        let ad = additionalData(ciphertextLength: innerPlaintext.length + TLSRecordProtector.aesTagLengthBytes)
        let cipherText = try TLSCiphertext(writeKey: key, nonce: nonce, innerPlaintext:innerPlaintext, additionalData: ad.span.bytes)

        recordParser.appendBytes(RecordParsingTests.oneRTTServerSecondFlightFullRecord)
        XCTAssertEqual(recordParser.numberOfBytesBuffered, RecordParsingTests.oneRTTServerSecondFlightFullRecord.count)
        guard let cipherTextTwo = try recordParser.parseCiphertextRecord() else {
            XCTFail("failed to parse record")
            return
        }
        XCTAssertEqual(cipherText.encryptedRecord.count, cipherTextTwo.encryptedRecord.count)
        XCTAssertEqual(cipherText.encryptedRecord, cipherTextTwo.encryptedRecord)

        let result = try cipherText.deprotect(peerWriteKey: key, nonce: nonce, aeadExpansionLength: TLSRecordProtector.aesTagLengthBytes)
        XCTAssertEqual(RecordParsingTests.oneRTTServerSecondFlightPayload, result.fragment)
        var fullRecord = ByteBuffer()
        fullRecord.writeRecord(cipherText)
        XCTAssertEqual(fullRecord, ByteBuffer(bytes: RecordParsingTests.oneRTTServerSecondFlightFullRecord))
    }

    func testTLSRecordProtector() throws {
        // One RTT HS from server second flight (first encrypted record with handshake secret seqno = 0)
        var serverHSWriteKey = SymmetricKey(data: RecordParsingTests.oneRTTServerHandshakeWriteKey)
        var serverHSIV: [UInt8] = RecordParsingTests.oneRTTServerHandshakeWriteIV

        var clientHSWriteKey = SymmetricKey(data: RecordParsingTests.oneRTTClientHandshakeWriteKey)
        var clientHSIV: [UInt8] = RecordParsingTests.oneRTTClientHandshakeWriteIV

        var serverProtector = try TLSRecordProtector(
                                    writeKey: serverHSWriteKey,
                                    writeIV: serverHSIV,
                                    readKey: clientHSWriteKey,
                                    readIV: clientHSIV,
                                    ciphersuite: .TLS_AES_128_GCM_SHA256)
        var clientProtector = try TLSRecordProtector(
                                    writeKey: clientHSWriteKey,
                                    writeIV: clientHSIV,
                                    readKey: serverHSWriteKey,
                                    readIV: serverHSIV,
                                    ciphersuite: .TLS_AES_128_GCM_SHA256)

        // server --> client, handshake content type, hs traffic keys, seqno = 0
        var ciphertext = try serverProtector.protect(plaintext: RecordParsingTests.oneRTTServerSecondFlightPayload.span.bytes, actualContentType: .handshake)
        XCTAssertEqual(ciphertext.encryptedRecord, RecordParsingTests.oneRTTServerSecondFlightEncryptedPayload)
        var deprotectedRecord = try clientProtector.deprotect(ciphertext: ciphertext)
        XCTAssertEqual(deprotectedRecord.actualContentType, .handshake)
        XCTAssertEqual(deprotectedRecord.fragment, RecordParsingTests.oneRTTServerSecondFlightPayload)

        // client --> server, handshake content type, hs traffic keys, seqno = 0
        ciphertext = try clientProtector.protect(plaintext: RecordParsingTests.oneRTTClientSecondFlightHSPayload.span.bytes, actualContentType: .handshake)
        XCTAssertEqual(ciphertext.encryptedRecord, Array(RecordParsingTests.oneRTTClientSecondFlightHSFullRecord.suffix(from: 5)))
        deprotectedRecord = try serverProtector.deprotect(ciphertext: ciphertext)
        XCTAssertEqual(deprotectedRecord.actualContentType, .handshake)
        XCTAssertEqual(deprotectedRecord.fragment, RecordParsingTests.oneRTTClientSecondFlightHSPayload)

        // update server write keys (client read keys)
        serverHSWriteKey = SymmetricKey(data: RecordParsingTests.oneRTTServerApplicationDataWriteKey)
        serverHSIV = RecordParsingTests.oneRTTServerApplicationDataIV
        try serverProtector.updateWriteKeyAndIV(serverHSWriteKey, serverHSIV)
        try clientProtector.updateReadKeyAndIV(serverHSWriteKey, serverHSIV)

        // server --> client, handshake content type, application traffic keys, seqno = 0
        ciphertext = try serverProtector.protect(plaintext: RecordParsingTests.oneRTTServerNewSessionTicketPayload.span.bytes, actualContentType: .handshake)
        XCTAssertEqual(ciphertext.encryptedRecord, RecordParsingTests.oneRTTServerNewSessionTicketEncryptedPayload)
        deprotectedRecord = try clientProtector.deprotect(ciphertext: ciphertext)
        XCTAssertEqual(deprotectedRecord.actualContentType, .handshake)
        XCTAssertEqual(deprotectedRecord.fragment, RecordParsingTests.oneRTTServerNewSessionTicketPayload)

        // update client write keys (server read keys)
        clientHSWriteKey = SymmetricKey(data: RecordParsingTests.oneRTTClientApplicationDataWriteKey)
        clientHSIV = RecordParsingTests.oneRTTClientApplicationDataWriteIV
        try clientProtector.updateWriteKeyAndIV(clientHSWriteKey, clientHSIV)
        try serverProtector.updateReadKeyAndIV(clientHSWriteKey, clientHSIV)

        // client --> server, application content type, application traffic keys, seqno = 0
        ciphertext = try clientProtector.protect(plaintext: RecordParsingTests.oneRTTClientApplicationDataPayload.span.bytes, actualContentType: .applicationData)
        XCTAssertEqual(ciphertext.encryptedRecord, Array(RecordParsingTests.oneRTTClientApplicationDataFullRecord.suffix(from: 5)))
        deprotectedRecord = try serverProtector.deprotect(ciphertext: ciphertext)
        XCTAssertEqual(deprotectedRecord.actualContentType, .applicationData)
        XCTAssertEqual(deprotectedRecord.fragment, RecordParsingTests.oneRTTClientApplicationDataPayload)

        // server --> client, application content type, application traffic keys, seqno = 1
        ciphertext = try serverProtector.protect(plaintext: RecordParsingTests.oneRTTServerApplicationDataPayload.span.bytes, actualContentType: .applicationData)
        XCTAssertEqual(ciphertext.encryptedRecord, RecordParsingTests.oneRTTServerApplicationDataEncryptedPayload)
        deprotectedRecord = try clientProtector.deprotect(ciphertext: ciphertext)
        XCTAssertEqual(deprotectedRecord.actualContentType, .applicationData)
        XCTAssertEqual(deprotectedRecord.fragment, RecordParsingTests.oneRTTServerApplicationDataPayload)

        // client --> server, alert content type, application traffic keys, seqno = 1
        ciphertext = try clientProtector.protect(plaintext: RecordParsingTests.oneRTTClientAlertPayload.span.bytes, actualContentType: .alert)
        XCTAssertEqual(ciphertext.encryptedRecord, Array(RecordParsingTests.oneRTTClientAlertFullRecord.suffix(from: 5)))
        deprotectedRecord = try serverProtector.deprotect(ciphertext: ciphertext)
        XCTAssertEqual(deprotectedRecord.actualContentType, .alert)
        XCTAssertEqual(deprotectedRecord.fragment, RecordParsingTests.oneRTTClientAlertPayload)

        // server --> client, alert content type, application traffic keys, seqno = 2
        ciphertext = try serverProtector.protect(plaintext: RecordParsingTests.oneRTTServerAlertPayload.span.bytes, actualContentType: .alert)
        XCTAssertEqual(ciphertext.encryptedRecord, Array(RecordParsingTests.oneRTTServerAlertFullRecord.suffix(from: 5)))
        deprotectedRecord = try clientProtector.deprotect(ciphertext: ciphertext)
        XCTAssertEqual(deprotectedRecord.actualContentType, .alert)
        XCTAssertEqual(deprotectedRecord.fragment, RecordParsingTests.oneRTTServerAlertPayload)

    }

    // RFC 9846 §5.5 - up to 2^24.5 (floor: 23_726_566) full-size records may be protected under
    // a single AES-GCM key. This bounds the write side only -- the RFC says receivers "SHOULD
    // NOT enforce these limits" -- so deprotect() has no equivalent guard.
    func testTLSRecordProtectorKeyUsageLimit() throws {
        let limit: UInt64 = 23_726_566

        let serverWriteKey = SymmetricKey(data: RecordParsingTests.oneRTTServerHandshakeWriteKey)
        let serverWriteIV: [UInt8] = RecordParsingTests.oneRTTServerHandshakeWriteIV
        let clientReadKey = SymmetricKey(data: RecordParsingTests.oneRTTServerHandshakeWriteKey)
        let clientReadIV: [UInt8] = RecordParsingTests.oneRTTServerHandshakeWriteIV

        // write side: exactly `limit` records are allowed, the (limit + 1)-th throws.
        var writeProtector = try TLSRecordProtector(
            writeKey: serverWriteKey,
            writeIV: serverWriteIV,
            ciphersuite: .TLS_AES_128_GCM_SHA256)
        writeProtector.setSequenceNumbersForTesting(write: limit - 1)

        // the `limit`-th record still succeeds.
        _ = try writeProtector.protect(plaintext: RecordParsingTests.oneRTTClientApplicationDataPayload.span.bytes, actualContentType: .applicationData)

        // the (limit + 1)-th record throws.
        XCTAssertThrowsError(try writeProtector.protect(plaintext: RecordParsingTests.oneRTTClientApplicationDataPayload.span.bytes, actualContentType: .applicationData)) { error in
            XCTAssertEqual(error as? TLSError, .keyUsageLimitExceeded)
        }

        // an alert is exempt from the limit, so it can still flush a fatal alert under an
        // expiring key (sendAlert() re-enters protect() on the same instance that just threw).
        _ = try writeProtector.protect(plaintext: RecordParsingTests.oneRTTClientAlertPayload.span.bytes, actualContentType: .alert)

        // read side: RFC 9846 §5.5 explicitly says "Receiving implementations SHOULD NOT enforce
        // these limits, as future analyses may result in updated values" -- so deprotect() must
        // keep succeeding well past the point where protect() would have thrown, using a real
        // matching encrypt/decrypt pair (not fudged ciphertext) so the nonce/tag are valid at the
        // seeded sequence number.
        var senderProtector = try TLSRecordProtector(writeKey: serverWriteKey, writeIV: serverWriteIV, ciphersuite: .TLS_AES_128_GCM_SHA256)
        var readProtector = try TLSRecordProtector(readKey: clientReadKey, readIV: clientReadIV, ciphersuite: .TLS_AES_128_GCM_SHA256)
        let wellPastLimit = limit + 1_000
        senderProtector.setSequenceNumbersForTesting(write: wellPastLimit)
        readProtector.setSequenceNumbersForTesting(read: wellPastLimit)

        // .alert is used here only because it's the one content type protect() will still
        // encrypt this far past the limit (per the write-side exemption above) -- it's just the
        // means of producing a real over-limit ciphertext for deprotect() to receive.
        let pastLimitRecord = try senderProtector.protect(plaintext: RecordParsingTests.oneRTTClientAlertPayload.span.bytes, actualContentType: .alert)
        let deprotected = try readProtector.deprotect(ciphertext: pastLimitRecord)
        XCTAssertEqual(deprotected.fragment, RecordParsingTests.oneRTTClientAlertPayload)

        // even at the far end of the UInt64 space, the tighter §5.5 limit is what fires, not the
        // pre-existing §5.3 sequence-number-wraparound guard.
        var farProtector = try TLSRecordProtector(writeKey: serverWriteKey, writeIV: serverWriteIV, ciphersuite: .TLS_AES_128_GCM_SHA256)
        farProtector.setSequenceNumbersForTesting(write: UInt64.max - 1)
        XCTAssertThrowsError(try farProtector.protect(plaintext: RecordParsingTests.oneRTTClientApplicationDataPayload.span.bytes, actualContentType: .applicationData)) { error in
            XCTAssertEqual(error as? TLSError, .keyUsageLimitExceeded)
        }
    }

    // Ensure CCS record is dropped if received, and next record is returned.
    //
    // RFC 9846: "An implementation may receive an unencrypted record of type
    // change_cipher_spec consisting of the single byte value 0x01 at any time
    // after the first ClientHello message has been sent or received and before
    // the peer's Finished message has been received and MUST simply drop it
    // without further processing."
    func testChangeCipherSpecIsDroppedBeforeNextRecord() throws {
        // Record 1: complete, valid legacy ChangeCipherSpec record
        //   14        content type = changeCipherSpec (20)
        //   03 03     legacy_record_version = TLS 1.2
        //   00 01     length = 1
        //   01        content = 0x01 (the only valid CCS body)
        // Record 2: a handshake-type record with recognizable filler content
        //   16        content type = handshake (22)
        //   03 03     legacy_record_version = TLS 1.2
        //   00 04     length = 4
        //   aabbccdd  content — arbitrary bytes
        let hex = "1403030001011603030004aabbccdd"

        var buf = ByteBuffer(data: try Data(hexString: hex))
        recordParser.appendBytes(&buf)
        XCTAssertEqual(recordParser.numberOfBytesBuffered, 15)

        guard let plaintext = try recordParser.parsePlaintextRecord() else {
            XCTFail("expected the record after CCS to be returned, not nil")
            return
        }

        // The CCS must not be what's handed back to the caller.
        XCTAssertEqual(plaintext.contentType, .handshake)
        XCTAssertEqual(plaintext.content, [0xaa, 0xbb, 0xcc, 0xdd])

        // Both the dropped CCS and the returned record's bytes must be consumed.
        XCTAssertEqual(recordParser.numberOfBytesBuffered, 0)
    }

    // Ensure that processing ChangeCipherSpec messages that claim more content bytes
    // than are available in the buffer do not infinitely loop.
    func testChangeCipherSpecFollowedByTruncatedRecordDoesNotHang() throws {
        // Record 1: complete, valid legacy ChangeCipherSpec record
        // Record 2: a handshake record header declaring 5 content bytes, with zero of them
        // buffered yet.
        let hex = "1403030001011603030005"

        // local instance since noncopyable class properties can't be consumed
        var localParser = TLSRecordParser()
        var buf = ByteBuffer(data: try Data(hexString: hex))
        localParser.appendBytes(&buf)

        final class Holder: @unchecked Sendable {
            var parser: TLSRecordParser
            var result: Result<TLSPlaintext?, Error>?
            init(parser: consuming TLSRecordParser) { self.parser = parser }
        }
        let holder = Holder(parser: localParser)
        let semaphore = DispatchSemaphore(value: 0)
        let thread = Thread {
            do {
                let record = try holder.parser.parsePlaintextRecord()
                holder.result = .success(record)
            } catch {
                holder.result = .failure(error)
            }
            semaphore.signal()
        }
        thread.start()

        let timedOut = semaphore.wait(timeout: .now() + 10) == .timedOut
        XCTAssertFalse(timedOut, "parsePlaintextRecord hung instead of returning nil to await the rest of record 2")

        guard !timedOut else { return }
        switch holder.result {
        case .success(let record):
            XCTAssertNil(record, "should be waiting for the remaining bytes of record 2, not returning a record")
        case .failure(let error):
            XCTFail("expected nil (waiting for more data), got error: \(error)")
        case nil:
            XCTFail("parser thread did not report a result")
        }
    }

    // Any change_cipher_spec value besides 0x01 MUST abort the handshake with
    // unexpected_message. This tests a bad value with the correct length.
    //
    // RFC 9846: "An implementation which receives any other change_cipher_spec
    // value [apart from the single byte value 0x01] ... MUST abort the handshake
    // with an "unexpected_message" alert."
    func testChangeCipherSpecWithInvalidValueIsRejected() throws {
        // A CCS record with the correct length (1) but a value other than 0x01.
        //   14        content type = changeCipherSpec (20)
        //   03 03     legacy_record_version = TLS 1.2
        //   00 01     length = 1
        //   00        content = 0x00 — only 0x01 is a valid CCS body
        let hex = "140303000100"
        var buf = ByteBuffer(data: try Data(hexString: hex))
        recordParser.appendBytes(&buf)

        XCTAssertThrowsError(try recordParser.parsePlaintextRecord()) { error in
            XCTAssertEqual(error as? TLSError, .handshakeUnexpectedMessage)
        }
    }

    // This test covers a bad length with the correct value.
    //
    // RFC 9846: "An implementation which receives any other change_cipher_spec
    // value [apart from the single byte value 0x01] ... MUST abort the handshake
    // with an "unexpected_message" alert."
    func testChangeCipherSpecWithInvalidLengthIsRejected() throws {
        // A CCS record with the correct leading byte but the wrong length (2, not 1).
        //   14        content type = changeCipherSpec (20)
        //   03 03     legacy_record_version = TLS 1.2
        //   00 02     length = 2 — only length 1 is valid for CCS
        //   01 01     content — two bytes; the length itself is already invalid
        //             regardless of what the bytes are
        let hex = "14030300020101"
        var buf = ByteBuffer(data: try Data(hexString: hex))
        recordParser.appendBytes(&buf)

        XCTAssertThrowsError(try recordParser.parsePlaintextRecord()) { error in
            XCTAssertEqual(error as? TLSError, .handshakeUnexpectedMessage)
        }
    }

}
