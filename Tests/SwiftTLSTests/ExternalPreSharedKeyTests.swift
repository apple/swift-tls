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
#if canImport(CryptoKit)
import CryptoKit
#elseif canImport(Crypto)
@preconcurrency import Crypto
#endif
#if canImport(SwiftTLS) && !SWIFTTLS_BUILTIN_TESTS
@testable import SwiftTLS
#endif

@available(SwiftTLS 0.1.0, *)
class ExternalPreSharedKeyTests: XCTestCase {
    func testPSKImporterInterface() throws {
        let externalIdentity = ByteBuffer("test psk identity")
        let epsk = SymmetricKey(size: SymmetricKeySize.bits128)
        let context = ByteBuffer("test context")

        let EPSK = try EPSK(externalIdentity: externalIdentity, epsk: epsk, context: context)
        XCTAssertEqual(EPSK.externalIdentity, externalIdentity)
        XCTAssertEqual(EPSK.epsk, epsk)
        XCTAssertEqual(EPSK.context, context)

        let importedIdentity256 = try EPSK.generateImportedIdentity(for: TLSKDFIdentifier.HKDF_SHA256)
        let importedIdentity384 = try EPSK.generateImportedIdentity(for: TLSKDFIdentifier.HKDF_SHA384)
        XCTAssertEqual(importedIdentity256.externalIdentity, externalIdentity)
        XCTAssertEqual(importedIdentity384.externalIdentity, externalIdentity)
        XCTAssertEqual(importedIdentity256.context, context)
        XCTAssertEqual(importedIdentity384.context, context)
        XCTAssertEqual(importedIdentity256.targetProtocol, 0x0304)
        XCTAssertEqual(importedIdentity384.targetProtocol, 0x0304)
        XCTAssertEqual(importedIdentity256.targetKDF, 0x0001)
        XCTAssertEqual(importedIdentity384.targetKDF, 0x0002)

        let serializedIdentity256 = importedIdentity256.serialize()
        let serializedIdentity384 = importedIdentity384.serialize()
        let deserializedIdentity256 = try ImportedIdentity(serialized: serializedIdentity256.bytes)
        let deserializedIdentity384 = try ImportedIdentity(serialized: serializedIdentity384.bytes)
        XCTAssertEqual(deserializedIdentity256, importedIdentity256)
        XCTAssertEqual(deserializedIdentity384, importedIdentity384)
    }

    func testPSKImporterInterfaceNoContext() throws {
        // context is optional in RFC 9258
        let externalIdentity = ByteBuffer("test psk identity")
        let epsk = SymmetricKey(size: SymmetricKeySize.bits128)
        let context: ByteBuffer? = nil

        let EPSK = try EPSK(externalIdentity: externalIdentity, epsk: epsk, context: context)
        XCTAssertEqual(EPSK.externalIdentity, externalIdentity)
        XCTAssertEqual(EPSK.epsk, epsk)
        XCTAssertEqual(EPSK.context, context)

        let importedIdentity256 = try EPSK.generateImportedIdentity(for: TLSKDFIdentifier.HKDF_SHA256)
        let importedIdentity384 = try EPSK.generateImportedIdentity(for: TLSKDFIdentifier.HKDF_SHA384)
        XCTAssertEqual(importedIdentity256.externalIdentity, externalIdentity)
        XCTAssertEqual(importedIdentity384.externalIdentity, externalIdentity)
        XCTAssertEqual(importedIdentity256.context, context)
        XCTAssertEqual(importedIdentity384.context, context)
        XCTAssertEqual(importedIdentity256.targetProtocol, 0x0304)
        XCTAssertEqual(importedIdentity384.targetProtocol, 0x0304)
        XCTAssertEqual(importedIdentity256.targetKDF, 0x0001)
        XCTAssertEqual(importedIdentity384.targetKDF, 0x0002)

        let serializedIdentity256 = importedIdentity256.serialize()
        let serializedIdentity384 = importedIdentity384.serialize()
        let deserializedIdentity256 = try ImportedIdentity(serialized: serializedIdentity256.bytes)
        let deserializedIdentity384 = try ImportedIdentity(serialized: serializedIdentity384.bytes)
        XCTAssertEqual(deserializedIdentity256, importedIdentity256)
        XCTAssertEqual(deserializedIdentity384, importedIdentity384)
    }

    func testLongImportedIdentityRejected() throws {
        let trashBytes = Data(repeating: UInt8(1), count: Int(UInt16.max)+1)
        let externalIdentity = ByteBuffer(data: trashBytes)
        let epsk = SymmetricKey(size: SymmetricKeySize.bits128)
        let context = ByteBuffer("test context")
        let EPSK = try EPSK(externalIdentity: externalIdentity, epsk: epsk, context: context)

        XCTAssertThrowsError(try EPSK.generateImportedIdentity(for: TLSKDFIdentifier.HKDF_SHA256)) { error in
            XCTAssertEqual(error as? TLSError, .importedIdentityTooLong)
        }
    }

    func testShortEPSKRejected() throws {
        let externalIdentity = ByteBuffer("test psk identity")
        let epsk = SymmetricKey(size: SymmetricKeySize(bitCount: 64))
        let context = ByteBuffer("test context")

        XCTAssertThrowsError(try EPSK(externalIdentity: externalIdentity, epsk: epsk, context: context)) {
            error in XCTAssertEqual(error as? TLSError, .insufficientLengthForEPSK)
        }
    }
}
