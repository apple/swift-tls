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
extension CertificateType: Loggable {
    func write<Printer>(to: Printer) where Printer : CharacterPrinter {

    }
}

extension SignatureScheme: Loggable {
    func write<Printer>(to: Printer) where Printer : CharacterPrinter {

    }
}

extension ExtensionType: Loggable {
    func write<Printer>(to: Printer) where Printer : CharacterPrinter {

    }
}

extension CipherSuite: Loggable {
    func write<Printer>(to: Printer) where Printer : CharacterPrinter {

    }
}

extension HandshakeType: Loggable {
    func write<Printer>(to: Printer) where Printer : CharacterPrinter {

    }
}

extension ProtocolVersion: Loggable {
    func write<Printer>(to: Printer) where Printer : CharacterPrinter {

    }
}

extension ContentType: Loggable {
    func write<Printer>(to: Printer) where Printer : CharacterPrinter {

    }
}

extension TLSError: Loggable {
    func write<Printer>(to: Printer) where Printer : CharacterPrinter {

    }
}

extension SwiftTLSError: Loggable  {
    func write<Printer>(to: Printer) where Printer : CharacterPrinter {

    }
}
#endif
