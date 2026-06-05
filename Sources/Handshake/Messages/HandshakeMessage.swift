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

enum HandshakeMessage: Hashable {
    case clientHello(ClientHello)
    case serverHello(ServerHello)
    case encryptedExtensions(EncryptedExtensions)
    case certificateRequest(CertificateRequest)
    case certificate(CertificateMessage)
    case certificateVerify(CertificateVerify)
    case finished(FinishedMessage)
    case newSessionTicket(NewSessionTicket)

    var logDescription: String {
        switch self {
        case .clientHello:
            return "clientHello"
        case .serverHello:
            return "serverHello"
        case .encryptedExtensions:
            return "encryptedExtensions"
        case .certificateRequest:
            return "certificateRequest"
        case .certificate:
            return "certificate"
        case .certificateVerify:
            return "certificateVerify"
        case .finished:
            return "finished"
        case .newSessionTicket:
            return "newSessionTicket"
        }
    }
}
