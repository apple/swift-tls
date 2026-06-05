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

// Cross platform shim for errSSL codes
enum TLSErrorCode: Int32 {
    case errSecSuccess                                   = 0        /* No error. */
    case errSSLBadCert                                   = -9808    /* bad certificate format */
    case errSSLHandshakeFail                             = -9858    /* handshake failed */
    case errSSLUnexpectedMessage                         = -9856    /* peer rejected unexpected message */
    case errSSLIllegalParam                              = -9830    /* illegal parameter */
}
