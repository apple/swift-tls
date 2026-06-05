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

enum PSKSource {
    case resumption
    case external
    case imported

    var secretLabel: String {
        switch self {
        case .resumption:
            return "res binder"
        case .external:
            return "ext binder"
        case .imported:
            return "imp binder"
        }
    }
}
