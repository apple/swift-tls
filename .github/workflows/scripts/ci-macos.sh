#!/bin/bash
##===----------------------------------------------------------------------===##
##
## This source file is part of the Swift open source project
##
## Copyright (c) 2026 Apple Inc. and the Swift project authors
## Licensed under Apache License v2.0
##
## See LICENSE.txt for license information
## See CONTRIBUTORS.txt for the list of Swift project authors
##
## SPDX-License-Identifier: Apache-2.0
##
##===----------------------------------------------------------------------===##

# Builds the package for most Apple platforms with xcodebuild, then runs the
# test suite on macOS.  Also see ci-ios.sh.
#
# Usage: ci-macos.sh [swift flags...]
#
# The flags are forwarded to `swift test` only. The xcodebuild invocations take
# their settings from the scheme.

set -u

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=ci-support.sh
. "${script_dir}/ci-support.sh"

xcodebuild_step 'macOS build' 'generic/platform=macos,variant=macos'
xcodebuild_step 'Mac Catalyst build' 'generic/platform=macos,variant=Mac Catalyst'
xcodebuild_step 'watchOS build' 'generic/platform=watchos'
xcodebuild_step 'tvOS build' 'generic/platform=tvos'
xcodebuild_step 'visionOS build' 'generic/platform=visionos'

ci_run 'swift test' xcrun swift test "$@"

ci_finish
