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

# Shared step runner for the CI scripts in this directory. Source it, call
# ci_run once per step, then call ci_finish.
#
# Steps always run even if an earlier one failed, so a single broken
# configuration does not hide the state of the others. ci_finish prints a
# summary and exits non-zero if any step failed.
#
# Note: this must stay compatible with bash 3.2, which is what /bin/bash is on
# the macOS runners.

ci_exit_code=0
ci_summary=()

# ci_record <name> <result>
ci_record() {
    ci_summary+=("$(printf '%-30s %s' "$1:" "$2")")
}

# ci_run <name> <command>...
ci_run() {
    local name="$1"
    shift

    echo "=== ${name} ==="
    if "$@"; then
        echo "=== ${name}: PASSED ==="
        ci_record "${name}" 'PASSED'
    else
        echo "=== ${name}: FAILED ==="
        ci_exit_code=1
        ci_record "${name}" 'FAILED'
    fi
}

ci_finish() {
    echo '=== Summary ==='
    if [ "${#ci_summary[@]}" -gt 0 ]; then
        printf '%s\n' "${ci_summary[@]}"
    fi

    # Surface the outcome on the run's summary page, not just buried in the log.
    if [ -n "${GITHUB_STEP_SUMMARY:-}" ] && [ "${#ci_summary[@]}" -gt 0 ]; then
        {
            echo '```'
            printf '%s\n' "${ci_summary[@]}"
            echo '```'
        } >> "${GITHUB_STEP_SUMMARY}"
    fi

    exit "${ci_exit_code}"
}

# xcodebuild_step <name> <destination>
xcodebuild_step() {
    local scheme='swift-tls'
    ci_run "$1" /usr/bin/xcodebuild -scheme "${scheme}" -destination "$2" build
}
