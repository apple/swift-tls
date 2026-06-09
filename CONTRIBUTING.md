# Contributing to SwiftTLS

Welcome to the community! Contributions are welcomed and encouraged. SwiftTLS is part of the Swift ecosystem and closely aligns with the [contribution guidelines for the Swift project](swift.org/contributing).

## How You Can Help

* Reporting bugs with clear, reproducible steps via [GitHub Issues](https://github.com/apple/swift-tls/issues)
* Improving documentation to make the project more accessible
* Adding or enhancing tests to improve reliability and coverage
* Adding ports to new platforms
* Triaging issues by providing feedback, testing, and validation
* Participating in the [Networking category on the Swift Forums](https://forums.swift.org/c/development/networking/129)

## Setting Up Your Environment

See the [README](./README#building-and-testing) for prerequisites and build (and test) instructions.

## Submitting Issues and Pull Requests

### Issues and Bugs

Use GitHub Issues to report bugs. When filing a bug, include your SwiftTLS version, Swift version, OS, and the simplest possible steps to reproduce.

### Pull requests

Each pull request will be reviewed by a code owner before merging.

* Pull requests should contain small, incremental changes focused on one task; we may ask you to split up the work.
* Squash work-in-progress commits. Each commit should stand on its own (including the addition of tests if possible). This allows us to bisect issues more effectively.
* After addressing review feedback, rebase your commit so that we create a clean history in the `main` branch.
* All code must conform to the [Swift API Design Guidelines](https://swift.org/documentation/api-design-guidelines/)
* Documentation is required. Please explain the "why" behind non-obvious decisions.

Given SwiftTLS's [limited scope](./README#Contributing), please confirm the fix or change via pull request is within scope by opening an [Issue](https://github.com/apple/swift-tls/issues) first. The [Networking category on the Swift Forums](https://forums.swift.org/c/development/networking/129) is also a great place to discuss feature requests and larger overall project discussions.  

## Tests

All tests must pass on all supported platforms before a pull request can be merged. Unit tests are run automatically on pull request creation and updates. Pull requests that add new functionality should come with new automated tests.

See the [README](./README#building-and-testing) for quick references

