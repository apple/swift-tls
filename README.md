# Swift TLS

SwiftTLS provides a minimal, Swift-native implementation of the TLS 1.3 handshake to support the QUIC transport protocol. This package is intended to support the implementation of QUIC in [SwiftNetwork](https://github.com/apple/swift-network-evolution).

SwiftTLS supports a minimal set of features and intentionally does not allow negotiation of older versions of TLS.

> [!NOTE]
> At this time, all types exposed in this package are marked as SPI and subject to change at any time.

## Getting Started

### Prerequisites

- [Swift 6.3 and up](https://swift.org/install)
- macOS 26.0 and up or Linux (Ubuntu 22.04+)
- Xcode 26.0 and up (Apple platforms only)

### Building and testing

To build via the command line (for all platforms), run at the root of the package:
```
swift build
``` 

To run all unit tests, run 
``` 
swift test
```

Unit tests can also be run by filtering a specific class or function:

```
% swift test --filter HandshakeStateMachineTests
% swift test --filter HandshakeStateMachineTests.testStartHandshake
```

GitHub runs the unit tests automatically when you open or update a pull request. See [CONTRIBUTING](https://github.com/apple/swift-tls/blob/main/CONTRIBUTING.md) for details.

## Contributing

The [SwiftTLS Contributing Guide](CONTRIBUTING.md) includes detailed information about participating in the project. 

We welcome the following contributions:
* Reporting bugs with clear, reproducible steps via [GitHub Issues](https://github.com/apple/swift-tls/issues)
* Improving documentation to make the project more accessible
* Adding or enhancing tests to improve reliability and coverage
* Adding ports to new platforms
* Triaging issues by providing feedback, testing, and validation
* Participating in the [Networking category on the Swift Forums](https://forums.swift.org/c/development/networking/129)

SwiftTLS has a limited scope and is focused on supporting specific projects, such as supporting QUIC in SwiftNetwork. Pull requests that add new functionality or expand the surface will not be accepted at this time. 
