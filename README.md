# Swift TLS

SwiftTLS provides a Swift-native minimal implementation of the TLS 1.3 handshake, specifically aimed at providing support for the QUIC transport protocol. This package is specifically intended to support the implementation of QUIC in  [SwiftNetwork](https://github.com/apple/swift-network-evolution).

SwiftTLS supports a minimal set of features and intentionally does not allow negotiation of older versions of TLS.

> [!NOTE]
> At this time, all types exposed in this package are marked as SPI and subject to change at any time.

## Building and Testing

> [!NOTE]
> Building this package requires the Swift 6.3 toolchain or later. You can download toolchains from [the Swift website](https://swift.org/install).

To build via the command line (for all platforms), run `swift build` at the root of package.

To run all unit tests, run `swift test`. Unit tests can also be run by filtering a specific class or function:

```
% swift test --filter HandshakeStateMachineTests
% swift test --filter HandshakeStateMachineTests.testStartHandshake
```

All unit tests are run automatically upon creation or update of a Pull Request. See [CONTRIBUTING](https://github.com/apple/swift-tls/blob/main/CONTRIBUTING.md) for details.

## Contributions

SwiftTLS has a limited scope and is focused on supporting specific projects, such as supporting QUIC in SwiftNetwork. Pull requests that add new functionality or expand the surface will not be accepted at this time. The community is welcome to propose bug fixes, tests, documentation, and ports to new platforms.

Please use [GitHub Issues](https://github.com/apple/swift-tls/issues) for tracking bugs and other work.

Please see the [CONTRIBUTING](https://github.com/apple/swift-tls/blob/main/CONTRIBUTING.md) document for information on how to contribute to the project.
