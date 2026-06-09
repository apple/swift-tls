# Contributing

This project follows the [contribution guidelines for the Swift project](https://swift.org/contributing/#contributing-code).

## Bug reports

We are using [GitHub Issues](https://github.com/apple/swift-tls/issues) for tracking bugs and other work.

## Pull requests

Each pull request will be reviewed by a code owner before merging.

* Pull requests should contain small, incremental changes.
* Focus on one task. If a pull request contains several unrelated commits, we will ask for the pull request to be split up.
* Squash work-in-progress commits. Each commit should stand on its own (including the addition of tests if possible). This allows us to bisect issues more effectively.
* After addressing review feedback, rebase your commit so that we create a clean history in the `main` branch.

## Tests

Unit tests are run automatically on pull request creation and updates. All tests must pass on all supported platforms before merging pull requests. Pull requests that add new functionality should come with new automated tests.
