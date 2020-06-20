# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.4.0] - 2020-06-20
### Added
- `reseal` command

## [0.3.0] - 2020-05-13
### Added
- `--fetch-cert` flag to `seal` and `verify` for enforcing a cert load
- warning in case a secret value is an empty string or padded with whitespace
### Changed
- renamed cert source `controller` to `kubernetes`
- moved `maxAge` one level up
- keys from snake_case to camelCase
- cert structure of `.sealit.yaml`
### Fixed
- flaky verify command

## [0.2.1] - 2020-05-11
### Changed
- Bug fix for `sealit init`
- Update of `.sealit.yaml`

## [0.2.0] - 2020-05-10
### Added
- CHANGELOG.md
- CONTRIBUTING.md
- CODE_OF_CONDUCT.md
- `template` command for creating a SealedSecret K8s resource
- Debug flag `--debug` and logs
### Changed
- README.md
- make build will populate the binary to `dist` instead of `bin`

## [0.1.0-alpha.2] - 2020-05-06
### Added
- `init`, `seal` and `verify` commands

[Unreleased]: https://github.com/dschniepp/sealit/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/dschniepp/sealit/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/dschniepp/sealit/compare/v0.2.1...v0.3.0
[0.2.1]: https://github.com/dschniepp/sealit/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/dschniepp/sealit/compare/v0.1.0-alpha.2...v0.2.0
[0.1.0-alpha.2]: https://github.com/dschniepp/sealit/releases/tag/v0.1.0-alpha.2