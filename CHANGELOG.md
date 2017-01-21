# Change Log

All notable changes to this project will be documented in this file.
This project adheres to [Semantic Versioning](http://semver.org/).

## [0.1.5] - 2017-01-20
### Changed
- Catch errors raised by `jiffy` for malformed JSON and report as an error.

## [0.1.4] - 2016-12-23
### Changed
- Return any file upload errors gracefully rather than crashing the gen_server.

## [0.1.3] - 2016-12-22
### Changed
- Ensure response body is consistently read so connection can be released.

## [0.1.2] - 2016-12-20
### Changed
- Set timeout for receiving response after a file upload to 60 seconds.

## [0.1.1] - 2016-12-18
### Changed
- Increase timeouts of `gen_server:call` to `infinity` since remote calls can be slow.

## [0.1.0] - 2016-11-18
### Changed
- Initial release
