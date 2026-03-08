# Changelog

## 0.2.0

- Option value interpretation helpers (`as_uint`, `as_block`, `as_content_format`, `as_string`) (#4)
- Option value construction helpers (`Option.uint`, `Option.empty`, `Option.content_format`, `BlockValue.option`) (#4)
- Const packet fields for safer usage (#3)
- Security, correctness, and ergonomics fixes (#2)
- Benchmarks switched to ArenaAllocator (~100x faster results) (#1)

## 0.1.0

Initial release.

- CoAP packet decode/encode (RFC 7252)
- Observe option support (RFC 7641)
- Block-wise transfer option parsing (RFC 7959)
- Too Many Requests response code (RFC 8516)
- Two-pass zero-copy decode with single-allocation encode
- Bounds checks and error reporting for malformed packets
