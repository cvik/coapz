# Changelog

## 0.4.0

- Add public `Observe` values for subscribe/unsubscribe requests (#7)
- Frontend-inline option length decoding to avoid error-result stack temporaries (#8)
- Exhaustively check option length values, truncation/overflow errors and cursor movement (#8)

## 0.3.0

- Add allocation-free `Packet.peekKind`, `Packet.peekMsgId`, and `Packet.peekOption` helpers (#6)
- Add `Packet.emptyAck` and `Packet.emptyRst` wire helpers (#6)

## 0.2.1

- Add allocation-free `writeBuf` for encoding into caller-provided buffers (#5)
- Add `encodedSize` to query exact wire size without encoding (#5)

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
