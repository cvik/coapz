# coapz

Minimal [CoAP](https://datatracker.ietf.org/doc/html/rfc7252) packet encoder/decoder for Zig. Zero-copy two-pass decode with pre-sized single-allocation encode.

## Scope

Handles binary CoAP message serialization only -- no transport, no retransmission, no resource discovery. Intended as a building block for CoAP stacks.

**Supported RFCs:**
- RFC 7252 -- Constrained Application Protocol (CoAP)
- RFC 7641 -- Observe Option
- RFC 7959 -- Block-Wise Transfers (option parsing)
- RFC 8516 -- Too Many Requests Response Code

## Usage

Add as a Zig dependency or vendor `src/root.zig` directly.

### Decoding

```zig
const coap = @import("coapz");

const data = [_]u8{
    0x44, 0x01, 0xba, 0x22, 0x0c, 0x53, 0x5f, 0xb9,
    0xb8, 0x63, 0x68, 0x65, 0x63, 0x6b, 0x5f, 0x69, 0x63,
};

const pkt = try coap.Packet.read(allocator, &data);
defer pkt.deinit();

// pkt.kind     == .confirmable
// pkt.code     == .get
// pkt.msg_id   == 0xba22
// pkt.token    == &[_]u8{ 0x0c, 0x53, 0x5f, 0xb9 }
// pkt.options[0].kind  == .uri_path
// pkt.options[0].value == "check_ic"
```

### Encoding

```zig
const encoded = try pkt.write();
defer allocator.free(encoded);
// encoded is a freshly allocated []u8 containing the CoAP wire format
```

### Error handling

`Packet.read` returns the following errors for malformed input:

| Error                | Condition                                       |
|----------------------|-------------------------------------------------|
| `MessageTooShort`    | Data shorter than 4-byte header or declared TKL |
| `InvalidTokenLength` | TKL field is 9--15 (reserved per RFC 7252)      |
| `TruncatedOption`    | Option delta/length nibble 15, or truncated extended bytes / value |
| `EmptyPayload`       | Payload marker `0xFF` with no bytes following   |

## Build

Requires Zig 0.15+.

```sh
zig build          # build static library
zig build test     # run tests
zig build bench    # run benchmarks
```

## Benchmarks

AMD Ryzen AI MAX+ 395, 32 threads, 112 GiB RAM, Linux 6.18.9

```
Decode:
  minimal (4B header only)                      740 ns/op     1351046 ops/s
  small (token + 1 option)                    11726 ns/op       85274 ops/s
  multi-option (3 opts + payload)             12106 ns/op       82601 ops/s
  host+path (2 options)                       12039 ns/op       83056 ops/s
  payload (ACK + 12B body)                     6553 ns/op      152591 ops/s
  extended delta (opt 258)                    11613 ns/op       86106 ops/s

Encode (read + write):
  minimal (4B header only)                     7189 ns/op      139097 ops/s
  small (token + 1 option)                    19860 ns/op       50350 ops/s
  multi-option (3 opts + payload)             21633 ns/op       46224 ops/s
  host+path (2 options)                       20731 ns/op       48235 ops/s
  payload (ACK + 12B body)                    13375 ns/op       74763 ops/s
  extended delta (opt 258)                    20029 ns/op       49927 ops/s

Round-trip (decode + encode + decode):
  minimal (4B header only)                     7889 ns/op      126751 ops/s
  small (token + 1 option)                    31963 ns/op       31286 ops/s
  multi-option (3 opts + payload)             33938 ns/op       29465 ops/s
  host+path (2 options)                       33087 ns/op       30222 ops/s
  payload (ACK + 12B body)                    20028 ns/op       49927 ops/s
  extended delta (opt 258)                    32007 ns/op       31242 ops/s
```

Note: benchmarks use `page_allocator`; real workloads with arena/pool allocators will be significantly faster.
