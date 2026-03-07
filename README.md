# coapz

Minimal [CoAP](https://datatracker.ietf.org/doc/html/rfc7252) packet encoder/decoder for Zig. Zero-copy two-pass decode with pre-sized single-allocation encode.

## Scope

Handles binary CoAP message serialization only -- no transport, no retransmission, no resource discovery. Intended as a building block for CoAP stacks.

**Supported RFCs:**
- RFC 7252 -- Constrained Application Protocol (CoAP)
- RFC 7641 -- Observe Option
- RFC 7959 -- Block-Wise Transfers (option parsing)
- RFC 8516 -- Too Many Requests Response Code

## Installation

Add as a Zig package dependency:

```sh
zig fetch --save git+https://github.com/cvik/coapz.git
```

Then in your `build.zig`:

```zig
const coapz = b.dependency("coapz", .{});
exe.root_module.addImport("coapz", coapz.module("coapz"));
```

Or vendor `src/root.zig` directly.

## Usage

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
zig build                              # build static library
zig build test                         # run tests
zig build bench -Doptimize=ReleaseFast # run benchmarks
```

## Benchmarks

AMD Ryzen AI MAX+ 395, 32 threads, 112 GiB RAM, Linux 6.18.9

```
Decode:
  minimal (4B header only)                       25 ns/op    39972777 ops/s
  small (token + 1 option)                     8963 ns/op      111562 ops/s
  multi-option (3 opts + payload)              9277 ns/op      107786 ops/s
  host+path (2 options)                        8955 ns/op      111658 ops/s
  payload (ACK + 12B body)                     4786 ns/op      208939 ops/s
  extended delta (opt 258)                     9018 ns/op      110885 ops/s

Encode (read + write):
  minimal (4B header only)                     4932 ns/op      202749 ops/s
  small (token + 1 option)                    14993 ns/op       66697 ops/s
  multi-option (3 opts + payload)             15110 ns/op       66178 ops/s
  host+path (2 options)                       14790 ns/op       67609 ops/s
  payload (ACK + 12B body)                     9761 ns/op      102442 ops/s
  extended delta (opt 258)                    14781 ns/op       67651 ops/s

Round-trip (decode + encode + decode):
  minimal (4B header only)                     4964 ns/op      201419 ops/s
  small (token + 1 option)                    24228 ns/op       41273 ops/s
  multi-option (3 opts + payload)             24685 ns/op       40509 ops/s
  host+path (2 options)                       24183 ns/op       41351 ops/s
  payload (ACK + 12B body)                    14755 ns/op       67771 ops/s
  extended delta (opt 258)                    24164 ns/op       41382 ops/s
```

Note: benchmarks use `page_allocator`; real workloads with arena/pool allocators will be significantly faster.
