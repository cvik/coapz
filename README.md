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
const encoded = try pkt.write(allocator);
defer allocator.free(encoded);
// encoded is a freshly allocated []u8 containing the CoAP wire format
```

### Error handling

`Packet.read` returns the following errors for malformed input:

| Error                | Condition                                       |
|----------------------|-------------------------------------------------|
| `MessageTooShort`    | Data shorter than 4-byte header or declared TKL |
| `InvalidVersion`     | Version field is not 1 (per RFC 7252 §3)        |
| `InvalidTokenLength` | TKL field is 9--15 (reserved per RFC 7252)      |
| `TruncatedOption`    | Option delta/length nibble 15, or truncated extended bytes / value |
| `EmptyPayload`       | Payload marker `0xFF` with no bytes following   |
| `UnsortedOptions`    | Options not in ascending order (encoding only)  |

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
  minimal (4B header only)                       26 ns/op    37546680 ops/s
  small (token + 1 option)                       90 ns/op    10989830 ops/s
  multi-option (3 opts + payload)               190 ns/op     5260000 ops/s
  host+path (2 options)                         138 ns/op     7198226 ops/s
  payload (ACK + 12B body)                       38 ns/op    26128314 ops/s
  extended delta (opt 258)                       86 ns/op    11540017 ops/s

Encode (read + write):
  minimal (4B header only)                       32 ns/op    30992027 ops/s
  small (token + 1 option)                      106 ns/op     9370659 ops/s
  multi-option (3 opts + payload)               216 ns/op     4628666 ops/s
  host+path (2 options)                         159 ns/op     6265900 ops/s
  payload (ACK + 12B body)                       46 ns/op    21709709 ops/s
  extended delta (opt 258)                      104 ns/op     9615095 ops/s

Round-trip (decode + encode + decode):
  minimal (4B header only)                       58 ns/op    17071762 ops/s
  small (token + 1 option)                      195 ns/op     5105325 ops/s
  multi-option (3 opts + payload)               404 ns/op     2471514 ops/s
  host+path (2 options)                         296 ns/op     3370795 ops/s
  payload (ACK + 12B body)                       76 ns/op    13025843 ops/s
  extended delta (opt 258)                      188 ns/op     5294927 ops/s
```

Benchmarks use `ArenaAllocator` with retained capacity (reset per iteration, no syscalls after warmup).
