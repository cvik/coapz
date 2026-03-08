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
defer pkt.deinit(allocator);

// pkt.kind     == .confirmable
// pkt.code     == .get
// pkt.msg_id   == 0xba22
// pkt.token    == &[_]u8{ 0x0c, 0x53, 0x5f, 0xb9 }
// pkt.options[0].kind  == .uri_path
// pkt.options[0].value == "check_ic"
```

### Building packets

```zig
const coap = @import("coapz");

var options = [_]coap.Option{
    .{ .kind = .uri_path, .value = "sensor" },
    .{ .kind = .uri_path, .value = "temp" },
};

const pkt = coap.Packet{
    .kind = .confirmable,
    .code = .get,
    .msg_id = 0x1234,
    .token = &.{ 0xDE, 0xAD },
    .options = &options,
    .payload = &.{},
    .data_buf = &.{},
};

const encoded = try pkt.write(allocator);
defer allocator.free(encoded);
```

### Encoding a decoded packet

```zig
const encoded = try pkt.write(allocator);
defer allocator.free(encoded);
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
  minimal (4B header only)                       16 ns/op    62154070 ops/s
  small (token + 1 option)                       35 ns/op    28215709 ops/s
  multi-option (3 opts + payload)                66 ns/op    15066762 ops/s
  host+path (2 options)                          50 ns/op    19986943 ops/s
  payload (ACK + 12B body)                       25 ns/op    38955629 ops/s
  extended delta (opt 258)                       34 ns/op    29074014 ops/s

Encode (read + write):
  minimal (4B header only)                       16 ns/op    61655540 ops/s
  small (token + 1 option)                       39 ns/op    25337057 ops/s
  multi-option (3 opts + payload)                72 ns/op    13819127 ops/s
  host+path (2 options)                          56 ns/op    17744944 ops/s
  payload (ACK + 12B body)                       25 ns/op    39308928 ops/s
  extended delta (opt 258)                       38 ns/op    26017315 ops/s

Round-trip (decode + encode + decode):
  minimal (4B header only)                       28 ns/op    35168467 ops/s
  small (token + 1 option)                       72 ns/op    13789785 ops/s
  multi-option (3 opts + payload)               135 ns/op     7378439 ops/s
  host+path (2 options)                         105 ns/op     9464411 ops/s
  payload (ACK + 12B body)                       48 ns/op    20817496 ops/s
  extended delta (opt 258)                       70 ns/op    14200029 ops/s
```

Benchmarks use `ArenaAllocator` with retained capacity (reset per iteration, no syscalls after warmup).
