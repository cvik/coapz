const std = @import("std");
const coap = @import("root.zig");
const Packet = coap.Packet;

const print = std.debug.print;

const Result = struct {
    label: []const u8,
    iters: u64,
    elapsed_ns: u64,

    fn nsPerOp(self: Result) u64 {
        return self.elapsed_ns / self.iters;
    }

    fn opsPerSec(self: Result) u64 {
        return self.iters * std.time.ns_per_s / self.elapsed_ns;
    }

    fn display(self: Result) void {
        print("  {s:<40} {d:>8} ns/op    {d:>10} ops/s\n", .{
            self.label,
            self.nsPerOp(),
            self.opsPerSec(),
        });
    }
};

fn bench(label: []const u8, comptime func: anytype) Result {
    const warmup = 1_000;
    const min_ns = 500 * std.time.ns_per_ms;

    // warmup
    for (0..warmup) |_| {
        func();
    }

    // calibrate: run until we've spent at least min_ns
    var iters: u64 = 1_000;
    while (true) {
        var timer = std.time.Timer.start() catch unreachable;
        for (0..iters) |_| {
            func();
        }
        const elapsed = timer.read();
        if (elapsed >= min_ns) {
            return .{ .label = label, .iters = iters, .elapsed_ns = elapsed };
        }
        iters *= 2;
    }
}

// -- Test messages --

// Minimal: CON GET, no token, no options, no payload
const minimal_msg = [_]u8{ 0x40, 0x01, 0x00, 0x01 };

// Small: CON GET with 4-byte token and one uri_path option "check_ic"
const small_msg = [_]u8{
    0x44, 0x01, 0xba, 0x22, 0x0c, 0x53, 0x5f, 0xb9,
    0xb8, 0x63, 0x68, 0x65, 0x63, 0x6b, 0x5f, 0x69,
    0x63,
};

// Multi-option: CON POST with token, multiple uri_path options, and payload
const multi_opt_msg = [_]u8{
    0x44, 0x02, 0x3e, 0x6f, 0x77, 0x68, 0x52, 0x80,
    0xb1, 0x31, 0x01, 0x32, 0x01, 0x33, 0xff, 0x64,
    0x61, 0x74, 0x61,
};

// With host + path: CON GET with uri_host "localhost" and uri_path "tv1"
const host_path_msg = [_]u8{
    0x44, 0x01, 0x5D, 0x1F, 0x00, 0x00, 0x39, 0x74,
    0x39, 0x6C, 0x6F, 0x63, 0x61, 0x6C, 0x68, 0x6F,
    0x73, 0x74, 0x83, 0x74, 0x76, 0x31,
};

// ACK with payload "Hello World!"
const payload_msg = [_]u8{
    0x64, 0x45, 0x5D, 0x1F, 0x00, 0x00, 0x39, 0x74,
    0xFF, 0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x57,
    0x6F, 0x72, 0x6C, 0x64, 0x21,
};

// Extended option delta: no_response option (258)
const ext_delta_msg = [_]u8{ 0x40, 0x01, 0x00, 0x01, 0xD1, 0xF5, 0x02 };

const doNotOptimize = std.mem.doNotOptimizeAway;

fn decodeBench(comptime msg: []const u8) fn () void {
    return struct {
        var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
        fn run() void {
            _ = arena.reset(.retain_capacity);
            const alloc = arena.allocator();
            const pkt = Packet.read(alloc, msg) catch unreachable;
            doNotOptimize(pkt);
        }
    }.run;
}

fn encodeBench(comptime msg: []const u8) fn () void {
    return struct {
        var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
        fn run() void {
            _ = arena.reset(.retain_capacity);
            const alloc = arena.allocator();
            const pkt = Packet.read(alloc, msg) catch unreachable;
            const encoded = pkt.write() catch unreachable;
            doNotOptimize(encoded);
        }
    }.run;
}

fn roundtripBench(comptime msg: []const u8) fn () void {
    return struct {
        var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
        fn run() void {
            _ = arena.reset(.retain_capacity);
            const alloc = arena.allocator();
            const pkt = Packet.read(alloc, msg) catch unreachable;
            const encoded = pkt.write() catch unreachable;
            const pkt2 = Packet.read(alloc, encoded) catch unreachable;
            doNotOptimize(pkt2);
        }
    }.run;
}

pub fn main() void {
    print("\n  CoAP Packet Benchmarks\n", .{});
    print("  {s}\n\n", .{"-" ** 62});

    print("  Decode:\n", .{});
    bench("minimal (4B header only)", decodeBench(&minimal_msg)).display();
    bench("small (token + 1 option)", decodeBench(&small_msg)).display();
    bench("multi-option (3 opts + payload)", decodeBench(&multi_opt_msg)).display();
    bench("host+path (2 options)", decodeBench(&host_path_msg)).display();
    bench("payload (ACK + 12B body)", decodeBench(&payload_msg)).display();
    bench("extended delta (opt 258)", decodeBench(&ext_delta_msg)).display();

    print("\n  Encode (read + write):\n", .{});
    bench("minimal (4B header only)", encodeBench(&minimal_msg)).display();
    bench("small (token + 1 option)", encodeBench(&small_msg)).display();
    bench("multi-option (3 opts + payload)", encodeBench(&multi_opt_msg)).display();
    bench("host+path (2 options)", encodeBench(&host_path_msg)).display();
    bench("payload (ACK + 12B body)", encodeBench(&payload_msg)).display();
    bench("extended delta (opt 258)", encodeBench(&ext_delta_msg)).display();

    print("\n  Round-trip (decode + encode + decode):\n", .{});
    bench("minimal (4B header only)", roundtripBench(&minimal_msg)).display();
    bench("small (token + 1 option)", roundtripBench(&small_msg)).display();
    bench("multi-option (3 opts + payload)", roundtripBench(&multi_opt_msg)).display();
    bench("host+path (2 options)", roundtripBench(&host_path_msg)).display();
    bench("payload (ACK + 12B body)", roundtripBench(&payload_msg)).display();
    bench("extended delta (opt 258)", roundtripBench(&ext_delta_msg)).display();

    print("\n", .{});
}
