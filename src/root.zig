//! Constrained Application Protocol (CoAP) encode/decode library
//!
const std = @import("std");

/// CoAP message type (CON, NON, ACK, RST).
pub const MessageKind = enum(u8) {
    confirmable = 0,
    non_confirmable = 1,
    acknowledgement = 2,
    reset = 3,
};

/// CoAP method or response code.
pub const Code = enum(u8) {
    empty = 0,
    get = 1,
    post,
    put,
    delete,
    fetch,
    patch,
    ipatch,
    created = 65,
    deleted,
    valid,
    changed,
    content,
    @"continue" = 95,
    bad_request = 128,
    unauthorized,
    bad_option,
    forbidden,
    not_found,
    method_not_allowed,
    not_acceptable,
    request_entity_incomplete = 136,
    conflict,
    precondition_failed = 140,
    request_entity_too_large,
    unsupported_content_format = 143,
    unprocessable_entity = 150,
    too_many_requests = 157,
    internal_server_error = 160,
    not_implemented,
    bad_gateway,
    service_unavailable,
    gateway_timeout,
    proxying_not_supported,
    hop_limit_reached = 168,
    _,
};

/// CoAP option number. Supports all options from RFC 7252, 7641, 7959, and 8516.
pub const OptionKind = enum(u16) {
    unknown = 0,
    if_match = 1,
    uri_host = 3,
    etag = 4,
    if_none_match = 5,
    observe = 6,
    uri_port = 7,
    location_path = 8,
    oscore = 9,
    uri_path = 11,
    content_format = 12,
    max_age = 14,
    uri_query = 15,
    accept = 17,
    location_query = 20,
    block2 = 23,
    block1 = 27,
    size2 = 28,
    proxy_uri = 35,
    proxy_scheme = 39,
    size1 = 60,
    no_response = 258,
    _,
};

/// A single CoAP option (number + opaque value).
pub const Option = struct {
    kind: OptionKind,
    value: []const u8,
};

/// Errors returned when decoding/encoding a malformed CoAP packet.
pub const Error = error{
    MessageTooShort,
    InvalidVersion,
    InvalidTokenLength,
    TruncatedOption,
    EmptyPayload,
    UnsortedOptions,
    OutOfMemory,
};

/// Decoded CoAP packet. Owns its token, option values, and payload through
/// a single backing buffer. Call `deinit()` to free.
pub const Packet = struct {
    kind: MessageKind,
    code: Code,
    msg_id: u16,
    token: []const u8,
    options: []Option,
    payload: []const u8,
    data_buf: []u8,

    alloc: std.mem.Allocator,

    /// Decode a CoAP packet from raw bytes. Returns `Error` on malformed input.
    pub fn read(alloc: std.mem.Allocator, data: []const u8) Error!Packet {
        if (data.len < 4) return Error.MessageTooShort;
        const b0 = data[0];
        if (b0 >> 6 != 1) return Error.InvalidVersion;
        const b1 = data[1];
        const msg_id: u16 = @as(u16, data[2]) << 8 | data[3];
        const token_len: usize = b0 & 0xf;
        if (token_len > 8) return Error.InvalidTokenLength;
        if (data.len < 4 + token_len) return Error.MessageTooShort;

        // Pass 1: count options and compute total data size
        var pos: usize = 4 + token_len;
        var opt_count: usize = 0;
        var data_size: usize = token_len;
        var payload_start: usize = 0;

        while (pos < data.len) {
            const c0 = data[pos];
            pos += 1;
            if (c0 == 0xff) {
                if (pos == data.len) return Error.EmptyPayload;
                payload_start = pos;
                data_size += data.len - pos;
                break;
            }
            _ = try readVarLen(data, &pos, @intCast(c0 >> 4 & 0xf));
            const val_len = try readVarLen(data, &pos, @intCast(c0 & 0xf));
            if (pos + val_len > data.len) return Error.TruncatedOption;
            data_size += val_len;
            pos += val_len;
            opt_count += 1;
        }

        // Pass 2: allocate and populate
        const data_buf = alloc.alloc(u8, data_size) catch return Error.OutOfMemory;
        errdefer alloc.free(data_buf);
        const options = alloc.alloc(Option, opt_count) catch return Error.OutOfMemory;
        errdefer alloc.free(options);

        // Copy token
        var buf_pos: usize = 0;
        @memcpy(data_buf[0..token_len], data[4 .. 4 + token_len]);
        const token = data_buf[0..token_len];
        buf_pos = token_len;

        // Parse and copy options
        pos = 4 + token_len;
        var delta_sum: u32 = 0;
        for (options) |*opt| {
            const c0 = data[pos];
            pos += 1;
            delta_sum += try readVarLen(data, &pos, @intCast(c0 >> 4 & 0xf));
            const val_len = try readVarLen(data, &pos, @intCast(c0 & 0xf));
            @memcpy(data_buf[buf_pos .. buf_pos + val_len], data[pos .. pos + val_len]);
            opt.* = .{
                .kind = @enumFromInt(@as(u16, @intCast(delta_sum))),
                .value = data_buf[buf_pos .. buf_pos + val_len],
            };
            buf_pos += val_len;
            pos += val_len;
        }

        // Copy payload
        var payload: []const u8 = &[0]u8{};
        if (payload_start > 0) {
            const payload_len = data.len - payload_start;
            @memcpy(data_buf[buf_pos .. buf_pos + payload_len], data[payload_start..data.len]);
            payload = data_buf[buf_pos .. buf_pos + payload_len];
        }

        return .{
            .alloc = alloc,
            .kind = @enumFromInt(b0 >> 4 & 0x3),
            .code = @enumFromInt(b1),
            .msg_id = msg_id,
            .token = token,
            .options = options,
            .payload = payload,
            .data_buf = data_buf,
        };
    }

    /// Encode the packet to CoAP wire format. Caller owns the returned slice.
    pub fn write(self: Packet, allocator: std.mem.Allocator) Error![]u8 {
        // Calculate exact output size
        var size: usize = 4 + self.token.len;
        var prev: u16 = 0;
        for (self.options) |opt| {
            const num = @intFromEnum(opt.kind);
            if (num < prev) return Error.UnsortedOptions;
            const delta = num - prev;
            const len: u16 = @intCast(opt.value.len);
            size += 1 + extendedSize(delta) + extendedSize(len) + opt.value.len;
            prev = num;
        }
        if (self.payload.len > 0) {
            size += 1 + self.payload.len;
        }

        // Single allocation
        const buf = allocator.alloc(u8, size) catch return Error.OutOfMemory;
        errdefer allocator.free(buf);

        // Header
        const token_len: u8 = @intCast(self.token.len);
        buf[0] = (1 << 6) | (@as(u8, @intFromEnum(self.kind)) << 4) | token_len;
        buf[1] = @intFromEnum(self.code);
        buf[2] = @intCast(self.msg_id >> 8);
        buf[3] = @intCast(self.msg_id & 0xff);

        // Token
        var pos: usize = 4;
        @memcpy(buf[4 .. 4 + self.token.len], self.token);
        pos += self.token.len;

        // Options
        prev = 0;
        for (self.options) |opt| {
            const num = @intFromEnum(opt.kind);
            const delta = num - prev;
            const len: u16 = @intCast(opt.value.len);
            buf[pos] = (optNibble(delta) << 4) | optNibble(len);
            pos += 1;
            writeExtended(buf, &pos, delta);
            writeExtended(buf, &pos, len);
            @memcpy(buf[pos .. pos + opt.value.len], opt.value);
            pos += opt.value.len;
            prev = num;
        }

        // Payload
        if (self.payload.len > 0) {
            buf[pos] = 0xff;
            pos += 1;
            @memcpy(buf[pos .. pos + self.payload.len], self.payload);
        }

        return buf;
    }

    /// Free the backing buffer and options array.
    pub fn deinit(self: Packet) void {
        self.alloc.free(self.data_buf);
        self.alloc.free(self.options);
    }
};

fn optNibble(val: u16) u8 {
    if (val <= 12) return @intCast(val);
    if (val < 269) return 13;
    return 14;
}

fn writeExtended(buf: []u8, pos: *usize, val: u16) void {
    switch (optNibble(val)) {
        13 => {
            buf[pos.*] = @intCast(val - 13);
            pos.* += 1;
        },
        14 => {
            const ext = val - 269;
            buf[pos.*] = @intCast(ext >> 8);
            buf[pos.* + 1] = @intCast(ext & 0xff);
            pos.* += 2;
        },
        else => {},
    }
}

fn extendedSize(val: u16) usize {
    return switch (optNibble(val)) {
        13 => 1,
        14 => 2,
        else => 0,
    };
}

fn readVarLen(data: []const u8, pos: *usize, nibble: u4) Error!u16 {
    return switch (nibble) {
        13 => blk: {
            if (pos.* >= data.len) return Error.TruncatedOption;
            const v: u16 = data[pos.*];
            pos.* += 1;
            break :blk v + 13;
        },
        14 => blk: {
            if (pos.* + 1 >= data.len) return Error.TruncatedOption;
            const v: u16 = @as(u16, data[pos.*]) << 8 | data[pos.* + 1];
            pos.* += 2;
            break :blk std.math.add(u16, v, 269) catch return Error.TruncatedOption;
        },
        15 => Error.TruncatedOption,
        else => nibble,
    };
}

test "decode assertions" {
    const alloc = std.testing.allocator;
    const expectEqual = std.testing.expectEqual;
    const expectEqualSlices = std.testing.expectEqualSlices;

    // msg1: CON GET, msg_id=0xba22, token=4, 2 options (uri_path, uri_path)
    const msg1 = [_]u8{
        0x44, 0x01, 0xba, 0x22, 0x0c, 0x53, 0x5f, 0xb9,
        0xb8, 0x63, 0x68, 0x65, 0x63, 0x6b, 0x5f, 0x69,
        0x63,
    };
    const p1 = try Packet.read(alloc, &msg1);
    defer p1.deinit();
    try expectEqual(.confirmable, p1.kind);
    try expectEqual(.get, p1.code);
    try expectEqual(@as(u16, 0xba22), p1.msg_id);
    try expectEqualSlices(u8, &[_]u8{ 0x0c, 0x53, 0x5f, 0xb9 }, p1.token);
    try expectEqual(@as(usize, 1), p1.options.len);
    try expectEqual(OptionKind.uri_path, p1.options[0].kind);
    try expectEqualSlices(u8, "check_ic", p1.options[0].value);
    try expectEqual(@as(usize, 0), p1.payload.len);

    // msg2: CON POST, msg_id=0x3e6f, token=4, 4 options, payload "data"
    const msg2 = [_]u8{
        0x44, 0x02, 0x3e, 0x6f, 0x77, 0x68, 0x52, 0x80,
        0xb1, 0x31, 0x01, 0x32, 0x01, 0x33, 0xff, 0x64,
        0x61, 0x74, 0x61,
    };
    const p2 = try Packet.read(alloc, &msg2);
    defer p2.deinit();
    try expectEqual(.confirmable, p2.kind);
    try expectEqual(.post, p2.code);
    try expectEqual(@as(u16, 0x3e6f), p2.msg_id);
    try expectEqual(@as(usize, 3), p2.options.len);
    try expectEqualSlices(u8, "data", p2.payload);

    // msg3: CON GET, uri_host="localhost", uri_path="tv1"
    const msg3 = [_]u8{
        0x44, 0x01, 0x5D, 0x1F, 0x00, 0x00, 0x39, 0x74,
        0x39, 0x6C, 0x6F, 0x63, 0x61, 0x6C, 0x68, 0x6F,
        0x73, 0x74, 0x83, 0x74, 0x76, 0x31,
    };
    const p3 = try Packet.read(alloc, &msg3);
    defer p3.deinit();
    try expectEqual(.confirmable, p3.kind);
    try expectEqual(@as(usize, 2), p3.options.len);
    try expectEqual(OptionKind.uri_host, p3.options[0].kind);
    try expectEqualSlices(u8, "localhost", p3.options[0].value);
    try expectEqual(OptionKind.uri_path, p3.options[1].kind);
    try expectEqualSlices(u8, "tv1", p3.options[1].value);
    try expectEqual(@as(usize, 0), p3.payload.len);

    // msg4: ACK 2.05 Content, payload "Hello World!"
    const msg4 = [_]u8{
        0x64, 0x45, 0x5D, 0x1F, 0x00, 0x00, 0x39, 0x74,
        0xFF, 0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x57,
        0x6F, 0x72, 0x6C, 0x64, 0x21,
    };
    const p4 = try Packet.read(alloc, &msg4);
    defer p4.deinit();
    try expectEqual(.acknowledgement, p4.kind);
    try expectEqual(.content, p4.code);
    try expectEqual(@as(usize, 0), p4.options.len);
    try expectEqualSlices(u8, "Hello World!", p4.payload);

    // Round-trip all four
    for ([_][]const u8{ &msg1, &msg2, &msg3, &msg4 }) |msg| {
        const pkt = try Packet.read(alloc, msg);
        defer pkt.deinit();
        const enc = try pkt.write(alloc);
        defer alloc.free(enc);
        try expectEqualSlices(u8, msg, enc);
    }
}

test "error: truncated option delta" {
    const alloc = std.testing.allocator;
    // header: CON GET, tkl=0, msg_id=0, then option byte with delta nibble=15
    const msg = [_]u8{ 0x40, 0x01, 0x00, 0x00, 0xF0 };
    try std.testing.expectError(Error.TruncatedOption, Packet.read(alloc, &msg));
}

test "error: truncated option length" {
    const alloc = std.testing.allocator;
    // option byte: delta=0, length nibble=15
    const msg = [_]u8{ 0x40, 0x01, 0x00, 0x00, 0x0F };
    try std.testing.expectError(Error.TruncatedOption, Packet.read(alloc, &msg));
}

test "all message kinds" {
    const alloc = std.testing.allocator;
    const kinds = [_]MessageKind{ .confirmable, .non_confirmable, .acknowledgement, .reset };
    for (kinds, 0..) |kind, i| {
        var msg = [_]u8{ 0x40, 0x01, 0x00, 0x00 };
        msg[0] = (1 << 6) | (@as(u8, @intCast(i)) << 4);
        const pkt = try Packet.read(alloc, &msg);
        defer pkt.deinit();
        try std.testing.expectEqual(kind, pkt.kind);
        const enc = try pkt.write(alloc);
        defer alloc.free(enc);
        try std.testing.expectEqualSlices(u8, &msg, enc);
    }
}

test "message id boundaries" {
    const alloc = std.testing.allocator;
    const ids = [_]u16{ 0x0000, 0xFFFF, 0x0100 };
    for (ids) |id| {
        const msg = [_]u8{ 0x40, 0x01, @intCast(id >> 8), @intCast(id & 0xff) };
        const pkt = try Packet.read(alloc, &msg);
        defer pkt.deinit();
        try std.testing.expectEqual(id, pkt.msg_id);
        const enc = try pkt.write(alloc);
        defer alloc.free(enc);
        try std.testing.expectEqualSlices(u8, &msg, enc);
    }
}

test "token lengths" {
    const alloc = std.testing.allocator;
    const lens = [_]u8{ 0, 1, 2, 4, 8 };
    for (lens) |tl| {
        var buf: [12]u8 = undefined;
        buf[0] = (1 << 6) | tl;
        buf[1] = 0x01; // GET
        buf[2] = 0x00;
        buf[3] = 0x00;
        for (0..tl) |j| buf[4 + j] = @intCast(j + 0xA0);
        const msg = buf[0 .. 4 + tl];
        const pkt = try Packet.read(alloc, msg);
        defer pkt.deinit();
        try std.testing.expectEqual(@as(usize, tl), pkt.token.len);
        const enc = try pkt.write(alloc);
        defer alloc.free(enc);
        try std.testing.expectEqualSlices(u8, msg, enc);
    }
}

test "response codes" {
    const alloc = std.testing.allocator;
    const codes = [_]Code{
        .empty, .get, .delete, .created, .content, .@"continue",
        .bad_request, .not_found, .too_many_requests,
        .internal_server_error, .hop_limit_reached,
    };
    for (codes) |code| {
        const msg = [_]u8{ 0x40, @intFromEnum(code), 0x00, 0x00 };
        const pkt = try Packet.read(alloc, &msg);
        defer pkt.deinit();
        try std.testing.expectEqual(code, pkt.code);
        const enc = try pkt.write(alloc);
        defer alloc.free(enc);
        try std.testing.expectEqualSlices(u8, &msg, enc);
    }
}

test "option length boundaries" {
    const alloc = std.testing.allocator;
    // lengths: 0, 12 (max inline), 13 (1-byte ext), 268 (1-byte max), 269 (2-byte ext)
    const lens = [_]u16{ 0, 12, 13, 268, 269 };
    for (lens) |opt_len| {
        // Build packet: header(4) + option_header + value
        const ext_size: usize = if (opt_len <= 12) 0 else if (opt_len < 269) 1 else 2;
        const total = 4 + 1 + ext_size + opt_len;
        const buf = try alloc.alloc(u8, total);
        defer alloc.free(buf);
        buf[0] = 0x40;
        buf[1] = 0x01;
        buf[2] = 0x00;
        buf[3] = 0x00;
        // Option: delta=1 (if_match), length=opt_len
        // delta nibble = 1 (inline)
        const len_nibble: u8 = if (opt_len <= 12) @intCast(opt_len) else if (opt_len < 269) 13 else 14;
        buf[4] = (1 << 4) | len_nibble;
        var pos: usize = 5;
        if (opt_len >= 13 and opt_len < 269) {
            buf[pos] = @intCast(opt_len - 13);
            pos += 1;
        } else if (opt_len >= 269) {
            const ext = opt_len - 269;
            buf[pos] = @intCast(ext >> 8);
            buf[pos + 1] = @intCast(ext & 0xff);
            pos += 2;
        }
        for (0..opt_len) |j| buf[pos + j] = @intCast(j & 0xff);

        const pkt = try Packet.read(alloc, buf);
        defer pkt.deinit();
        try std.testing.expectEqual(@as(usize, 1), pkt.options.len);
        try std.testing.expectEqual(@as(usize, opt_len), pkt.options[0].value.len);
        const enc = try pkt.write(alloc);
        defer alloc.free(enc);
        try std.testing.expectEqualSlices(u8, buf, enc);
    }
}

test "option delta boundaries" {
    const alloc = std.testing.allocator;
    // deltas: 1 (inline), 12 (max inline), 13 (1-byte ext), 268 (1-byte max), 269 (2-byte ext)
    const deltas = [_]u16{ 1, 12, 13, 268, 269 };
    for (deltas) |delta| {
        const ext_size: usize = if (delta <= 12) 0 else if (delta < 269) 1 else 2;
        const total = 4 + 1 + ext_size;
        const buf = try alloc.alloc(u8, total);
        defer alloc.free(buf);
        buf[0] = 0x40;
        buf[1] = 0x01;
        buf[2] = 0x00;
        buf[3] = 0x00;
        const delta_nibble: u8 = if (delta <= 12) @intCast(delta) else if (delta < 269) 13 else 14;
        buf[4] = (delta_nibble << 4) | 0; // length=0
        var pos: usize = 5;
        if (delta >= 13 and delta < 269) {
            buf[pos] = @intCast(delta - 13);
            pos += 1;
        } else if (delta >= 269) {
            const ext = delta - 269;
            buf[pos] = @intCast(ext >> 8);
            buf[pos + 1] = @intCast(ext & 0xff);
            pos += 2;
        }

        const pkt = try Packet.read(alloc, buf);
        defer pkt.deinit();
        try std.testing.expectEqual(@as(usize, 1), pkt.options.len);
        try std.testing.expectEqual(@as(u16, delta), @intFromEnum(pkt.options[0].kind));
        const enc = try pkt.write(alloc);
        defer alloc.free(enc);
        try std.testing.expectEqualSlices(u8, buf, enc);
    }
}

test "extended delta and length combined" {
    const alloc = std.testing.allocator;
    // Option: delta=300 (2-byte ext), length=300 (2-byte ext)
    // delta nibble=14, ext=300-269=31; length nibble=14, ext=300-269=31
    var msg: [4 + 1 + 2 + 2 + 300]u8 = undefined;
    msg[0] = 0x40;
    msg[1] = 0x01;
    msg[2] = 0x00;
    msg[3] = 0x00;
    msg[4] = 0xEE; // both nibbles = 14
    // delta ext = 31 (big-endian)
    msg[5] = 0x00;
    msg[6] = 31;
    // length ext = 31
    msg[7] = 0x00;
    msg[8] = 31;
    for (0..300) |j| msg[9 + j] = @intCast(j & 0xff);

    const pkt = try Packet.read(alloc, &msg);
    defer pkt.deinit();
    try std.testing.expectEqual(@as(usize, 1), pkt.options.len);
    try std.testing.expectEqual(@as(u16, 300), @intFromEnum(pkt.options[0].kind));
    try std.testing.expectEqual(@as(usize, 300), pkt.options[0].value.len);
    const enc = try pkt.write(alloc);
    defer alloc.free(enc);
    try std.testing.expectEqualSlices(u8, &msg, enc);
}

test "zero-length option values" {
    const alloc = std.testing.allocator;
    // if_none_match (5) with zero-length value
    const msg = [_]u8{ 0x40, 0x01, 0x00, 0x00, 0x50 };
    const pkt = try Packet.read(alloc, &msg);
    defer pkt.deinit();
    try std.testing.expectEqual(@as(usize, 1), pkt.options.len);
    try std.testing.expectEqual(OptionKind.if_none_match, pkt.options[0].kind);
    try std.testing.expectEqual(@as(usize, 0), pkt.options[0].value.len);
    const enc = try pkt.write(alloc);
    defer alloc.free(enc);
    try std.testing.expectEqualSlices(u8, &msg, enc);
}

test "multiple options with accumulating deltas" {
    const alloc = std.testing.allocator;
    // Three uri_path options (delta=11, then 0, 0): "a", "b", "c"
    const msg = [_]u8{
        0x40, 0x01, 0x00, 0x00,
        0xB1, 0x61, // delta=11 (uri_path), len=1, "a"
        0x01, 0x62, // delta=0 (uri_path again), len=1, "b"
        0x01, 0x63, // delta=0 (uri_path again), len=1, "c"
    };
    const pkt = try Packet.read(alloc, &msg);
    defer pkt.deinit();
    try std.testing.expectEqual(@as(usize, 3), pkt.options.len);
    for (pkt.options) |opt| try std.testing.expectEqual(OptionKind.uri_path, opt.kind);
    try std.testing.expectEqualSlices(u8, "a", pkt.options[0].value);
    try std.testing.expectEqualSlices(u8, "b", pkt.options[1].value);
    try std.testing.expectEqualSlices(u8, "c", pkt.options[2].value);
    const enc = try pkt.write(alloc);
    defer alloc.free(enc);
    try std.testing.expectEqualSlices(u8, &msg, enc);
}

test "option kinds" {
    const alloc = std.testing.allocator;
    // All 21 known OptionKind values in ascending order, each with 0-byte value
    const kind_nums = [_]u16{ 1, 3, 4, 5, 6, 7, 8, 9, 11, 12, 14, 15, 17, 20, 23, 27, 28, 35, 39, 60, 258 };
    // Build packet: header + 21 option headers with appropriate deltas
    var buf_arr: [256]u8 = undefined;
    buf_arr[0] = 0x40;
    buf_arr[1] = 0x01;
    buf_arr[2] = 0x00;
    buf_arr[3] = 0x00;
    var pos: usize = 4;
    var prev: u16 = 0;
    for (kind_nums) |num| {
        const delta = num - prev;
        const delta_nibble = optNibble(delta);
        buf_arr[pos] = (delta_nibble << 4) | 0;
        pos += 1;
        writeExtended(&buf_arr, &pos, delta);
        prev = num;
    }
    const msg = buf_arr[0..pos];

    const pkt = try Packet.read(alloc, msg);
    defer pkt.deinit();
    try std.testing.expectEqual(@as(usize, 21), pkt.options.len);
    for (pkt.options, 0..) |opt, i| {
        try std.testing.expectEqual(@as(u16, kind_nums[i]), @intFromEnum(opt.kind));
    }
    const enc = try pkt.write(alloc);
    defer alloc.free(enc);
    try std.testing.expectEqualSlices(u8, msg, enc);
}

test "payload edge cases" {
    const alloc = std.testing.allocator;

    // No payload
    const msg_no_payload = [_]u8{ 0x40, 0x01, 0x00, 0x00 };
    const pkt1 = try Packet.read(alloc, &msg_no_payload);
    defer pkt1.deinit();
    try std.testing.expectEqual(@as(usize, 0), pkt1.payload.len);

    // 1-byte payload
    const msg_1byte = [_]u8{ 0x40, 0x01, 0x00, 0x00, 0xFF, 0x42 };
    const pkt2 = try Packet.read(alloc, &msg_1byte);
    defer pkt2.deinit();
    try std.testing.expectEqualSlices(u8, &[_]u8{0x42}, pkt2.payload);

    // Payload after options
    const msg_opt_payload = [_]u8{
        0x40, 0x01, 0x00, 0x00,
        0xB0, // uri_path, len=0
        0xFF, 0xAA, 0xBB,
    };
    const pkt3 = try Packet.read(alloc, &msg_opt_payload);
    defer pkt3.deinit();
    try std.testing.expectEqual(@as(usize, 1), pkt3.options.len);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xAA, 0xBB }, pkt3.payload);

    // Round-trip all
    for ([_][]const u8{ &msg_no_payload, &msg_1byte, &msg_opt_payload }) |msg| {
        const pkt = try Packet.read(alloc, msg);
        defer pkt.deinit();
        const enc = try pkt.write(alloc);
        defer alloc.free(enc);
        try std.testing.expectEqualSlices(u8, msg, enc);
    }
}

test "rfc7641 observe option" {
    const alloc = std.testing.allocator;
    // CON GET with Observe option (6) = sequence 1
    const msg = [_]u8{
        0x41, 0x01, 0x00, 0x01, 0xAB, // header: tkl=1, token=0xAB
        0x61, 0x01, // option: delta=6 (observe), len=1, value=0x01
    };
    const pkt = try Packet.read(alloc, &msg);
    defer pkt.deinit();
    try std.testing.expectEqual(@as(usize, 1), pkt.options.len);
    try std.testing.expectEqual(OptionKind.observe, pkt.options[0].kind);
    try std.testing.expectEqualSlices(u8, &[_]u8{0x01}, pkt.options[0].value);
    const enc = try pkt.write(alloc);
    defer alloc.free(enc);
    try std.testing.expectEqualSlices(u8, &msg, enc);
}

test "rfc7959 block options" {
    const alloc = std.testing.allocator;
    // CON GET with Block2 (23), Block1 (27), Size2 (28)
    // Ascending order: 23, 27, 28
    const msg = [_]u8{
        0x40, 0x01, 0x00, 0x00,
        0xD1, 0x0A, 0x06, // delta=23 (ext 10), len=1, value=0x06 (Block2)
        0x41, 0x15, // delta=4 (->27 Block1), len=1, value=0x15
        0x12, 0x01, 0x00, // delta=1 (->28 Size2), len=2, value=0x0100
    };
    const pkt = try Packet.read(alloc, &msg);
    defer pkt.deinit();
    try std.testing.expectEqual(@as(usize, 3), pkt.options.len);
    try std.testing.expectEqual(OptionKind.block2, pkt.options[0].kind);
    try std.testing.expectEqual(OptionKind.block1, pkt.options[1].kind);
    try std.testing.expectEqual(OptionKind.size2, pkt.options[2].kind);
    const enc = try pkt.write(alloc);
    defer alloc.free(enc);
    try std.testing.expectEqualSlices(u8, &msg, enc);
}

test "rfc8516 too many requests" {
    const alloc = std.testing.allocator;
    // ACK 4.29 Too Many Requests
    const msg = [_]u8{ 0x60, 0x9D, 0x00, 0x01 };
    const pkt = try Packet.read(alloc, &msg);
    defer pkt.deinit();
    try std.testing.expectEqual(.acknowledgement, pkt.kind);
    try std.testing.expectEqual(.too_many_requests, pkt.code);
    try std.testing.expectEqual(@as(u16, 1), pkt.msg_id);
    const enc = try pkt.write(alloc);
    defer alloc.free(enc);
    try std.testing.expectEqualSlices(u8, &msg, enc);
}

test "round-trip" {
    const alloc = std.testing.allocator;

    const messages = [_][]const u8{
        // confirmable GET with token and options
        &[_]u8{ 0x44, 0x01, 0xba, 0x22, 0x0c, 0x53, 0x5f, 0xb9, 0xb8, 0x63, 0x68, 0x65, 0x63, 0x6b, 0x5f, 0x69, 0x63 },
        // confirmable POST with token, options, and payload "data"
        &[_]u8{ 0x44, 0x02, 0x3e, 0x6f, 0x77, 0x68, 0x52, 0x80, 0xb1, 0x31, 0x01, 0x32, 0x01, 0x33, 0xff, 0x64, 0x61, 0x74, 0x61 },
        // confirmable GET with options, no payload
        &[_]u8{ 0x44, 0x01, 0x5D, 0x1F, 0x00, 0x00, 0x39, 0x74, 0x39, 0x6C, 0x6F, 0x63, 0x61, 0x6C, 0x68, 0x6F, 0x73, 0x74, 0x83, 0x74, 0x76, 0x31 },
        // acknowledgement 2.05 Content with payload "Hello World!"
        &[_]u8{ 0x64, 0x45, 0x5D, 0x1F, 0x00, 0x00, 0x39, 0x74, 0xFF, 0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x57, 0x6F, 0x72, 0x6C, 0x64, 0x21 },
    };

    for (messages) |msg| {
        const pkt = try Packet.read(alloc, msg);
        defer pkt.deinit();
        const encoded = try pkt.write(alloc);
        defer alloc.free(encoded);
        try std.testing.expectEqualSlices(u8, msg, encoded);
    }
}

test "round-trip with extended option delta" {
    const alloc = std.testing.allocator;

    // Packet with no_response option (number 258) requiring extended delta encoding:
    // header: ver=1 CON tkl=0, code=GET, msg_id=0x0001
    // option: delta=258 (nibble=13, ext=245), len=1, value=0x02
    const msg = [_]u8{ 0x40, 0x01, 0x00, 0x01, 0xD1, 0xF5, 0x02 };

    const pkt = try Packet.read(alloc, &msg);
    defer pkt.deinit();

    try std.testing.expectEqual(.confirmable, pkt.kind);
    try std.testing.expectEqual(.get, pkt.code);
    try std.testing.expectEqual(@as(u16, 1), pkt.msg_id);
    try std.testing.expectEqual(@as(usize, 0), pkt.token.len);
    try std.testing.expectEqual(@as(usize, 1), pkt.options.len);
    try std.testing.expectEqual(.no_response, pkt.options[0].kind);
    try std.testing.expectEqualSlices(u8, &[_]u8{0x02}, pkt.options[0].value);

    const encoded = try pkt.write(alloc);
    defer alloc.free(encoded);
    try std.testing.expectEqualSlices(u8, &msg, encoded);
}

test "error: empty message" {
    const alloc = std.testing.allocator;
    try std.testing.expectError(Error.MessageTooShort, Packet.read(alloc, &[_]u8{}));
}

test "error: header too short" {
    const alloc = std.testing.allocator;
    try std.testing.expectError(Error.MessageTooShort, Packet.read(alloc, &[_]u8{0x40}));
    try std.testing.expectError(Error.MessageTooShort, Packet.read(alloc, &[_]u8{ 0x40, 0x01 }));
    try std.testing.expectError(Error.MessageTooShort, Packet.read(alloc, &[_]u8{ 0x40, 0x01, 0x00 }));
}

test "error: invalid token length" {
    const alloc = std.testing.allocator;
    // TKL=9 (reserved)
    try std.testing.expectError(Error.InvalidTokenLength, Packet.read(alloc, &[_]u8{ 0x49, 0x01, 0x00, 0x00 }));
    // TKL=15 (reserved)
    try std.testing.expectError(Error.InvalidTokenLength, Packet.read(alloc, &[_]u8{ 0x4F, 0x01, 0x00, 0x00 }));
}

test "error: token extends past data" {
    const alloc = std.testing.allocator;
    // TKL=4 but only 1 byte after header
    try std.testing.expectError(Error.MessageTooShort, Packet.read(alloc, &[_]u8{ 0x44, 0x01, 0x00, 0x00, 0xAA }));
}

test "error: truncated 1-byte extended delta" {
    const alloc = std.testing.allocator;
    // Option byte: delta nibble=13 (needs 1 ext byte), but no byte follows
    try std.testing.expectError(Error.TruncatedOption, Packet.read(alloc, &[_]u8{ 0x40, 0x01, 0x00, 0x00, 0xD0 }));
}

test "error: truncated 2-byte extended delta" {
    const alloc = std.testing.allocator;
    // Option byte: delta nibble=14 (needs 2 ext bytes), but only 1 follows
    try std.testing.expectError(Error.TruncatedOption, Packet.read(alloc, &[_]u8{ 0x40, 0x01, 0x00, 0x00, 0xE0, 0x00 }));
}

test "error: truncated 1-byte extended length" {
    const alloc = std.testing.allocator;
    // delta=0 inline, length nibble=13 (needs 1 ext byte), but no byte follows
    try std.testing.expectError(Error.TruncatedOption, Packet.read(alloc, &[_]u8{ 0x40, 0x01, 0x00, 0x00, 0x0D }));
}

test "error: truncated 2-byte extended length" {
    const alloc = std.testing.allocator;
    // delta=0 inline, length nibble=14 (needs 2 ext bytes), but only 1 follows
    try std.testing.expectError(Error.TruncatedOption, Packet.read(alloc, &[_]u8{ 0x40, 0x01, 0x00, 0x00, 0x0E, 0x00 }));
}

test "error: option value extends past data" {
    const alloc = std.testing.allocator;
    // Option: delta=1, length=5, but only 2 value bytes present
    try std.testing.expectError(Error.TruncatedOption, Packet.read(alloc, &[_]u8{ 0x40, 0x01, 0x00, 0x00, 0x15, 0xAA, 0xBB }));
}

test "error: empty payload after marker" {
    const alloc = std.testing.allocator;
    // Payload marker 0xFF with no bytes following
    try std.testing.expectError(Error.EmptyPayload, Packet.read(alloc, &[_]u8{ 0x40, 0x01, 0x00, 0x00, 0xFF }));
}

test "error: empty payload after options" {
    const alloc = std.testing.allocator;
    // Option then payload marker with no bytes following
    try std.testing.expectError(Error.EmptyPayload, Packet.read(alloc, &[_]u8{ 0x40, 0x01, 0x00, 0x00, 0xB0, 0xFF }));
}

test "error: invalid version" {
    const alloc = std.testing.allocator;
    // Version 0 (0x00 in top 2 bits)
    try std.testing.expectError(Error.InvalidVersion, Packet.read(alloc, &[_]u8{ 0x00, 0x01, 0x00, 0x00 }));
    // Version 2 (0x80 in top 2 bits)
    try std.testing.expectError(Error.InvalidVersion, Packet.read(alloc, &[_]u8{ 0x80, 0x01, 0x00, 0x00 }));
    // Version 3 (0xC0 in top 2 bits)
    try std.testing.expectError(Error.InvalidVersion, Packet.read(alloc, &[_]u8{ 0xC0, 0x01, 0x00, 0x00 }));
}

test "unknown response code round-trip" {
    const alloc = std.testing.allocator;
    // Code byte 0x08 is unassigned but valid on the wire
    const msg = [_]u8{ 0x40, 0x08, 0x00, 0x00 };
    const pkt = try Packet.read(alloc, &msg);
    defer pkt.deinit();
    try std.testing.expectEqual(@as(u8, 0x08), @intFromEnum(pkt.code));
    const enc = try pkt.write(alloc);
    defer alloc.free(enc);
    try std.testing.expectEqualSlices(u8, &msg, enc);
}

test "error: unsorted options in write" {
    const alloc = std.testing.allocator;
    // Construct a packet with unsorted options
    const data_buf = try alloc.alloc(u8, 0);
    defer alloc.free(data_buf);
    var opts = [_]Option{
        .{ .kind = .uri_path, .value = &.{} },
        .{ .kind = .uri_host, .value = &.{} }, // uri_host(3) < uri_path(11)
    };
    const pkt = Packet{
        .alloc = alloc,
        .kind = .confirmable,
        .code = .get,
        .msg_id = 0,
        .token = &.{},
        .options = &opts,
        .payload = &.{},
        .data_buf = data_buf,
    };
    try std.testing.expectError(Error.UnsortedOptions, pkt.write(alloc));
}
