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

    /// Option value format per RFC 7252 Table 5.
    pub const Format = enum { empty, @"opaque", uint, string };

    pub fn format(self: OptionKind) Format {
        return switch (self) {
            .if_none_match => .empty,
            .unknown, .if_match, .etag, .oscore => .@"opaque",
            .uri_host, .location_path, .uri_path,
            .uri_query, .location_query,
            .proxy_uri, .proxy_scheme,
            => .string,
            .observe, .uri_port, .content_format,
            .max_age, .accept, .block2, .block1,
            .size2, .size1, .no_response,
            => .uint,
            _ => .@"opaque",
        };
    }
};

pub const ContentFormat = @import("content_format.zig").ContentFormat;

/// Observe option registration values per RFC 7641 §2.
pub const Observe = enum(u32) {
    subscribe = 0,
    unsubscribe = 1,
    _,
};

/// Parsed block option value per RFC 7959 §2.2.
pub const BlockValue = struct {
    num: u32,
    more: bool,
    szx: u3,

    /// Block size in bytes: 2^(szx + 4).
    pub fn size(self: BlockValue) u16 {
        return @as(u16, 1) << (@as(u4, self.szx) + 4);
    }

    /// Encode as a CoAP block option (1-3 bytes per RFC 7959 §2.2).
    pub fn option(self: BlockValue, kind: OptionKind, buf: *[3]u8) Option {
        const val: u32 = (self.num << 4) | (@as(u32, @intFromBool(self.more)) << 3) | self.szx;
        if (val <= 0xff) {
            buf[0] = @intCast(val);
            return .{ .kind = kind, .value = buf[0..1] };
        } else if (val <= 0xffff) {
            buf[0] = @intCast(val >> 8);
            buf[1] = @intCast(val & 0xff);
            return .{ .kind = kind, .value = buf[0..2] };
        } else {
            buf[0] = @intCast(val >> 16);
            buf[1] = @intCast(val >> 8 & 0xff);
            buf[2] = @intCast(val & 0xff);
            return .{ .kind = kind, .value = buf[0..3] };
        }
    }
};

/// Iterator over options matching a specific kind.
pub const OptionIterator = struct {
    options: []const Option,
    kind: OptionKind,
    pos: usize = 0,

    pub fn next(self: *OptionIterator) ?Option {
        while (self.pos < self.options.len) {
            const opt = self.options[self.pos];
            self.pos += 1;
            if (opt.kind == self.kind) return opt;
        }
        return null;
    }

    pub fn reset(self: *OptionIterator) void {
        self.pos = 0;
    }
};

/// A single CoAP option (number + opaque value).
pub const Option = struct {
    kind: OptionKind,
    value: []const u8,

    /// Create an option with an empty value (e.g. if_none_match).
    pub fn empty(kind: OptionKind) Option {
        return .{ .kind = kind, .value = &.{} };
    }

    /// Create an option with a uint value, using minimal bytes per RFC 7252 §3.2.
    pub fn uint(kind: OptionKind, val: u32, buf: *[4]u8) Option {
        if (val == 0) return .{ .kind = kind, .value = &.{} };
        buf[0] = @intCast(val >> 24);
        buf[1] = @intCast(val >> 16 & 0xff);
        buf[2] = @intCast(val >> 8 & 0xff);
        buf[3] = @intCast(val & 0xff);
        const skip: usize = if (buf[0] != 0) 0 else if (buf[1] != 0) 1 else if (buf[2] != 0) 2 else 3;
        return .{ .kind = kind, .value = buf[skip..] };
    }

    /// Create a content_format option from a ContentFormat value.
    pub fn content_format(fmt: ContentFormat, buf: *[2]u8) Option {
        const val: u16 = @intFromEnum(fmt);
        buf[0] = @intCast(val >> 8);
        buf[1] = @intCast(val & 0xff);
        const skip: usize = if (buf[0] != 0) 0 else 1;
        return .{ .kind = .content_format, .value = buf[skip..] };
    }

    /// Interpret value as a big-endian uint (0-4 bytes, per RFC 7252 §3.2).
    /// Empty value returns 0. Returns null if value exceeds 4 bytes.
    pub fn as_uint(self: Option) ?u32 {
        if (self.value.len > 4) return null;
        var result: u32 = 0;
        for (self.value) |b| result = result << 8 | b;
        return result;
    }

    /// Return value as a string (CoAP strings are UTF-8, no interpretation needed).
    pub fn as_string(self: Option) []const u8 {
        return self.value;
    }

    /// Interpret value as a ContentFormat enum.
    pub fn as_content_format(self: Option) ?ContentFormat {
        const val = self.as_uint() orelse return null;
        return ContentFormat.from_uint(val);
    }

    /// Interpret value as a block option (RFC 7959 §2.2).
    /// Valid for 1-3 byte values. Returns null otherwise.
    pub fn as_block(self: Option) ?BlockValue {
        if (self.value.len == 0 or self.value.len > 3) return null;
        const val = self.as_uint() orelse return null;
        return .{
            .num = val >> 4,
            .more = val & 0x08 != 0,
            .szx = @intCast(val & 0x07),
        };
    }
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
    BufferTooSmall,
};

/// Decoded CoAP packet. Owns its token, option values, and payload through
/// a single backing buffer. Call `deinit()` to free.
pub const Packet = struct {
    kind: MessageKind,
    code: Code,
    msg_id: u16,
    token: []const u8,
    options: []const Option,
    payload: []const u8,
    data_buf: []const u8,

    /// Find the first option matching the given kind.
    pub fn find_option(self: Packet, kind: OptionKind) ?Option {
        for (self.options) |opt| {
            if (opt.kind == kind) return opt;
        }
        return null;
    }

    /// Return an iterator over all options matching the given kind.
    pub fn find_options(self: Packet, kind: OptionKind) OptionIterator {
        return .{ .options = self.options, .kind = kind };
    }

    /// Extract the message kind from raw wire data without decoding.
    pub fn peekKind(data: []const u8) ?MessageKind {
        if (data.len < 1) return null;
        return @enumFromInt((data[0] >> 4) & 0x03);
    }

    /// Extract the message ID from raw wire data without decoding.
    pub fn peekMsgId(data: []const u8) ?u16 {
        if (data.len < 4) return null;
        return @as(u16, data[2]) << 8 | data[3];
    }

    /// Scan raw wire data for the first option matching `kind` without allocating.
    /// The returned Option's value points directly into `data`.
    pub fn peekOption(data: []const u8, kind: OptionKind) ?Option {
        if (data.len < 4) return null;
        const tkl: usize = data[0] & 0x0F;
        if (tkl > 8 or data.len < 4 + tkl) return null;
        var pos: usize = 4 + tkl;
        var opt_num: u32 = 0;
        const target: u32 = @intFromEnum(kind);

        while (pos < data.len) {
            const c0 = data[pos];
            pos += 1;
            if (c0 == 0xff) break;
            const delta: u32 = readVarLen(data, &pos, @intCast(c0 >> 4 & 0xf)) catch return null;
            const val_len: usize = readVarLen(data, &pos, @intCast(c0 & 0xf)) catch return null;
            if (pos + val_len > data.len) return null;
            opt_num += delta;

            if (opt_num == target) {
                return .{ .kind = kind, .value = data[pos..][0..val_len] };
            }
            if (opt_num > target) return null;

            pos += val_len;
        }
        return null;
    }

    /// Write a 4-byte empty ACK into `buf`.
    pub fn emptyAck(msg_id: u16, buf: *[4]u8) []const u8 {
        buf[0] = 0x60;
        buf[1] = 0x00;
        buf[2] = @intCast(msg_id >> 8);
        buf[3] = @intCast(msg_id & 0xff);
        return buf;
    }

    /// Write a 4-byte empty RST into `buf`.
    pub fn emptyRst(msg_id: u16, buf: *[4]u8) []const u8 {
        buf[0] = 0x70;
        buf[1] = 0x00;
        buf[2] = @intCast(msg_id >> 8);
        buf[3] = @intCast(msg_id & 0xff);
        return buf;
    }

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
            .kind = @enumFromInt(b0 >> 4 & 0x3),
            .code = @enumFromInt(b1),
            .msg_id = msg_id,
            .token = token,
            .options = options,
            .payload = payload,
            .data_buf = data_buf,
        };
    }

    /// Returns the exact encoded size in bytes without writing anything.
    /// Validates option sort order.
    pub fn encodedSize(self: Packet) Error!usize {
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
        return size;
    }

    /// Encode into a caller-provided buffer. Returns the filled subslice.
    pub fn writeBuf(self: Packet, buf: []u8) Error![]u8 {
        return writeAll(self, buf);
    }

    /// Encode the packet to CoAP wire format. Caller owns the returned slice.
    pub fn write(self: Packet, allocator: std.mem.Allocator) Error![]u8 {
        const size = try self.encodedSize();
        const buf = allocator.alloc(u8, size) catch return Error.OutOfMemory;
        errdefer allocator.free(buf);
        return writeAll(self, buf);
    }

    fn writeAll(self: Packet, buf: []u8) Error![]u8 {
        const size = try self.encodedSize();
        if (buf.len < size) return Error.BufferTooSmall;

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
        var prev: u16 = 0;
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

        return buf[0..size];
    }

    /// Free the backing buffer and options array.
    pub fn deinit(self: Packet, allocator: std.mem.Allocator) void {
        allocator.free(self.data_buf);
        allocator.free(self.options);
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
    defer p1.deinit(alloc);
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
    defer p2.deinit(alloc);
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
    defer p3.deinit(alloc);
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
    defer p4.deinit(alloc);
    try expectEqual(.acknowledgement, p4.kind);
    try expectEqual(.content, p4.code);
    try expectEqual(@as(usize, 0), p4.options.len);
    try expectEqualSlices(u8, "Hello World!", p4.payload);

    // Round-trip all four
    for ([_][]const u8{ &msg1, &msg2, &msg3, &msg4 }) |msg| {
        const pkt = try Packet.read(alloc, msg);
        defer pkt.deinit(alloc);
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
        defer pkt.deinit(alloc);
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
        defer pkt.deinit(alloc);
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
        defer pkt.deinit(alloc);
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
        defer pkt.deinit(alloc);
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
        defer pkt.deinit(alloc);
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
        defer pkt.deinit(alloc);
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
    defer pkt.deinit(alloc);
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
    defer pkt.deinit(alloc);
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
    defer pkt.deinit(alloc);
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
    defer pkt.deinit(alloc);
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
    defer pkt1.deinit(alloc);
    try std.testing.expectEqual(@as(usize, 0), pkt1.payload.len);

    // 1-byte payload
    const msg_1byte = [_]u8{ 0x40, 0x01, 0x00, 0x00, 0xFF, 0x42 };
    const pkt2 = try Packet.read(alloc, &msg_1byte);
    defer pkt2.deinit(alloc);
    try std.testing.expectEqualSlices(u8, &[_]u8{0x42}, pkt2.payload);

    // Payload after options
    const msg_opt_payload = [_]u8{
        0x40, 0x01, 0x00, 0x00,
        0xB0, // uri_path, len=0
        0xFF, 0xAA, 0xBB,
    };
    const pkt3 = try Packet.read(alloc, &msg_opt_payload);
    defer pkt3.deinit(alloc);
    try std.testing.expectEqual(@as(usize, 1), pkt3.options.len);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xAA, 0xBB }, pkt3.payload);

    // Round-trip all
    for ([_][]const u8{ &msg_no_payload, &msg_1byte, &msg_opt_payload }) |msg| {
        const pkt = try Packet.read(alloc, msg);
        defer pkt.deinit(alloc);
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
    defer pkt.deinit(alloc);
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
    defer pkt.deinit(alloc);
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
    defer pkt.deinit(alloc);
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
        defer pkt.deinit(alloc);
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
    defer pkt.deinit(alloc);

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
    defer pkt.deinit(alloc);
    try std.testing.expectEqual(@as(u8, 0x08), @intFromEnum(pkt.code));
    const enc = try pkt.write(alloc);
    defer alloc.free(enc);
    try std.testing.expectEqualSlices(u8, &msg, enc);
}

test "as_uint" {
    const opt = Option{ .kind = .max_age, .value = &.{} };
    try std.testing.expectEqual(@as(u32, 0), opt.as_uint().?);

    const opt1 = Option{ .kind = .max_age, .value = &.{0x2A} };
    try std.testing.expectEqual(@as(u32, 42), opt1.as_uint().?);

    const opt2 = Option{ .kind = .max_age, .value = &.{ 0x01, 0x00 } };
    try std.testing.expectEqual(@as(u32, 256), opt2.as_uint().?);

    const opt4 = Option{ .kind = .max_age, .value = &.{ 0x00, 0x01, 0x51, 0x80 } };
    try std.testing.expectEqual(@as(u32, 86400), opt4.as_uint().?);

    // 5 bytes => null
    const opt5 = Option{ .kind = .max_age, .value = &.{ 0x01, 0x02, 0x03, 0x04, 0x05 } };
    try std.testing.expectEqual(@as(?u32, null), opt5.as_uint());
}

test "as_content_format" {
    const json_opt = Option{ .kind = .content_format, .value = &.{50} };
    try std.testing.expectEqual(ContentFormat.json, json_opt.as_content_format().?);

    const cbor_opt = Option{ .kind = .content_format, .value = &.{60} };
    try std.testing.expectEqual(ContentFormat.cbor, cbor_opt.as_content_format().?);

    // Unknown value via wildcard
    const unknown_opt = Option{ .kind = .content_format, .value = &.{ 0x27, 0x0F } };
    try std.testing.expectEqual(@as(u16, 9999), @intFromEnum(unknown_opt.as_content_format().?));
}

test "as_block" {
    // 1-byte: num=0, more=true, szx=6 => 0x0E
    const b1 = Option{ .kind = .block2, .value = &.{0x0E} };
    const bv1 = b1.as_block().?;
    try std.testing.expectEqual(@as(u32, 0), bv1.num);
    try std.testing.expectEqual(true, bv1.more);
    try std.testing.expectEqual(@as(u3, 6), bv1.szx);

    // 2-byte: num=4, more=false, szx=2 => 0x00 0x42
    const b2 = Option{ .kind = .block1, .value = &.{ 0x00, 0x42 } };
    const bv2 = b2.as_block().?;
    try std.testing.expectEqual(@as(u32, 4), bv2.num);
    try std.testing.expectEqual(false, bv2.more);
    try std.testing.expectEqual(@as(u3, 2), bv2.szx);

    // 3-byte: num=256, more=true, szx=3 => 0x00 0x10 0x0B
    const b3 = Option{ .kind = .block2, .value = &.{ 0x00, 0x10, 0x0B } };
    const bv3 = b3.as_block().?;
    try std.testing.expectEqual(@as(u32, 256), bv3.num);
    try std.testing.expectEqual(true, bv3.more);
    try std.testing.expectEqual(@as(u3, 3), bv3.szx);

    // Empty => null
    const empty = Option{ .kind = .block2, .value = &.{} };
    try std.testing.expectEqual(@as(?BlockValue, null), empty.as_block());

    // 4-byte => null
    const too_long = Option{ .kind = .block2, .value = &.{ 0x01, 0x02, 0x03, 0x04 } };
    try std.testing.expectEqual(@as(?BlockValue, null), too_long.as_block());
}

test "BlockValue.size" {
    var szx: u4 = 0;
    while (szx < 7) : (szx += 1) {
        const bv = BlockValue{ .num = 0, .more = false, .szx = @intCast(szx) };
        const expected: u16 = @as(u16, 1) << (szx + 4);
        try std.testing.expectEqual(expected, bv.size());
    }
}

test "find_option" {
    const alloc = std.testing.allocator;
    // CON GET with uri_host="localhost", uri_path="tv1"
    const msg = [_]u8{
        0x44, 0x01, 0x5D, 0x1F, 0x00, 0x00, 0x39, 0x74,
        0x39, 0x6C, 0x6F, 0x63, 0x61, 0x6C, 0x68, 0x6F,
        0x73, 0x74, 0x83, 0x74, 0x76, 0x31,
    };
    const pkt = try Packet.read(alloc, &msg);
    defer pkt.deinit(alloc);

    const host = pkt.find_option(.uri_host).?;
    try std.testing.expectEqualSlices(u8, "localhost", host.as_string());

    try std.testing.expectEqual(@as(?Option, null), pkt.find_option(.content_format));
}

test "find_options iterator" {
    const alloc = std.testing.allocator;
    // Three uri_path options: "a", "b", "c"
    const msg = [_]u8{
        0x40, 0x01, 0x00, 0x00,
        0xB1, 0x61, // uri_path "a"
        0x01, 0x62, // uri_path "b"
        0x01, 0x63, // uri_path "c"
    };
    const pkt = try Packet.read(alloc, &msg);
    defer pkt.deinit(alloc);

    var it = pkt.find_options(.uri_path);
    try std.testing.expectEqualSlices(u8, "a", it.next().?.value);
    try std.testing.expectEqualSlices(u8, "b", it.next().?.value);
    try std.testing.expectEqualSlices(u8, "c", it.next().?.value);
    try std.testing.expectEqual(@as(?Option, null), it.next());

    // Reset
    it.reset();
    try std.testing.expectEqualSlices(u8, "a", it.next().?.value);

    // Empty iterator
    var empty = pkt.find_options(.content_format);
    try std.testing.expectEqual(@as(?Option, null), empty.next());
}

test "OptionKind.format" {
    try std.testing.expectEqual(OptionKind.Format.string, OptionKind.uri_host.format());
    try std.testing.expectEqual(OptionKind.Format.string, OptionKind.uri_path.format());
    try std.testing.expectEqual(OptionKind.Format.uint, OptionKind.content_format.format());
    try std.testing.expectEqual(OptionKind.Format.uint, OptionKind.max_age.format());
    try std.testing.expectEqual(OptionKind.Format.empty, OptionKind.if_none_match.format());
    try std.testing.expectEqual(OptionKind.Format.@"opaque", OptionKind.etag.format());
    // Unknown option
    const unknown: OptionKind = @enumFromInt(@as(u16, 999));
    try std.testing.expectEqual(OptionKind.Format.@"opaque", unknown.format());
}

test "Option.empty" {
    const opt = Option.empty(.if_none_match);
    try std.testing.expectEqual(OptionKind.if_none_match, opt.kind);
    try std.testing.expectEqual(@as(usize, 0), opt.value.len);
}

test "Option.uint" {
    var buf: [4]u8 = undefined;

    // Zero => empty value
    const o0 = Option.uint(.max_age, 0, &buf);
    try std.testing.expectEqual(@as(usize, 0), o0.value.len);
    try std.testing.expectEqual(@as(u32, 0), o0.as_uint().?);

    // 1-byte
    const o1 = Option.uint(.max_age, 42, &buf);
    try std.testing.expectEqual(@as(usize, 1), o1.value.len);
    try std.testing.expectEqual(@as(u32, 42), o1.as_uint().?);

    // 2-byte
    const o2 = Option.uint(.uri_port, 5683, &buf);
    try std.testing.expectEqual(@as(usize, 2), o2.value.len);
    try std.testing.expectEqual(@as(u32, 5683), o2.as_uint().?);

    // 4-byte
    const o4 = Option.uint(.max_age, 86400, &buf);
    try std.testing.expectEqual(@as(u32, 86400), o4.as_uint().?);

    // Max u32
    const omax = Option.uint(.size1, 0xFFFFFFFF, &buf);
    try std.testing.expectEqual(@as(usize, 4), omax.value.len);
    try std.testing.expectEqual(@as(u32, 0xFFFFFFFF), omax.as_uint().?);
}

test "Option.content_format" {
    var buf: [2]u8 = undefined;

    const json_opt = Option.content_format(.json, &buf);
    try std.testing.expectEqual(OptionKind.content_format, json_opt.kind);
    try std.testing.expectEqual(ContentFormat.json, json_opt.as_content_format().?);

    // Value > 255 needs 2 bytes
    const lwm2m = Option.content_format(.vnd_oma_lwm2m_tlv, &buf);
    try std.testing.expectEqual(@as(usize, 2), lwm2m.value.len);
    try std.testing.expectEqual(ContentFormat.vnd_oma_lwm2m_tlv, lwm2m.as_content_format().?);
}

test "BlockValue.option" {
    var buf: [3]u8 = undefined;

    // 1-byte block value
    const bv1 = BlockValue{ .num = 0, .more = true, .szx = 2 };
    const o1 = bv1.option(.block2, &buf);
    try std.testing.expectEqual(@as(usize, 1), o1.value.len);
    const parsed1 = o1.as_block().?;
    try std.testing.expectEqual(bv1.num, parsed1.num);
    try std.testing.expectEqual(bv1.more, parsed1.more);
    try std.testing.expectEqual(bv1.szx, parsed1.szx);

    // 2-byte block value
    const bv2 = BlockValue{ .num = 100, .more = false, .szx = 5 };
    const o2 = bv2.option(.block1, &buf);
    try std.testing.expectEqual(@as(usize, 2), o2.value.len);
    const parsed2 = o2.as_block().?;
    try std.testing.expectEqual(bv2.num, parsed2.num);
    try std.testing.expectEqual(bv2.more, parsed2.more);
    try std.testing.expectEqual(bv2.szx, parsed2.szx);

    // 3-byte block value (num=4096 => val = 4096<<4 | 8 | 3 = 0x1000B)
    const bv3 = BlockValue{ .num = 4096, .more = true, .szx = 3 };
    const o3 = bv3.option(.block2, &buf);
    try std.testing.expectEqual(@as(usize, 3), o3.value.len);
    const parsed3 = o3.as_block().?;
    try std.testing.expectEqual(bv3.num, parsed3.num);
    try std.testing.expectEqual(bv3.more, parsed3.more);
    try std.testing.expectEqual(bv3.szx, parsed3.szx);
}

test "Option.uint round-trip encode" {
    const alloc = std.testing.allocator;
    var uint_buf: [4]u8 = undefined;

    var options = [_]Option{
        Option.uint(.content_format, 50, &uint_buf),
    };
    const pkt = Packet{
        .kind = .confirmable,
        .code = .post,
        .msg_id = 0x0001,
        .token = &.{},
        .options = &options,
        .payload = "hello",
        .data_buf = &.{},
    };
    const enc = try pkt.write(alloc);
    defer alloc.free(enc);
    const dec = try Packet.read(alloc, enc);
    defer dec.deinit(alloc);
    try std.testing.expectEqual(ContentFormat.json, dec.options[0].as_content_format().?);
    try std.testing.expectEqualSlices(u8, "hello", dec.payload);
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

test "writeBuf exact-size round-trip" {
    const alloc = std.testing.allocator;
    const messages = [_][]const u8{
        &[_]u8{ 0x44, 0x01, 0xba, 0x22, 0x0c, 0x53, 0x5f, 0xb9, 0xb8, 0x63, 0x68, 0x65, 0x63, 0x6b, 0x5f, 0x69, 0x63 },
        &[_]u8{ 0x44, 0x02, 0x3e, 0x6f, 0x77, 0x68, 0x52, 0x80, 0xb1, 0x31, 0x01, 0x32, 0x01, 0x33, 0xff, 0x64, 0x61, 0x74, 0x61 },
        &[_]u8{ 0x40, 0x01, 0x00, 0x00 },
    };
    for (messages) |msg| {
        const pkt = try Packet.read(alloc, msg);
        defer pkt.deinit(alloc);
        var buf: [256]u8 = undefined;
        const exact = try pkt.encodedSize();
        const enc = try pkt.writeBuf(buf[0..exact]);
        try std.testing.expectEqualSlices(u8, msg, enc);
    }
}

test "writeBuf oversized buffer returns correct subslice" {
    const alloc = std.testing.allocator;
    const msg = [_]u8{ 0x40, 0x01, 0x00, 0x00 };
    const pkt = try Packet.read(alloc, &msg);
    defer pkt.deinit(alloc);
    var buf: [256]u8 = undefined;
    const enc = try pkt.writeBuf(&buf);
    try std.testing.expectEqual(@as(usize, 4), enc.len);
    try std.testing.expectEqualSlices(u8, &msg, enc);
}

test "writeBuf too small returns BufferTooSmall" {
    const alloc = std.testing.allocator;
    const msg = [_]u8{ 0x40, 0x01, 0x00, 0x00 };
    const pkt = try Packet.read(alloc, &msg);
    defer pkt.deinit(alloc);
    var buf: [3]u8 = undefined;
    try std.testing.expectError(Error.BufferTooSmall, pkt.writeBuf(&buf));
}

test "encodedSize matches actual encoded length" {
    const alloc = std.testing.allocator;
    const messages = [_][]const u8{
        &[_]u8{ 0x40, 0x01, 0x00, 0x00 },
        &[_]u8{ 0x64, 0x45, 0x5D, 0x1F, 0x00, 0x00, 0x39, 0x74, 0xFF, 0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x57, 0x6F, 0x72, 0x6C, 0x64, 0x21 },
        &[_]u8{ 0x40, 0x01, 0x00, 0x01, 0xD1, 0xF5, 0x02 },
    };
    for (messages) |msg| {
        const pkt = try Packet.read(alloc, msg);
        defer pkt.deinit(alloc);
        const size = try pkt.encodedSize();
        try std.testing.expectEqual(msg.len, size);
        const enc = try pkt.write(alloc);
        defer alloc.free(enc);
        try std.testing.expectEqual(size, enc.len);
    }
}

test "peekKind" {
    try std.testing.expectEqual(MessageKind.confirmable, Packet.peekKind(&.{ 0x40, 0x01, 0x00, 0x00 }).?);
    try std.testing.expectEqual(MessageKind.non_confirmable, Packet.peekKind(&.{ 0x50, 0x01, 0x00, 0x00 }).?);
    try std.testing.expectEqual(MessageKind.acknowledgement, Packet.peekKind(&.{ 0x60, 0x45, 0x00, 0x01 }).?);
    try std.testing.expectEqual(MessageKind.reset, Packet.peekKind(&.{ 0x70, 0x00, 0x00, 0x01 }).?);
    try std.testing.expectEqual(@as(?MessageKind, null), Packet.peekKind(&.{}));
}

test "peekMsgId" {
    try std.testing.expectEqual(@as(u16, 0xBA22), Packet.peekMsgId(&.{ 0x44, 0x01, 0xBA, 0x22 }).?);
    try std.testing.expectEqual(@as(u16, 0x0000), Packet.peekMsgId(&.{ 0x40, 0x01, 0x00, 0x00 }).?);
    try std.testing.expectEqual(@as(u16, 0xFFFF), Packet.peekMsgId(&.{ 0x40, 0x01, 0xFF, 0xFF }).?);
    try std.testing.expectEqual(@as(?u16, null), Packet.peekMsgId(&.{ 0x40, 0x01, 0x00 }));
}

test "peekOption: observe" {
    // CON GET with Observe option (6) = sequence 1, token=0xAB
    const msg = [_]u8{
        0x41, 0x01, 0x00, 0x01, 0xAB, // header: tkl=1, token=0xAB
        0x61, 0x01, // option: delta=6 (observe), len=1, value=0x01
    };
    const opt = Packet.peekOption(&msg, .observe).?;
    try std.testing.expectEqual(OptionKind.observe, opt.kind);
    try std.testing.expectEqual(@as(u32, 1), opt.as_uint().?);
}

test "peekOption: missing option" {
    const msg = [_]u8{ 0x40, 0x01, 0x00, 0x00 };
    try std.testing.expectEqual(@as(?Option, null), Packet.peekOption(&msg, .observe));
}

test "peekOption: option past target" {
    // Option with delta=11 (uri_path) — observe (6) comes before, so not found.
    const msg = [_]u8{ 0x40, 0x01, 0x00, 0x00, 0xB1, 0x61 };
    try std.testing.expectEqual(@as(?Option, null), Packet.peekOption(&msg, .observe));
}

test "peekOption: with extended delta" {
    const alloc = std.testing.allocator;
    // Build a packet with block2 (23) using extended delta.
    var uint_buf: [4]u8 = undefined;
    var b2_buf: [3]u8 = undefined;
    const options = [_]Option{
        Option.uint(.observe, 5, &uint_buf),
        (BlockValue{ .num = 3, .more = true, .szx = 6 }).option(.block2, &b2_buf),
    };
    const pkt = Packet{
        .kind = .confirmable,
        .code = .get,
        .msg_id = 0x1234,
        .token = &.{0xAA},
        .options = &options,
        .payload = &.{},
        .data_buf = &.{},
    };
    const wire = try pkt.write(alloc);
    defer alloc.free(wire);

    // Peek for block2 in the encoded wire data.
    const opt = Packet.peekOption(wire, .block2).?;
    const bv = opt.as_block().?;
    try std.testing.expectEqual(@as(u32, 3), bv.num);
    try std.testing.expect(bv.more);
    try std.testing.expectEqual(@as(u3, 6), bv.szx);
}

test "peekOption: truncated data" {
    try std.testing.expectEqual(@as(?Option, null), Packet.peekOption(&.{}, .observe));
    try std.testing.expectEqual(@as(?Option, null), Packet.peekOption(&.{ 0x40, 0x01 }, .observe));
    // Token extends past data.
    try std.testing.expectEqual(@as(?Option, null), Packet.peekOption(&.{ 0x44, 0x01, 0x00, 0x00 }, .observe));
}

test "emptyAck" {
    var buf: [4]u8 = undefined;
    const ack = Packet.emptyAck(0x1234, &buf);
    try std.testing.expectEqualSlices(u8, &.{ 0x60, 0x00, 0x12, 0x34 }, ack);

    // Verify it round-trips through read.
    const alloc = std.testing.allocator;
    const pkt = try Packet.read(alloc, ack);
    defer pkt.deinit(alloc);
    try std.testing.expectEqual(MessageKind.acknowledgement, pkt.kind);
    try std.testing.expectEqual(Code.empty, pkt.code);
    try std.testing.expectEqual(@as(u16, 0x1234), pkt.msg_id);
}

test "emptyRst" {
    var buf: [4]u8 = undefined;
    const rst = Packet.emptyRst(0xABCD, &buf);
    try std.testing.expectEqualSlices(u8, &.{ 0x70, 0x00, 0xAB, 0xCD }, rst);

    const alloc = std.testing.allocator;
    const pkt = try Packet.read(alloc, rst);
    defer pkt.deinit(alloc);
    try std.testing.expectEqual(MessageKind.reset, pkt.kind);
    try std.testing.expectEqual(Code.empty, pkt.code);
    try std.testing.expectEqual(@as(u16, 0xABCD), pkt.msg_id);
}
