//! Constrained Application Protocol (CoAP) encode/decode library
//!
const std = @import("std");
const Big = std.builtin.Endian.big;

const MessageKind = enum(u8) {
    confirmable = 0,
    non_confirmable = 1,
    acknowledgement = 2,
    reset = 3,
};

const Code = enum(u8) {
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
};

const OptionKind = enum(u16) {
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
    block1 = 27,
    block2 = 23,
    proxy_uri = 35,
    proxy_scheme = 39,
    size1 = 60,
    size2 = 28,
    no_response = 258,
};

const Option = struct {
    kind: OptionKind,
    value: []const u8,
};

const Error = error{
    TruncatedOption,
};

pub const Packet = struct {
    const Self = @This();

    kind: MessageKind,
    code: Code,
    msg_id: u16,
    token: []const u8,
    options: []Option,
    payload: []const u8,
    _data_buf: []u8,

    alloc: std.mem.Allocator,

    pub fn read(alloc: std.mem.Allocator, data: []const u8) !Packet {
        const b0 = data[0];
        const b1 = data[1];
        const msg_id: u16 = @as(u16, data[2]) << 8 | data[3];
        const token_len: usize = b0 & 0xf;

        // Pass 1: count options and compute total data size
        var pos: usize = 4 + token_len;
        var opt_count: usize = 0;
        var data_size: usize = token_len;
        var payload_start: usize = 0;

        while (pos < data.len) {
            const c0 = data[pos];
            pos += 1;
            if (c0 == 0xff) {
                payload_start = pos;
                data_size += data.len - pos;
                break;
            }
            _ = try readVarLenDirect(data, &pos, @intCast(c0 >> 4 & 0xf));
            const val_len = try readVarLenDirect(data, &pos, @intCast(c0 & 0xf));
            data_size += val_len;
            pos += val_len;
            opt_count += 1;
        }

        // Pass 2: allocate and populate
        const data_buf = try alloc.alloc(u8, data_size);
        errdefer alloc.free(data_buf);
        const options = try alloc.alloc(Option, opt_count);
        errdefer alloc.free(options);

        // Copy token
        var buf_pos: usize = 0;
        @memcpy(data_buf[0..token_len], data[4 .. 4 + token_len]);
        const token = data_buf[0..token_len];
        buf_pos = token_len;

        // Parse and copy options
        pos = 4 + token_len;
        var delta_sum: u16 = 0;
        for (options) |*opt| {
            const c0 = data[pos];
            pos += 1;
            delta_sum += try readVarLenDirect(data, &pos, @intCast(c0 >> 4 & 0xf));
            const val_len = try readVarLenDirect(data, &pos, @intCast(c0 & 0xf));
            @memcpy(data_buf[buf_pos .. buf_pos + val_len], data[pos .. pos + val_len]);
            opt.* = .{
                .kind = @enumFromInt(delta_sum),
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
            ._data_buf = data_buf,
        };
    }

    pub fn write(self: Self) ![]u8 {
        // Calculate exact output size
        var size: usize = 4 + self.token.len;
        var prev: u16 = 0;
        for (self.options) |opt| {
            const num = @intFromEnum(opt.kind);
            const delta = num - prev;
            const len: u16 = @intCast(opt.value.len);
            size += 1 + extendedSize(delta) + extendedSize(len) + opt.value.len;
            prev = num;
        }
        if (self.payload.len > 0) {
            size += 1 + self.payload.len;
        }

        // Single allocation
        const buf = try self.alloc.alloc(u8, size);
        errdefer self.alloc.free(buf);

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
            writeExtDirect(buf, &pos, delta);
            writeExtDirect(buf, &pos, len);
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

    pub fn deinit(self: Self) void {
        self.alloc.free(self._data_buf);
        self.alloc.free(self.options);
    }
};

fn optNibble(val: u16) u8 {
    if (val <= 12) return @intCast(val);
    if (val < 269) return 13;
    return 14;
}

fn writeExtDirect(buf: []u8, pos: *usize, val: u16) void {
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

fn readVarLenDirect(data: []const u8, pos: *usize, nibble: u4) !u16 {
    return switch (nibble) {
        13 => blk: {
            const v: u16 = data[pos.*];
            pos.* += 1;
            break :blk v + 13;
        },
        14 => blk: {
            const v: u16 = @as(u16, data[pos.*]) << 8 | data[pos.* + 1];
            pos.* += 2;
            break :blk v + 269;
        },
        15 => Error.TruncatedOption,
        else => nibble,
    };
}

test "decode" {
    const print = std.debug.print;
    const alloc = std.testing.allocator;

    print("\n", .{});

    // Bin = <<68,1,186,34,12,83,95,185,184,99,104,101,99,107,95,105,99>>.
    const msg1 = [_]u8{
        0x44, 0x01, 0xba, 0x22, 0x0c, 0x53, 0x5f, 0xb9,
        0xb8, 0x63, 0x68, 0x65, 0x63, 0x6b, 0x5f, 0x69,
        0x63,
    };
    const packet1 = try Packet.read(alloc, &msg1);
    defer packet1.deinit();
    print("packet1: {}\n", .{packet1});
    for (packet1.options) |opt| print("opt: {any}=>{s}\n", .{ opt.kind, opt.value });

    // Bin = <<68,2,62,111,119,104,82,128,177,49,1,50,1,51,255,100,97,116,97>>.
    const msg2 = [_]u8{
        0x44, 0x02, 0x3e, 0x6f, 0x77, 0x68, 0x52, 0x80,
        0xb1, 0x31, 0x01, 0x32, 0x01, 0x33, 0xff, 0x64,
        0x61, 0x74, 0x61,
    };
    const packet2 = try Packet.read(alloc, &msg2);
    defer packet2.deinit();
    print("packet2: {}\n", .{packet2});
    for (packet2.options) |opt| print("opt: {any}=>{s}\n", .{ opt.kind, opt.value });

    // Bin = <<68,1,93,31,0,0,57,116,57,108,111,99,97,108,104,111,115,116,131,116,118,49>>.
    const msg3 = [_]u8{
        0x44, 0x01, 0x5D, 0x1F, 0x00, 0x00, 0x39, 0x74,
        0x39, 0x6C, 0x6F, 0x63, 0x61, 0x6C, 0x68, 0x6F,
        0x73, 0x74, 0x83, 0x74, 0x76, 0x31,
    };
    const packet3 = try Packet.read(alloc, &msg3);
    defer packet3.deinit();
    print("packet3: {}\n", .{packet3});
    for (packet3.options) |opt| print("opt: {any}=>{s}\n", .{ opt.kind, opt.value });

    // Bin = <<100,69,93,31,0,0,57,116,255,72,101,108,108,111,32,87,111,114,108,100,33>>.
    const msg4 = [_]u8{
        0x64, 0x45, 0x5D, 0x1F, 0x00, 0x00, 0x39, 0x74,
        0xFF, 0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x57,
        0x6F, 0x72, 0x6C, 0x64, 0x21,
    };
    const packet4 = try Packet.read(alloc, &msg4);
    defer packet4.deinit();
    print("packet4: {}\n", .{packet4});
    for (packet4.options) |opt| print("opt: {any}=>{s}\n", .{ opt.kind, opt.value });
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
        const encoded = try pkt.write();
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

    const encoded = try pkt.write();
    defer alloc.free(encoded);
    try std.testing.expectEqualSlices(u8, &msg, encoded);
}
