const std = @import("std");
const heap = std.heap;
const io = std.io;
const mem = std.mem;
const eql = mem.eql;
const testing = std.testing;
const Big = std.builtin.Endian.big;

const print = std.debug.print;

const MessageType = enum(u8) {
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
    created = 65,
    deleted,
    valid,
    changed,
    content,
    bad_request = 128,
    unauthorized,
    bad_option,
    forbidden,
    not_found,
    method_not_allowed,
    not_acceptable,
    precondition_failed = 140,
    request_entity_too_large,
    unsupported_content_format = 143,
    internal_server_error = 160,
    not_implemented,
    bad_gateway,
    service_unavailable,
    gateway_timeout,
    proxying_not_supported,
};

const OptionType = enum(u16) {
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
    typ: OptionType,
    value: []const u8,
};

const Error = error{
    TruncatedOption,
};

pub const Packet = struct {
    const Self = @This();

    typ: MessageType,
    code: Code,
    msg_id: u16,
    token: []const u8,
    options: []Option,
    payload: []const u8,

    alloc: mem.Allocator,

    // TODO: Handle more protocol errors
    fn read(alloc: mem.Allocator, data: []const u8) !Packet {
        var fb = io.fixedBufferStream(data);
        var r = fb.reader();

        const b0 = try r.readByte();
        const b1 = try r.readByte();
        const msg_id = try r.readInt(u16, Big);
        const token_len = b0 & 0xf;
        const token = try alloc.alloc(u8, token_len);
        errdefer alloc.free(token);
        var n = try r.read(token);

        var opts = std.ArrayList(Option).init(alloc);
        var sum: u16 = 0;
        var has_payload = false;
        while (true) {
            const c0 = r.readByte() catch break;
            if (c0 == 255) {
                has_payload = true;
                break;
            }

            var delta: u16 = c0 >> 4 & 0xf;
            if (delta > 15)
                return Error.TruncatedOption;
            delta = switch (delta) {
                13 => (try r.readInt(u8, Big)) + 13,
                14 => (try r.readInt(u16, Big)) + 269, // TODO: Could this overflow?
                else => delta,
            };
            sum += delta;

            var len: u16 = c0 & 0xf;
            if (len > 15)
                return Error.TruncatedOption;
            len = switch (len) {
                13 => (try r.readInt(u8, Big)) + 13,
                14 => (try r.readInt(u16, Big)) + 269,
                else => len,
            };

            const opt_buf = try alloc.alloc(u8, len);
            errdefer alloc.free(opt_buf);
            n = try r.read(opt_buf);
            const opt_type: OptionType = @enumFromInt(sum);
            const opt = Option{ .typ = opt_type, .value = opt_buf };
            try opts.append(opt);
        }

        // NOTE: Could be cleaner to just keep the ArrayList and free it in the end.
        //       This creates a new clone of opts.
        const owned_opts_slice = try opts.toOwnedSlice();
        opts.deinit();

        return Packet{
            .alloc = alloc,
            .typ = @enumFromInt(b0 >> 4 & 0x3),
            .code = @enumFromInt(b1),
            .msg_id = msg_id,
            .token = token,
            .options = owned_opts_slice,
            .payload = val: {
                if (has_payload) {
                    const payload = try r.readAllAlloc(alloc, 16 * 1024);
                    errdefer alloc.free(payload);
                    break :val payload;
                } else {
                    break :val &[0]u8{};
                }
            },
        };
    }

    fn write(self: Self) ![]u8 {
        _ = &self;
    }

    fn deinit(self: Self) void {
        self.alloc.free(self.payload);
        self.alloc.free(self.token);
        for (self.options) |opt| {
            self.alloc.free(opt.value);
        }
        self.alloc.free(self.options);
    }
};

test "decode" {
    print("\n", .{});
    const alloc = testing.allocator;

    // Bin = <<68,1,186,34,12,83,95,185,184,99,104,101,99,107,95,105,99>>.
    const msg1 = [_]u8{
        0x44, 0x01, 0xba, 0x22, 0x0c, 0x53, 0x5f, 0xb9,
        0xb8, 0x63, 0x68, 0x65, 0x63, 0x6b, 0x5f, 0x69,
        0x63,
    };
    const packet1 = try Packet.read(alloc, &msg1);
    defer packet1.deinit();
    print("packet1: {}\n", .{packet1});
    for (packet1.options) |opt| print("opt: {any}=>{s}\n", .{ opt.typ, opt.value });

    // Bin = <<68,2,62,111,119,104,82,128,177,49,1,50,1,51,255,100,97,116,97>>.
    const msg2 = [_]u8{
        0x44, 0x02, 0x3e, 0x6f, 0x77, 0x68, 0x52, 0x80,
        0xb1, 0x31, 0x01, 0x32, 0x01, 0x33, 0xff, 0x64,
        0x61, 0x74, 0x61,
    };
    const packet2 = try Packet.read(alloc, &msg2);
    defer packet2.deinit();
    print("packet2: {}\n", .{packet2});
    for (packet2.options) |opt| print("opt: {any}=>{s}\n", .{ opt.typ, opt.value });

    const msg3 = [_]u8{
        0x44, 0x01, 0x5D, 0x1F, 0x00, 0x00, 0x39, 0x74,
        0x39, 0x6C, 0x6F, 0x63, 0x61, 0x6C, 0x68, 0x6F,
        0x73, 0x74, 0x83, 0x74, 0x76, 0x31,
    };
    const packet3 = try Packet.read(alloc, &msg3);
    defer packet3.deinit();
    print("packet3: {}\n", .{packet3});
    for (packet3.options) |opt| print("opt: {any}=>{s}\n", .{ opt.typ, opt.value });

    const msg4 = [_]u8{
        0x64, 0x45, 0x5D, 0x1F, 0x00, 0x00, 0x39, 0x74,
        0xFF, 0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x57,
        0x6F, 0x72, 0x6C, 0x64, 0x21,
    };
    const packet4 = try Packet.read(alloc, &msg4);
    defer packet4.deinit();
    print("packet3: {}\n", .{packet4});
    for (packet4.options) |opt| print("opt: {any}=>{s}\n", .{ opt.typ, opt.value });
}
