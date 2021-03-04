const std = @import("std");
const heap = std.heap;
const io = std.io;
const mem = std.mem;
const eql = mem.eql;
const testing = std.testing;
//const gpa = heap.GeneralPurposeAllocator(.{}).allocator;
const gpa = heap.page_allocator;

const print = std.io.getStdOut().writer().print;

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

const OptionU = union(OptionType) {
    unknown,
    if_match: []const u8,
    uri_host: []const u8,
    etag: []const u8,
    if_none_match: []const u8,
    observe: []const u8,
    uri_port: []const u8,
    location_path: []const u8,
    oscore: []const u8,
    uri_path: []const u8,
    content_format: []const u8,
    max_age: []const u8,
    uri_query: []const u8,
    accept: []const u8,
    location_query: []const u8,
    block1: []const u8,
    block2: []const u8,
    proxy_uri: []const u8,
    proxy_scheme: []const u8,
    size1: []const u8,
    size2: []const u8,
    no_response,
};

const Option = struct {
    typ: OptionType,
    value: []const u8,
};

const Error = error{
    TruncatedOption,
};

pub const Packet = struct {
    typ: MessageType,
    code: Code,
    msg_id: u16,
    token: []const u8,
    options: []Option,
    payload: []const u8,

    const Self = @This();

    fn write(self: Self) ![]u8 {}
};

const Parser = struct {
    alloc: *mem.Allocator,
    const Self = @This();

    pub fn init(allocator: *mem.Allocator) Self {
        return Self{ .alloc = allocator };
    }

    // TODO: Check more error cases
    // TODO: Test with payload and longer options
    // TODO: Set module global allocator and endianess
    fn read(self: Self, data: []const u8) !Packet {
        const r = io.fixedBufferStream(data).reader();

        const b0 = try r.readByte();
        const b1 = try r.readByte();
        const msg_id = try r.readIntBig(u16);
        const token_len = b0 & 0xf;
        const token = try self.alloc.alloc(u8, token_len);
        var n = try r.read(token);

        var opts = std.ArrayList(Option).init(self.alloc);
        const payload = try self.alloc.alloc(u8, 4096);
        var sum: u16 = 0;
        while (true) {
            const c0 = r.readByte() catch break;
            if (c0 == 255) {
                n = try r.readAll(payload);
                const m = self.alloc.shrink(payload, n);
                break;
            }

            var delta: u16 = c0 >> 4 & 0xf;
            if (delta > 15)
                return Error.TruncatedOption;
            delta = switch (delta) {
                13 => (try r.readIntBig(u8)) + 13,
                14 => (try r.readIntBig(u16)) + 269, // TODO: Could this overflow?
                else => delta,
            };
            sum += delta;

            var len: u16 = c0 & 0xf;
            if (len > 15)
                return Error.TruncatedOption;
            len = switch (len) {
                13 => (try r.readIntBig(u8)) + 13,
                14 => (try r.readIntBig(u16)) + 269,
                else => len,
            };

            const opt_buf = try self.alloc.alloc(u8, len);
            n = try r.read(opt_buf);
            const opt_type = @intToEnum(OptionType, sum);
            const opt = Option{ .typ = opt_type, .value = opt_buf };
            try opts.append(opt);
        }

        return Packet{
            .typ = @intToEnum(MessageType, b0 >> 4 & 0x3),
            .code = @intToEnum(Code, b1),
            .msg_id = msg_id,
            .token = token, //data[4..(4 + token_len)],
            .options = opts.items,
            .payload = &[_]u8{}, //payload,
        };
    }
};

fn readU16(p1: u8, p2: u8) u16 {
    return mem.bigToNative(u16, mem.bytesAsValue(u16, &[_]u8{ p1, p2 }).*);
}

test "decode" {
    try print("\n", .{});
    const parser = Parser.init(gpa);

    // Bin = <<68,1,186,34,12,83,95,185,184,99,104,101,99,107,95,105,99>>.
    const msg1 = [_]u8{
        0x44, 0x01, 0xba, 0x22, 0x0c, 0x53, 0x5f, 0xb9,
        0xb8, 0x63, 0x68, 0x65, 0x63, 0x6b, 0x5f, 0x69,
        0x63,
    };
    const packet1 = try parser.read(&msg1);
    try print("packet1: {}\n", .{packet1});

    // Bin = <<68,2,62,111,119,104,82,128,177,49,1,50,1,51,255,100,97,116,97>>.
    const msg2 = [_]u8{
        0x44, 0x02, 0x3e, 0x6f, 0x77, 0x68, 0x52, 0x80,
        0xb1, 0x31, 0x01, 0x32, 0x01, 0x33, 0xff, 0x64,
        0x61, 0x74, 0x61,
    };
    const packet2 = try parser.read(&msg2);
    try print("packet2: {}\n", .{packet2});

    const msg3 = [_]u8{
        0x44, 0x2,  0x3e, 0x6f, 0x74, 0x6f, 0x6b, 0x31,
        0xb1, 0x31, 0x1,  0x32, 0x1,  0x33, 0xff, 0x64,
        0x61, 0x74, 0x61,
    };
    const packet3 = try parser.read(&msg3);
    try print("packet3: {}\n", .{packet3});

    for (packet1.options) |opt| try print("opt: {s}\n", .{opt.value});
}
