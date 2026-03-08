/// IANA-registered CoAP Content-Formats.
/// See https://www.iana.org/assignments/core-parameters/core-parameters.xhtml#content-formats
pub const ContentFormat = enum(u16) {
    text_plain = 0,
    cose_encrypt0 = 16,
    cose_mac0 = 17,
    cose_sign1 = 18,
    link_format = 40,
    xml = 41,
    octet_stream = 42,
    exi = 47,
    json = 50,
    json_patch = 51,
    json_merge_patch = 52,
    cbor = 60,
    cwt = 61,
    multipart_core = 62,
    cbor_seq = 63,
    cose_encrypt = 96,
    cose_mac = 97,
    cose_sign = 98,
    cose_key = 101,
    cose_key_set = 102,
    senml_json = 110,
    sensml_json = 111,
    senml_cbor = 112,
    sensml_cbor = 113,
    senml_exi = 114,
    sensml_exi = 115,
    coap_group_json = 256,
    dots_cbor = 271,
    pkcs7_smime_signed = 280,
    pkcs7_certs_only = 281,
    pkcs8 = 284,
    csrattrs = 285,
    pkcs10 = 286,
    pkix_cert = 287,
    aif_cbor = 290,
    aif_json = 291,
    senml_xml = 310,
    sensml_xml = 311,
    senml_etch_json = 320,
    senml_etch_cbor = 322,
    yang_data_cbor_sid = 340,
    yang_data_cbor = 341,
    td_json = 432,
    vnd_ocf_cbor = 10000,
    oscore = 10001,
    json_deflate = 11050,
    cbor_deflate = 11060,
    vnd_oma_lwm2m_tlv = 11542,
    vnd_oma_lwm2m_json = 11543,
    vnd_oma_lwm2m_cbor = 11544,
    text_css = 20000,
    image_svg_xml = 30000,
    _,

    const Self = @This();

    pub fn from_uint(val: u32) ?Self {
        if (val > std.math.maxInt(u16)) return null;
        return @enumFromInt(@as(u16, @intCast(val)));
    }
};

const std = @import("std");

test "content format values" {
    const expectEqual = std.testing.expectEqual;
    try expectEqual(@as(u16, 0), @intFromEnum(ContentFormat.text_plain));
    try expectEqual(@as(u16, 40), @intFromEnum(ContentFormat.link_format));
    try expectEqual(@as(u16, 50), @intFromEnum(ContentFormat.json));
    try expectEqual(@as(u16, 60), @intFromEnum(ContentFormat.cbor));
    try expectEqual(@as(u16, 61), @intFromEnum(ContentFormat.cwt));
    try expectEqual(@as(u16, 10001), @intFromEnum(ContentFormat.oscore));
    try expectEqual(@as(u16, 11542), @intFromEnum(ContentFormat.vnd_oma_lwm2m_tlv));

    // Unknown value via wildcard
    const unknown: ContentFormat = @enumFromInt(@as(u16, 9999));
    try expectEqual(@as(u16, 9999), @intFromEnum(unknown));
}
