## coapz - Constrained Application Protocol (CoAP) encode/decode library for Zig

Currently only an embryo for such a library.

Supports read, but now write of CoAP-packets.

### Todo
- [X] Rename all fields named `typ` to `kind` (or similar)
- [ ] Implement `Packet.write(self: Self) ![]u8`
      + ..or: `Packet.write(self: Self, out: anytype) !void`
- [ ] Write actual test suits for reading and writing
- [ ] Create a proper ErrorSet for all types of errors
      + make them explicit instead of just bubbling
      + handle reader errors
      + handle alloc errors (maybe bubble these?)
      + Just follow the trys
- [ ] Test against ecoap (erlang library)
      + Use ecoap to generate lot's of examples
- [ ] Check which standards exist and which to Implement
      + Document which RFCs are implemented etc. (see coap-lite crate)

### RFCs
- [X] CoAP RFC 7252
- [X] CoAP Observe Option RFC 7641
- [X] Too Many Requests Response Code RFC 8516
- [ ] Block-Wise Transfers RFC 7959
- [ ] Constrained RESTful Environments (CoRE) Link Format RFC6690
