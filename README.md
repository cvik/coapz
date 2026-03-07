## coapz - Constrained Application Protocol (CoAP) encode/decode library for Zig

A minimal CoAP packet encode/decode library for Zig.

Supports reading and writing of CoAP packets with a two-pass decode and pre-sized encode for efficiency.

### Todo
- [X] Rename all fields named `typ` to `kind` (or similar)
- [X] Implement `Packet.write(self: Self) ![]u8`
- [ ] Write actual test suites for reading and writing
      + Current tests cover basic decode and round-trip; need more comprehensive coverage
- [ ] Create a proper ErrorSet for all types of errors
      + make them explicit instead of just bubbling
      + handle reader errors
      + handle alloc errors (maybe bubble these?)
      + Just follow the trys
- [ ] Test against ecoap (erlang library)
      + Use ecoap to generate lot's of examples
- [ ] Check which standards exist and which to implement
      + Document which RFCs are implemented etc. (see coap-lite crate)

### RFCs
- [X] CoAP RFC 7252
- [X] CoAP Observe Option RFC 7641
- [X] Too Many Requests Response Code RFC 8516
- [ ] Block-Wise Transfers RFC 7959
- [ ] Constrained RESTful Environments (CoRE) Link Format RFC6690
