module(..., package.seeall)

local DNS = require("program.dnssd.lib.dns").DNS
local ethernet = require("lib.protocol.ethernet")
local ffi = require("ffi")
local ipv4 = require("lib.protocol.ipv4")
local lib = require("core.lib")
local udp = require("lib.protocol.udp")

local ntohs = lib.ntohs

local ethernet_header_size = 14
local ipv4_header_size = 20
local udp_header_size = 8

local STANDARD_QUERY_RESPONSE = 0x8400

MDNS = {
   ETHER = "01:00:5e:00:00:fb",
   IPV4 = "224.0.0.251",
   PORT = 5353,
}

mdns_header_t = ffi.typeof[[
   struct {
      uint16_t id;
      uint16_t flags;
      uint16_t questions;
      uint16_t answer_rrs;
      uint16_t authority_rrs;
      uint16_t additional_rrs;
   } __attribute__((packed))
]]
local mdns_header_ptr_t = ffi.typeof("$*", mdns_header_t)

function MDNS.is_mdns (pkt)
   local ether_hdr = ethernet:new_from_mem(pkt.data, ethernet_header_size)
   local ipv4_hdr = ipv4:new_from_mem(pkt.data + ethernet_header_size, ipv4_header_size)
   local udp_hdr = udp:new_from_mem(pkt.data + ethernet_header_size + ipv4_header_size, udp_header_size)

   return ethernet:ntop(ether_hdr:dst()) == MDNS.ETHER and
      ipv4:ntop(ipv4_hdr:dst()) == MDNS.IPV4 and
      udp_hdr:dst_port() == MDNS.PORT
end

function MDNS.parse_header (pkt)
   local mdns_header = ffi.new(mdns_header_t)

   local mdns_payload_offset = ethernet_header_size + ipv4_header_size + udp_header_size
   ffi.copy(mdns_header, pkt.data + mdns_payload_offset, ffi.sizeof(mdns_header_t))
   mdns_header.id = ntohs(mdns_header.id)
   mdns_header.flags = ntohs(mdns_header.flags)
   mdns_header.questions = ntohs(mdns_header.questions)
   mdns_header.answer_rrs = ntohs(mdns_header.answer_rrs)
   mdns_header.authority_rrs = ntohs(mdns_header.authority_rrs)
   mdns_header.additional_rrs = ntohs(mdns_header.additional_rrs)
   return mdns_header, ffi.sizeof(mdns_header_t)
end

function MDNS.is_response (pkt)
   local header = MDNS.parse_header(pkt)
   return header.flags == STANDARD_QUERY_RESPONSE
end

local function collect_records (payload, t, n)
   local rrs, len = DNS.parse_records(payload, n)
   for _, each in ipairs(rrs) do table.insert(t, each) end
   return payload + len
end

function MDNS.parse_packet (pkt)
   assert(MDNS.is_mdns(pkt))
   local mdns_hdr, size = MDNS.parse_header(pkt)
   local payload_offset = ethernet_header_size + ipv4_header_size + udp_header_size
   local payload = pkt.data + payload_offset + size
   local ret = {
      questions = {},
      answer_rrs = {},
      authority_rrs = {},
      additional_rrs = {},
   }
   payload = collect_records(payload, ret.questions, mdns_hdr.questions)
   payload = collect_records(payload, ret.answer_rrs, mdns_hdr.answer_rrs)
   payload = collect_records(payload, ret.authority_rrs, mdns_hdr.authority_rrs)
   payload = collect_records(payload, ret.additional_rrs, mdns_hdr.additional_rrs)
   return ret
end

function selftest()
   local function parse_response ()
      -- MDNS response.
      local pkt = packet.from_string(lib.hexundump ([[
         01:00:5e:00:00:fb ce:6c:59:f2:f3:c1 08 00 45 00
         01 80 00 00 40 00 ff 11 82 88 c0 a8 56 40 e0 00
         00 fb 14 e9 14 e9 01 6c d2 12 00 00 84 00 00 00
         00 01 00 00 00 03 0b 5f 67 6f 6f 67 6c 65 63 61
         73 74 04 5f 74 63 70 05 6c 6f 63 61 6c 00 00 0c
         00 01 00 00 00 78 00 2e 2b 43 68 72 6f 6d 65 63
         61 73 74 2d 38 34 38 64 61 35 39 64 38 63 62 36
         34 35 39 61 39 39 37 31 34 33 34 62 31 64 35 38
         38 62 61 65 c0 0c c0 2e 00 10 80 01 00 00 11 94
         00 b3 23 69 64 3d 38 34 38 64 61 35 39 64 38 63
         62 36 34 35 39 61 39 39 37 31 34 33 34 62 31 64
         35 38 38 62 61 65 23 63 64 3d 37 32 39 32 37 38
         45 30 32 35 46 43 46 44 34 44 43 44 43 37 46 42
         39 45 38 42 43 39 39 35 42 37 13 72 6d 3d 39 45
         41 37 31 43 38 33 43 43 45 46 37 39 32 37 05 76
         65 3d 30 35 0d 6d 64 3d 43 68 72 6f 6d 65 63 61
         73 74 12 69 63 3d 2f 73 65 74 75 70 2f 69 63 6f
         6e 2e 70 6e 67 09 66 6e 3d 4b 69 62 62 6c 65 07
         63 61 3d 34 31 30 31 04 73 74 3d 30 0f 62 73 3d
         46 41 38 46 43 41 39 33 42 35 43 34 04 6e 66 3d
         31 03 72 73 3d c0 2e 00 21 80 01 00 00 00 78 00
         2d 00 00 00 00 1f 49 24 38 34 38 64 61 35 39 64
         2d 38 63 62 36 2d 34 35 39 61 2d 39 39 37 31 2d
         34 33 34 62 31 64 35 38 38 62 61 65 c0 1d c1 2d
         00 01 80 01 00 00 00 78 00 04 c0 a8 56 40
      ]], 398))
      local response = MDNS.parse_packet(pkt)
      assert(#response.answer_rrs == 1)
      assert(#response.additional_rrs == 3)
   end
   local function parse_request ()
      local mDNSQuery = require("program.dnssd.lib.mdns_query").mDNSQuery
      local requester = mDNSQuery.new({
         src_eth = "ce:6c:59:f2:f3:c1",
         src_ipv4 = "192.168.0.1",
      })
      local query = "_services._dns-sd._udp.local"
      local request = MDNS.parse_packet(requester:build(query))
      assert(#request.questions == 1)
   end
   parse_response()
   parse_request()
end
