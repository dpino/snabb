module(..., package.seeall)

local lib = require("core.lib")
local RawSocket = require("apps.socket.raw").RawSocket
local basic_apps = require("apps.basic.basic_apps")
local ethernet = require("lib.protocol.ethernet")
local ipv4 = require("lib.protocol.ipv4")
local udp = require("lib.protocol.udp")

local ffi = require("ffi")

local htons, ntohs = lib.htons, lib.ntohs
local htonl, ntohl = lib.htonl, lib.ntohl

--[=[
ffi.cdef[[
   typedef struct { char* key; char* val; } __atribute__((packed)) entry_t;
]]

local mdns_txt_record_t = ffi.typeof[[
   struct {
      entry_t dict[];
   } __attribute__((packed))
]]
local mdns_txt_record_t = ffi.typeof("$*", mdns_txt_record_t)
--]=]

local long_opts = {
   help = "h",
}

local ethernet_header_size = 14
local ipv4_header_size = 20
local udp_header_size = 8

MDNS = {
   ETHER = "01:00:5e:00:00:fb",
   IPV4 = "224.0.0.251",
   PORT = 5353,
}

local mdns_header_t = ffi.typeof[[
   struct {
      uint16_t id;
      uint16_t flag;
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

function mdns_parse (pkt)
   local mdns_header = ffi.new(mdns_header_t)

   local mdns_payload_offset = ethernet_header_size + ipv4_header_size + udp_header_size
   ffi.copy(mdns_header, pkt.data + mdns_payload_offset, ffi.sizeof(mdns_header_t))
   mdns_header.id = ntohs(mdns_header.id)
   mdns_header.flag = ntohs(mdns_header.flag)
   mdns_header.questions = ntohs(mdns_header.questions)
   mdns_header.answer_rrs = ntohs(mdns_header.answer_rrs)
   mdns_header.authority_rrs = ntohs(mdns_header.authority_rrs)
   mdns_header.additional_rrs = ntohs(mdns_header.additional_rrs)
   return mdns_header, ffi.sizeof(mdns_header_t)
end

DNS = {}

-- Head fixed info.
local dns_record_head_info_t = ffi.typeof([[
   struct {
      uint16_t type;
      uint16_t class;
      uint32_t ttl;
      uint16_t data_length;
   } __attribute__((packed))
]])
local dns_record_head_info_ptr_t = ffi.typeof("$*", dns_record_head_info_t)

-- Head.
local dns_record_head_t = ffi.typeof[[
   struct {
      char* name;
      uint16_t type;
      uint16_t class;
      uint32_t ttl;
      uint16_t data_length;
   } __attribute__((packed))
]]
local dns_record_head_ptr_t  = ffi.typeof("$*", dns_record_head_t)

-- PTR.
local dns_record_ptr_t = ffi.typeof([[
   struct {
      $ h;
      char* domain_name;
   } __attribute__((packed))
]], dns_record_head_t)
local dns_record_ptr_ptr_t = ffi.typeof("$*", dns_record_ptr_t)

local dns_record_a_t = ffi.typeof([[
   struct {
      $ h;
      uint32_t address;
   } __attribute__((packed))
]], dns_record_head_t)
local dns_record_a_ptr_t = ffi.typeof("$*", dns_record_a_t)

local dns_record_srv_t = ffi.typeof([[
   struct {
      $ h;
      uint16_t priority;
      uint16_t weight;
      uint16_t port;
      char* target;
   } __attribute__((packed))
]], dns_record_head_t)
local dns_record_a_ptr_t = ffi.typeof("$*", dns_record_srv_t)

local dns_record_txt_t = ffi.typeof([[
   struct {
      $ h;
      char** chunks;
   } __attribute__((packed))
]], dns_record_head_t)
local dns_record_a_ptr_t = ffi.typeof("$*", dns_record_txt_t)

-- Finds first end of string in payload.
function DNS.eos (payload)
   local i = 0
   for i=0, 9660 do
      if payload[i] == 0 then return i+1 end
   end
   error("Couldn't find end of string")
end

local A =   htons(0x01)
local PTR = htons(0x0c)
local SRV = htons(0x21)
local TXT = htons(0x10)

local function r16 (ptr)
   return ffi.cast("uint16_t*", ptr)[0]
end

local function r32 (ptr)
   return ffi.cast("uint32_t*", ptr)[0]
end

local function copy_string(dst, src, len)
   ffi.copy(dst, src, len)
   dst[len] = 0
end

local function set (...)
   local ret = {}
   for _, each in ipairs(...) do ret[each] = true end
   return ret
end

local function contains (set, key)
   return set[key]
end

local function new_dns_record (type)
   if type == A then
      return ffi.new(dns_record_a_t)
   elseif type == PTR then
      return ffi.new(dns_record_ptr_t)
   elseif type == SRV then
      return ffi.new(dns_record_srv_t)
   elseif type == TXT then
      return ffi.new(dns_record_txt_t)
   end
end

function DNS.parse_record (payload)
   -- Create record depending on type.
   -- XXX: I'm not sure what's the best way to check a DNS record type.
   -- Records start with a 'name' field, which in the case of PTR records is a
   -- string literal ending in '\0'. For all the other records (A, SRV and TXT),
   -- the 'name' field is an 16-bit identifier. So what I'm doing here is to
   -- peep the next two bytes after the identifier to read the 'type'.. If the
   -- 'type' is A, SRV or TXT I consider the skipped two bytes the name. If
   -- not I read a raw of bytes until '\0' and consider that the name.
   -- The following two bytes must be PTR.
   local len, type
   local maybe_type = r16(payload + 2)
   if contains(set{A, SRV, TXT}, maybe_type) then
      len = 2
      type = maybe_type
   else
      len = DNS.eos(payload)
      type = r16(payload + len)
      assert(type == PTR)
   end
   local dns_record = new_dns_record(type)
   if not dns_record then return nil, 0 end

   -- Copy head.
   dns_record.h.name = ffi.new("char[?]", len)
   ffi.copy(dns_record.h.name, payload, len)
   local ptr = ffi.cast(dns_record_head_info_ptr_t, payload + len)
   dns_record.h.type = ptr.type
   dns_record.h.class = ptr.class
   dns_record.h.ttl = ptr.ttl
   dns_record.h.data_length = ptr.data_length

   -- Copy variable information.
   local data_length = ntohs(dns_record.h.data_length)
   local total_len = len + ffi.sizeof(dns_record_head_info_t) + data_length
   local offset = len + ffi.sizeof(dns_record_head_info_t)
   if type == A then
      print("Parse: A")
      dns_record.address = r32(payload + offset)
   elseif type == PTR then
      print("Parse: PTR")
      dns_record.domain_name = ffi.new("char[?]", data_length + 1)
      copy_string(dns_record.domain_name, payload + offset, data_length)
   elseif type == SRV then
      print("Parse: SRV")
      local srv_info_t = ffi.typeof[[
         struct {
            uint16_t priority;
            uint16_t weight;
            uint16_t port;
         } __attribute__((packed))
      ]]
      local srv_info_ptr_t = ffi.typeof("$*", srv_info_t)
      local ptr = ffi.cast(srv_info_ptr_t, payload + offset)
      dns_record.priority = ptr.priority
      dns_record.weight = ptr.weight
      dns_record.port = ptr.port
      local target_len = data_length - ffi.sizeof(srv_info_t)
      dns_record.target = ffi.new("char[?]", target_len + 1)
      copy_string(dns_record.target, payload + offset + ffi.sizeof(srv_info_t), target_len)
   elseif type == TXT then
      print("Parse: TXT")
      local chunks = {}
      local ptr = payload + offset
      while data_length > 0 do
         local size = ffi.cast("uint8_t*", ptr)[0]
         ptr = ptr + 1
         local str = ffi.new("char[?]", size + 1)
         copy_string(str, ptr, size)
         data_length = data_length - size
         ptr = ptr + size
      end
      dns_record.chunks = ffi.new("char*[?]", #chunks)
      for i=1,#chunks do
         dns_record.chunks[i] = chunks[i]
      end
   end

   return dns_record, total_len
end

local function usage(exit_code)
   print(require("program.dnssd.README_inc"))
   main.exit(exit_code)
end

function parse_args (args)
   local handlers = {}
   function handlers.h (arg)
      usage(0)
   end
   args = lib.dogetopt(args, handlers, "hl:", long_opts)
   if #args > 1 then usage(1) end
   return args
end

function run(args)
   args = parse_args(args)
   local iface = assert(args[1])

   print(("Capturing packets from interface '%s'"):format(iface))

   local c = config.new()
   config.app(c, "iface", RawSocket, iface)
   config.app(c, "sink", basic_apps.Sink)
   config.link(c, "iface.tx -> sink.input")

   engine.configure(c)
   engine.main({duration=1, report = {showapps = true, showlinks = true}})
end

local function read_records(payload, n)
   local rrs = {}
   local ptr = payload
   local total_len = 0
   for i=1, n do
      local rr, len = DNS.parse_record(ptr)
      ptr = ptr + len
      total_len = total_len + len
      table.insert(rrs, rr)
   end
   return rrs, total_len
end

local function collect_records(payload, t, n)
   local rrs, len = read_records(payload, n)
   for _, each in ipairs(rrs) do table.insert(t, each) end
   payload = payload + len
end
function selftest()
   -- MDNS response.
   local pkt = packet.from_string(lib.hexundump ([[
      01:00:5e:00:00:fb 54:60:09:47:6b:88 08 00 45 00
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

   local function dns_type(dns_record)
      print(ntohs(dns_record.h.type))
   end

   function parse_mdns_response (pkt)
      assert(MDNS.is_mdns(pkt))
      local mdns_hdr, size = mdns_parse(pkt)
      local payload_offset = ethernet_header_size + ipv4_header_size + udp_header_size
      local payload = pkt.data + payload_offset + size + 1

      -- Collect all DNS records.
      local t = {
         questions = {},
         answer_rrs = {},
         authority_rrs = {},
         additional_rrs = {},
      }
      collect_records(payload, t.questions, mdns_hdr.questions)
      collect_records(payload, t.answer_rrs, mdns_hdr.answer_rrs)
      collect_records(payload, t.authority_rrs, mdns_hdr.authority_rrs)
      collect_records(payload, t.additional_rrs, mdns_hdr.additional_rrs)

      assert(#t.answer_rrs == 1)
      assert(#t.additional_rrs == 3)
   end

   parse_mdns_response(pkt)
end
