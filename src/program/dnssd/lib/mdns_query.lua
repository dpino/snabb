module(..., package.seeall)

local common = require("program.dnssd.lib.common")
local datagram = require("lib.protocol.datagram")
local ethernet = require("lib.protocol.ethernet")
local ffi = require("ffi")
local ipv4 = require("lib.protocol.ipv4")
local lib = require("core.lib")
local udp = require("lib.protocol.udp")
local mdns = require("program.dnssd.lib.mdns")

local copy_string, rand16 = common.copy_string, common.rand16
local htons = lib.htons
local mdns_header_t = mdns.mdns_header_t

local CLASS_IN = htons(0x01)
local ETHER_PROTO_IPV4 = 0x0800
local MDNS_DST_ETHER = ethernet:pton("01:00:5e:00:00:fb")
local MDNS_DST_IPV4 = ipv4:pton("224.0.0.251")
local MDNS_DST_PORT = 5353
local TYPE_PTR = htons(0x0c)
local UDP_PROTOCOL = 0x11
local STANDARD_QUERY = 0x0

mDNSQuery = {}

local dns_query_t = ffi.typeof[[
   struct {
      char* name;
      uint16_t type;
      uint16_t class;
   } __attribute__((packed))
]]

local function read_uint16 (dst, src, pos)
   ffi.cast("uint16_t*", dst + pos)[0] = src
   return dst, pos + 2
end

local function read_string (dst, src, pos)
   local dst = ffi.new("char[?]", #src + 1)
   ffi.copy(dst, src, #src)
   dst[#src] = 0
   return dst, #src + 1
end

-- A mDNS's name field of the format _service._type._zone is encoded as
-- spliting each part by '.' and prepending each part's length.
local function encode_name (name)
   local t = {}
   local total_length = 0
	-- Split name by '.' and store in table 't'.
   for part in name:gmatch("[^.]+") do
      table.insert(t, part)
      total_length = total_length + (#part + 1)
   end
	-- Allocate destination string.
   local dst, pos = ffi.new("char[?]", total_length + 1), 0
	-- Helper function to append values to destination string.
   local function push (val)
      if type(val) == "number" then
         dst[pos] = val
         pos = pos + 1
      elseif type(val) == "string" then
         ffi.copy(dst + pos, val)
         pos = pos + #val
      else
         error("Unreachable")
      end
   end
	-- For each part append part's size and part value plus '.'.
   for _, part in ipairs(t) do
      push(#part)
      push(part)
   end
	-- Last part gets extra '.' overwritten with terminating string character.
   dst[total_length] = 0
   assert(pos == total_length)
   return dst, total_length
end

local function encode_query (name)
   local query = ffi.new(dns_query_t)
   local name, len = encode_name(name)
   local pos = 0
   local total_length = len + 1 + 2 + 2
   local buf = ffi.new("uint8_t[?]", total_length)

   -- Name.
   ffi.copy(buf, name, len)
   pos = pos + len + 1
   -- Type.
   buf, pos = read_uint16(buf, TYPE_PTR, pos)
   -- Class.
   buf, pos = read_uint16(buf, CLASS_IN, pos)

   assert(pos == total_length)
   return buf, total_length
end

local function encode_queries (queries)
   local ret = {}
   local total_length = 0
   for _, each in ipairs(queries) do
      local buf, len = encode_query(each)
      total_length = total_length + len
      table.insert(ret, {data = buf, len = len})
   end
   return ret, total_length
end

local function build_payload (queries)
   local body, len = encode_queries(assert(queries))
   local header = ffi.new(mdns_header_t)

   -- Set header.
   header.id = 0 -- htons(rand16())
   header.flags = STANDARD_QUERY
   header.questions = htons(#queries)
   header.answer_rrs = 0
   header.authority_rrs = 0
   header.additional_rrs = 0

   local total_length = ffi.sizeof(mdns_header_t) + len
   local buf = ffi.new("uint8_t[?]", total_length)

   -- Serialize header
   local pos = 0
   local attrs = {'id','flags','questions','answer_rrs','authority_rrs','additional_rrs'}
   for _, attr in ipairs(attrs) do
      buf, pos = read_uint16(buf, header[attr], pos)
   end
   -- Serialze body.
   for _, part in ipairs(body) do
      for j=0,part.len-1 do
         buf[pos] = part.data[j]
         pos = pos + 1
      end
   end
   assert(pos == total_length)
   return buf, pos
end

function mDNSQuery.new (args)
   local o = {
      src_eth = assert(args.src_eth),
      src_ipv4 = assert(args.src_ipv4),
   }
   return setmetatable(o, {__index=mDNSQuery})
end

function mDNSQuery:build (...)
   local names = assert({...})
   local dgram = datagram:new()
   local ether_h = ethernet:new({dst = MDNS_DST_ETHER,
                                 src = ethernet:pton(self.src_eth),
                                 type = ETHER_PROTO_IPV4})
   local ipv4_h = ipv4:new({dst = MDNS_DST_IPV4,
                            src = ipv4:pton(self.src_ipv4),
                            protocol = UDP_PROTOCOL,
                            id = 0x0c6f,
                            -- id = htons(rand16()),
                            flags = 0x02,
                            ttl = 255})
   local udp_h = udp:new({src_port = 5353,
                          dst_port = MDNS_DST_PORT})
   -- Add payload.
   local payload, len = build_payload(names)
   -- Set IPV4's total-length.
   ipv4_h:total_length(ipv4_h:sizeof() + udp_h:sizeof() + len)
   udp_h:length(udp_h:sizeof() + len)
   -- Generate packet.
   dgram:payload(payload, len)
   dgram:push(udp_h)
   dgram:push(ipv4_h)
   dgram:push(ether_h)
   return dgram:packet()
end

function selftest()
   local mdns_query = mDNSQuery.new({
      src_eth = "ce:6c:59:f2:f3:c1",
      src_ipv4 = "192.168.0.1",
   })
   local query = "_services._dns-sd._udp.local"
   local pkt = assert(mdns_query:build(query))

   local total_length = 14 + 20 + 8 + 12 + #query + 2 + 4
   assert(pkt.length == total_length)
end
