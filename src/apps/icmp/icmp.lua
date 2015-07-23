module(...,package.seeall)

local utils = require("apps.icmp.utils")

local bytes, byte, word16 = utils.bytes, utils.byte, utils.word16
local word32 = utils.word32

icmp = {}

local ARP_HDR_SIZE   = 28
local ETHER_HDR_SIZE = 14
local IPV4_HDR_SIZE  = 20
local TRANSPORT_BASE = 34  -- Tranport layer (TCP/UDP/etc) header start.

local PROTO_ARP     = 0x806
local PROTO_IPV4    = 0x800
local PROTO_TCP     = 6
local PROTO_UDP     = 17
local PROTO_ICMP    = 1

function icmp:new()
   local result = { packet_counter = 0 }
   return setmetatable(result, { __index = icmp })
end

function icmp:push(p)
   local i = assert(self.input.input, "input port not found")
   local o = assert(self.output.output, "output port not found")

   while not link.empty(i) and not link.full(o) do
      self:process_packet(i, o)
      self.packet_counter = self.packet_counter + 1
   end
end

local function ethertype(p)
   return word16(p, ETHER_HDR_SIZE - 2)
end

local function ipv4_proto(p)
   if ethertype(p) == PROTO_IPV4 then
      return byte(p, ETHER_HDR_SIZE + 9)
   end
end

local function icmp_id(p)
   local offset = ETHER_HDR_SIZE + IPV4_HDR_SIZE + 4
   return word16(p, offset)
end

local function icmp_seq(p)
   local offset = ETHER_HDR_SIZE + IPV4_HDR_SIZE + 6
   return word16(p, offset)
end


local Proxy = {}

function Proxy:new(ip)
   local o = {
      ip = ip
   }
   return setmetatable(o, {__index = Proxy})
end

function Proxy:hash(icmp_id, src, dest)
   return ("%d-%d-%d"):format(icmp_id, src, dest)
end

function Proxy:add(id, ip)
   self.table[id] = ip
end

function icmp:process_packet(i, o)
   local p = link.receive(i)

   -- Is ICMP
   if ipv4_proto(p) == PROTO_ICMP then
      if start_session(p) then

      end
      print(("ID: %d; seq: %d"):format(icmp_id(p), icmp_seq(p)))
   end

   link.transmit(o, p)
end
