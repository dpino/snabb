module(...,package.seeall)

local ffi = require("ffi")
local C = ffi.C

split = {}

function split:new()
   local result = { packet_counter = 0 }
   return setmetatable(result, { __index = split })
end

local ETHER_HDR_SIZE = 14
local IPV4_HDR_SIZE  = 20

local function g_byte(pkt, offset)
   return ffi.cast("uint8_t*", pkt.data + offset)[0]
end

local function g_word(pkt, offset)
   return ffi.cast("uint16_t*", pkt.data + offset)[0]
end

local function g_dword(pkt, offset)
   return ffi.cast("uint32_t*", pkt.data + offset)[0]
end

local function icmp_type(pkt)
   local offset = ETHER_HDR_SIZE + IPV4_HDR_SIZE
   return g_byte(pkt, offset)
end

local function icmp_seq(pkt)
   local offset = ETHER_HDR_SIZE + IPV4_HDR_SIZE
   local SEQ_FIELD = 7
   return g_byte(pkt, offset + SEQ_FIELD)
end

function split:push(p)
   local i = assert(self.input.input, "input port not found")
   local o = assert(self.output.output, "output port not found")

   while not link.empty(i) and not link.full(o) do
      self:process_packet(i, o)
      self.packet_counter = self.packet_counter + 1
   end
end

function split:process_packet(i, o)
   local p = link.receive(i)

   if icmp_type(p) == 8 and icmp_seq(p) % 2 == 1 then
      link.transmit(o, p)
   else
      packet.free(p)
   end
end
