module(..., package.seeall)

local utils = require("apps.basicnat.utils")
local ffi = require("ffi")

local bytes, byte, word16 = utils.bytes, utils.byte, utils.word16
local word32 = utils.word32

--- ### `basicnat` app: Implement http://www.ietf.org/rfc/rfc1631.txt Basic NAT.
--- This translates one IP address to another IP address.
--
BasicNAT = {}

local ARP_HDR_SIZE   = 28
local ETHER_HDR_SIZE = 14
local IPV4_HDR_SIZE  = 20
local TRANSPORT_BASE = 34  -- Tranport layer (TCP/UDP/etc) header start.

local PROTO_ARP     = 0x806
local PROTO_IPV4    = 0x800
local PROTO_TCP     = 6
local PROTO_UDP     = 17

local function debug(...)
   io.write("### DEBUG: ")
   print(...)
end

local function format_ip(ip)
   local t = {}
   if ip == nil then return "" end
   if type(ip) == "number" then
      for _, b in bytes(ip, 4) do
         table.insert(t, b)
      end
   else
      for i=0,3 do
         table.insert(t, ip[i])
      end
   end
   return table.concat(t, ".")
end

local function checksum_carry_and_not(csum)
   while csum > 0xffff do -- Process the carry nibbles.
      local carry = bit.rshift(csum, 16)
      csum = bit.band(csum, 0xffff) + carry
   end
   return bit.band(bit.bnot(csum), 0xffff)
end

-- https://en.wikipedia.org/wiki/IPv4_header_checksum.
local function calculate_checksum(p, offset)
   local offset = offset or ETHER_HDR_SIZE
   local checksum = 0
   for i = offset, offset + 18, 2 do
      if i ~= offset + 10 then -- The checksum bytes are assumed to be 0.
         checksum = checksum + p.data[i] * 0x100 + p.data[i+1]
      end
   end
   return checksum_carry_and_not(checksum)
end

local function checksum(p, val)
   local offset = ETHER_HDR_SIZE + 10
   return word16(p, offset, val)
end

local function ethertype(p)
   return word16(p, ETHER_HDR_SIZE - 2)
end

local function ip_proto(p)
   if ethertype(p) == PROTO_IPV4 then
      return byte(p, ETHER_HDR_SIZE + 9)
   end
end

local function tcplen(p)
   return word16(p, ETHER_HDR_SIZE + 2) - 20
end

local function transport_checksum(p)
   local csum = 0
   -- First 64 bytes of the TCP pseudo-header: the ip addresses.
   for i = ETHER_HDR_SIZE + 12, ETHER_HDR_SIZE + 18, 2 do
      csum = csum + word16(p, i)
   end
   -- Add the protocol field of the IPv4 header to the csum.
   csum = csum + ip_proto(p)
   local tcplen = tcplen(p)
   csum = csum + tcplen -- End of pseudo-header.

   for i = TRANSPORT_BASE, TRANSPORT_BASE + tcplen - 2, 2 do
      if i ~= TRANSPORT_BASE + 16 then -- The csum bytes are zero.
         csum = csum + word16(p, i)
      end
   end
   if tcplen % 2 == 1 then
      csum = csum + byte(p, TRANSPORT_BASE + tcplen - 1)
   end
   return checksum_carry_and_not(csum)
end

local function refresh_checksum(p)
   checksum(p, calculate_checksum(p))
   local proto = ip_proto(p)
   if proto == PROTO_TCP then
      word16(p, TRANSPORT_BASE + 16, transport_checksum(p))
      return true
   end
   if proto == PROTO_UDP then
      -- IPv4 UDP checksums are optional.
      word16(p, TRANSPORT_BASE + 6, 0)
      return true
   end
   -- Didn't attempt to change a transport-layer checksum.
   return false
end

-- Reads or writes source IP. It does not refresh checksum.
local function src_ip(p, val)
   if ethertype(p) == PROTO_ARP then
      local offset = ETHER_HDR_SIZE + ARP_HDR_SIZE - 14
      return word32(p, offset, val)
   end
   if ethertype(p) == PROTO_IPV4 then
      local offset = ETHER_HDR_SIZE + IPV4_HDR_SIZE - 8
      return word32(p, offset, val)
   end
end

-- Reads or writes destination IP. It does not refresh checksum.
local function dst_ip(p, val)
   if ethertype(p) == PROTO_ARP then
      local offset = ETHER_HDR_SIZE + ARP_HDR_SIZE - 4
      return word32(p, offset, val)
   end
   if ethertype(p) == PROTO_IPV4 then
      local offset = ETHER_HDR_SIZE + IPV4_HDR_SIZE - 4
      return word32(p, offset, val)
   end
end

local function to_uint32(a, b, c, d)
   return a * 0x1000000 + b * 0x10000 + c * 0x100 + d
end

local function ip_to_uint32(ip)
   local t = {}
   for each in ip:gmatch("(%d+)") do
      each = tonumber(each)
      assert(each >= 0 and each <= 255)
      table.insert(t, each)
   end
   return to_uint32(unpack(t))
end

-- Format: 10.0.0.0/24
local function parse_network_ip(ip)
   local network, pos = ip:match("([0-9.]+)()")
   local mask = ip:match("/([0-9]+)", pos)
   return ip_to_uint32(network), tonumber(mask) or 32
end

--

function BasicNAT:new(c)
   local network, len
   if c.network then
      network, len = parse_network_ip(c.network)
   end
   local o = {
      public_ip = ip_to_uint32(c.public_ip),
      private_ip = ip_to_uint32(c.private_ip),
      netmask = bit.bswap(2^len - 1),
      network = network,
   }
   return setmetatable(o, { __index = BasicNAT })
end

function BasicNAT:push(p)
   local i = assert(self.input.input, "input port not found")
   local o = assert(self.output.output, "output port not found")

   while not link.empty(i) and not link.full(o) do
      self:process_packet(i, o)
   end
end

function BasicNAT:process_packet(i, o)
   local p = link.receive(i)
   self:rewrite(p)
   link.transmit(o, p)
end

function BasicNAT:rewrite(p)
   -- Only attempt to alter ipv4 packets. Assume an Ethernet encapsulation.
   if p.data[12] ~= 8 or p.data[13] ~= 0 then return p end
   local needs_refresh = false
   local ip = {
      src = src_ip(p),
      dst = dst_ip(p),
   }
   if self:is_private_network(ip.src) and self:is_public_network(ip.dst) then
      src_ip(p, self:mask(ip.src))
      needs_refresh = true
   end
   if ip.dst == self.public_ip and self:is_public_network(ip.src) then
      dst_ip(p, self:unmask(ip.dst))
      needs_refresh = true
   end
   if needs_refresh then
      refresh_checksum(p)
   end
end

function BasicNAT:is_private_network(ip)
   return bit.band(ip, self.netmask) == bit.tobit(self.network)
end

function BasicNAT:is_public_network(ip)
   return not self:is_private_network(ip)
end

-- TODO: Save private_ip in a store and return public address
function BasicNAT:mask(private_ip)
   return self.public_ip
end

-- TODO: Retrieve private address from a store
function BasicNAT:unmask(ip)
   return self.private_ip
end

---

local function testIPv4GetSet()
   print("Test ipv4 operations")
   local p = {
      data = ffi.new("uint8_t[?]", 4)
   }
   for i=0,3 do
      if i % 2 == 1 then
         p.data[i] = 0xff
      else
         p.data[i] = 0
      end
   end

   -- Prints 0.255.0.255
   assert("0.255.0.255" == format_ip(p.data), "Wrong format_ip")
   print(("0.255.0.255 == %s"):format(format_ip(p.data)))

   local ip = 0xFF996633
   word32(p, 0, ip)
   ip = word32(p, 0)
   -- Prints 255.153.102.51
   print(("255.153.102.51 == %s"):format(format_ip(ip)))
   assert("255.153.102.51" == format_ip(ip))

   -- Prints 65535
   local ip = 65535
   assert(ip == ip_to_uint32("0.0.255.255"), "Wrong ip_to_uint32")
   print(("%d == %d"):format(ip, ip_to_uint32("0.0.255.255")))

   print("---")
end

local function create_packet(data)
   local p = {
      data = ffi.new("uint8_t[?]", #data)
   }
   for i=1,#data do
      p.data[i-1] = data[i]
   end
   return p
end

local function raw(data)
   local result = {}
   for byte in data:gmatch("(%x+)") do
      table.insert(result, tonumber(byte, 16))
   end
   return result
end

local function testIPChecksum()
   print("Test IP checksum")
   local p = create_packet(raw([[
      00 1b 21 a9 22 48 f0 de f1 61 b6 22 08 00 45 00
      00 34 59 1a 40 00 40 06 b0 8e c0 a8 14 a9 6b 15
      f0 b4 de 0b 01 bb e7 db 57 bc 91 cd 18 32 80 10
      05 9f 38 2a 00 00 01 01 08 0a 06 0c 5c bd fa 4a
      e1 65
   ]]))
   local csum = word16(p, ETHER_HDR_SIZE + 10)
   assert(calculate_checksum(p) == csum)
   print(("IP Checksum: 0x%x"):format(csum))
   print("---")
end

local function testTCPChecksum()
   print("Test TCP checksum")
   local p = create_packet(raw([[
      00 1b 21 a9 22 48 f0 de f1 61 b6 22 08 00 45 00
      00 34 59 1a 40 00 40 06 b0 8e c0 a8 14 a9 6b 15
      f0 b4 de 0b 01 bb e7 db 57 bc 91 cd 18 32 80 10
      05 9f 38 2a 00 00 01 01 08 0a 06 0c 5c bd fa 4a
      e1 65
   ]]))
   local csum = word16(p, TRANSPORT_BASE + 16)
   assert(transport_checksum(p) == csum)
   print(("TCP Checksum: 0x%x"):format(csum))
   print("---")
end

function selftest()
   testIPv4GetSet()
   testIPChecksum()
   testTCPChecksum()
   print("OK")
end
