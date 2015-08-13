module(..., package.seeall)

local ffi = require("ffi")

-- Functions for managing packets.

-- Prints out a packet.
function packet_dump(p)
   local result = {}
   local d = p.data
   local len = p.length
   for i=0,len do
      table.insert(result, ("%.2x"):format(d[i]))
      if i == 13 then table.insert(result, "\n") end
   end
   return table.concat(result, " ")
end

-- Iterator of a value into its bytes.
-- For instance, 'bytes(val, 4)' divides 'val' into 4 bytes.
function bytes(val, n)
   assert(n and n % 2 == 0 and n <= 4, "number of bytes is nil or an odd number")

   -- Decompose val in n bytes
   local t = {}
   local start = n*8 - 8
   for i=start,0,-8 do
      table.insert(t, bit.band(bit.rshift(val, i), 0xff))
   end

   -- Iterator
   local function iter_bytes(t, i)
      i = i + 1
      local v = t[i]
      if v then
         return i, v
      end
   end
   return iter_bytes, t, 0
end

-- Reads or sets a byte value into 'p' at 'offset'.
function byte(p, offset, val)
   if not val then
      return p.data[offset]
   end
   p.data[offset] = val
end

-- Reads or sets a two bytes value into 'p' at 'offset'.
function word16(p, offset, val)
   if not val then
      local d = p.data
      return d[offset] * 0x100 + d[offset+1]
   end
   p.data[offset] = bit.rshift(val, 8)
   p.data[offset+1] = bit.band(val, 0xff)
end

-- Reads or sets a four bytes value into 'p' at 'offset'.
function word32(p, offset, val)
   if not val then
      local d = p.data
      return d[offset] * 0x1000000 + d[offset+1] * 0x10000 +
         d[offset+2] * 0x100 + d[offset+3]
   end
   p.data[offset] = bit.rshift(val, 24)
   p.data[offset+1] = bit.rshift(val, 16)
   p.data[offset+2] = bit.rshift(val, 8)
   p.data[offset+3] = bit.band(val, 0xff)
end

local function testUint16GetSet()
   print("Test uint16 operations")
   local p = {
      data = ffi.new("uint8_t[?]", 2)
   }
   p.data[0] = 0xff
   p.data[1] = 0

   local val = word16(p, 0)
   assert(val == 0xff00, "Wrong value")
   print(("0x%x == 0x%x"):format(val, 0xff00))

   word16(p, 0, 0xff00)
   val = word16(p, 0)
   print(("0x%x == 0x%x"):format(val, 0xff00))
   assert(val == 0xff00, "Wrong value")
   print("---")
end

local function testUint32GetSet()
   print("Test uint32 operations")
   local p = {
      data = ffi.new("uint8_t[?]", 4)
   }
   p.data[0] = 0xaa
   p.data[1] = 0xbb
   p.data[2] = 0xcc
   p.data[3] = 0xdd

   local val = word32(p, 0)
   print(("0x%x == 0x%x"):format(val, 0xaabbccdd))
   assert(val == 0xaabbccdd, "Wrong value")

   word32(p, 0, 0xaabbccdd)
   val = word32(p, 0)
   print(("0x%x == 0x%x"):format(val, 0xaabbccdd))
   assert(val == 0xaabbccdd, "Wrong value")
   print("---")
end

function selftest()
   testUint16GetSet()
   testUint32GetSet()
end
