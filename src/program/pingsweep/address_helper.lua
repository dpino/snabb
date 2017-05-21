module(..., package.seeall)

local bit = require("bit")
local ffi = require("ffi")
local ipv4 = require("lib.protocol.ipv4")

local C = ffi.C
local rshift, band = bit.rshift, bit.band

local AddressHelper = {}

function AddressHelper.network_address (addr, cidr)
	cidr = assert(tonumber(cidr))
	assert(cidr >= 0 or cidr <= 32)
	local num = band(as_num(ipv4:pton(addr), 2^cidr-1))
	local arr = as_arr(num)
	return ("%d.%d.%d.%d"):format(arr[3], arr[2], arr[1], arr[0])
end

function as_num (addr)
   return addr[3] * 2^24 + addr[2] * 2^16 + addr[1] * 2^8 + addr[0]
end

function as_arr (n)
   local ret = ffi.new("uint8_t[?]", 4)
	ret[0] = rshift(n, 24)
	ret[1] = band(rshift(n, 16), 0xff)
	ret[2] = band(rshift(n, 8), 0xff)
	ret[3] = band(n, 0xff)
	return ret
end

function selftest ()
	local ip = "192.168.0.1/24"
	local addr, cidr = ip:match("([^/]+)/(.*)$")
	print(AddressHelper.network_address(addr, cidr))
end

return AddressHelper
