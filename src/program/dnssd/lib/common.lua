module(..., package.seeall)

local ffi = require("ffi")
local math = require("math")

function r16 (ptr)
   return ffi.cast("uint16_t*", ptr)[0]
end

function r32 (ptr)
   return ffi.cast("uint32_t*", ptr)[0]
end

function set (...)
   local ret = {}
   for _, each in ipairs(...) do ret[each] = true end
   return ret
end

function contains (set, key)
   return set[key]
end

function copy_string (src, len)
   len = len or #src
   local dst = ffi.new("char[?]", len + 1)
   ffi.copy(dst, src, len)
   dst[len] = 0
   return dst
end

function rand16 ()
   return math.ceil(math.random() * 65535)
end

function hex (val)
   return ("%.2x"):format(val)
end
