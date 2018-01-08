module(..., package.seeall)

local common = require("program.dnssd.lib.common")
local ffi = require("ffi")
local ipv4 = require("lib.protocol.ipv4")
local lib = require("core.lib")

local htons, ntohs = lib.htons, lib.ntohs

local set, contains = common.set, common.contains
local copy_string = common.copy_string

local function r16 (ptr)
   return ffi.cast("uint16_t*", ptr)[0]
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

-- PTR record.
local dns_record_ptr_t = ffi.typeof([[
   struct {
      $ h;
      char* domain_name;
   } __attribute__((packed))
]], dns_record_head_t)
local dns_record_ptr_ptr_t = ffi.typeof("$*", dns_record_ptr_t)

-- A record.
local dns_record_a_t = ffi.typeof([[
   struct {
      $ h;
      uint8_t address[4];
   } __attribute__((packed))
]], dns_record_head_t)
local dns_record_a_ptr_t = ffi.typeof("$*", dns_record_a_t)

-- SRV record.
local dns_record_srv_t = ffi.typeof([[
   struct {
      $ h;
      uint16_t priority;
      uint16_t weight;
      uint16_t port;
      char* target;
   } __attribute__((packed))
]], dns_record_head_t)
local dns_record_srv_ptr_t = ffi.typeof("$*", dns_record_srv_t)

local srv_info_t = ffi.typeof[[
   struct {
      uint16_t priority;
      uint16_t weight;
      uint16_t port;
   } __attribute__((packed))
]]
local srv_info_ptr_t = ffi.typeof("$*", srv_info_t)

-- TXT record.
local dns_record_txt_t = ffi.typeof([[
   struct {
      $ h;
      char** chunks;
      uint8_t nchunks;
   } __attribute__((packed))
]], dns_record_head_t)
local dns_record_txt_ptr_t = ffi.typeof("$*", dns_record_txt_t)

local A   = htons(0x01)
local PTR = htons(0x0c)
local SRV = htons(0x21)
local TXT = htons(0x10)

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

   -- Check out if next two bytes are of type TXT.
   local maybe_type = r16(payload + 2)
   if maybe_type == TXT then
      len = 2
      type = maybe_type
   else
      -- Read out string until find end-of-string character.
      local ptr = payload
      local i = 0
      while true do
         -- PTR records's name end with an end-of-string character. Next byte belongs to type.
         if ptr[i] == 0 and ptr[i + 1] == 0 then i = i + 1 break end
         -- This zero belongs to type so break.
         if ptr[i] == 0 then break end
         i = i + 1
      end
      len = i
      type = r16(payload + len)
      if not contains(set{A, SRV, PTR}, type) then
         return nil, 0
      end
   end

   -- Copy head.
   local dns_record = new_dns_record(type)
   dns_record.h.name = copy_string(payload, len)
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
      ffi.copy(dns_record.address, payload + offset, 4)
   elseif type == PTR then
      dns_record.domain_name = copy_string(payload + offset, data_length)
   elseif type == SRV then
      local ptr = ffi.cast(srv_info_ptr_t, payload + offset)
      dns_record.priority = ptr.priority
      dns_record.weight = ptr.weight
      dns_record.port = ptr.port
      local size = ffi.sizeof(srv_info_t)
      local target_len = data_length - size
      dns_record.target = copy_string(payload + offset + size, target_len)
   elseif type == TXT then
      local chunks = {}
      local ptr = payload + offset
      while data_length > 0 do
         local size = tonumber(ptr[0])
         if not size or size <= 0 then break end
         table.insert(chunks, copy_string(ptr, size + 1))
         data_length = data_length - size
         ptr = ptr + size + 1
      end
      dns_record.chunks = ffi.new("char*[?]", #chunks)
      for i=1,#chunks do
         dns_record.chunks[i-1] = chunks[i]
      end
      dns_record.nchunks = #chunks
   end
   return dns_record, total_len
end

function DNS.parse_records (payload, n)
   n = n or 1
   assert(n >= 0)
   local rrs, total_len = {}, 0
   local ptr = payload
   for i=1, n do
      local rr, len = DNS.parse_record(ptr)
      ptr = ptr + len
      total_len = total_len + len
      table.insert(rrs, rr)
   end
   return rrs, total_len
end

-- Reads a string which has the format (length, char*).  If there are several
-- chunks they got separated by a dot.
local function format_string (cdata)
   local t = {}
   local ptr, i = cdata, 0
   while ptr[i] ~= 0 do
      -- Read uint8.
      local len = tonumber(ptr[i])
      if len <= 0 then break end
      -- Read string.
      i = i + 1
      for j=1,len do
         table.insert(t, string.char(ptr[i]))
         i = i + 1
      end
      -- Insert dot to separate parts.
      table.insert(t, ".")
   end
   -- Remove latest dot.
   local ret = table.concat(t)
   return ret:sub(1,#ret-1)
end

function DNS.print(rr)
   local w = io.write
   local function wln (...) w(...) w("\n") end
   local type = rr.h.type
   if type == A then
      w("Address: ")
      wln(ipv4:ntop(rr.address))
   elseif type == PTR then
      w("PTR: ")
      w("(")
      w("name: "..format_string(rr.h.name).."; ")
      w("domain-name: "..format_string(rr.domain_name))
      wln(")")
   elseif type == SRV then
      w("SRV: ")
      w("(")
      w("target: "..format_string(rr.target))
      wln(")")
   elseif type == TXT then
      w("TXT: ")
      w("(")
      for i=0, rr.nchunks-1 do
         local str = format_string(rr.chunks[i])
         if #str > 0 then
            w(str)
            w(";")
         end
      end
      wln(")")
   end
end
