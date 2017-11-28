module(..., package.seeall)

local lib = require("core.lib")
local datagram = require("lib.protocol.datagram")
local ipv4 = require("lib.protocol.ipv4")
local ethernet = require("lib.protocol.ethernet")
local udp = require("lib.protocol.udp")
local lwdebug = require("apps.lwaftr.lwdebug")
local RawSocket = require("apps.socket.raw").RawSocket
local filter = require("lib.pcap.filter")

local print_pkt = lwdebug.print_pkt
local htons, ntohs = lib.htons, lib.ntohs

local ffi = require("ffi")

ffi.cdef[[
   typedef struct {
      uint16_t transaction_id;
      uint16_t flags;
      uint16_t questions;
      uint16_t answer_rrs;
      uint16_t authority_rrs;
      uint16_t additional_rrs;
      uint8_t queries[14];
      uint8_t auth_nameservers[16];
   } mdns_t;
]]

local mdns = {}

local mDNS = {}

function mDNS.new (args)
   local o = {
      ellapse = 1, -- 1 second ellapse between requests.
      request = mDNS.build_request(args.eth, args.ip)
   }
   return setmetatable(o, {__index=mDNS})
end

function mDNS.build_request (eth, ip)
   local pkt = packet.allocate()
   local dgram = datagram:new(pkt)
   dgram:push(udp:new({
      src_port = htons(1234),
      dst_port = htons(5353),
   }))
   dgram:push(ipv4:new({
      src = ipv4:pton(ip),
      dst = ipv4:pton("224.0.0.251"),
   }))
   dgram:push(ethernet:new({
      src = ethernet:pton(eth),
      dst = ethernet:pton("01:00:5E:00:00:FB"),
      type = htons(0x800),
   }))
   pkt = dgram:packet()
   return pkt
end

function mDNS.build_request()
	return packet.from_string(lib.hexundump([[
		01:00:5e:00:00:fb 44:85:00:4f:b8:fc 08 00 45 00
		00 55 32 7c 00 00 01 11 8f 5a c0 a8 56 1e e0 00
		00 fb e3 53 14 e9 00 41 89 9d 25 85 01 20 00 01
		00 00 00 00 00 01 09 5f 73 65 72 76 69 63 65 73
		07 5f 64 6e 73 2d 73 64 04 5f 75 64 70 05 6c 6f
		63 61 6c 00 00 0c 00 01 00 00 29 10 00 00 00 00
		00 00 00
	]], 99))
end

function mDNS:pull ()
   local tx = assert(self.output.tx)
   -- Send request only once.
   while not link.full(tx) and not self.done do
      link.transmit(tx, self.request)
      self.done = true
   end
end

function mDNS:push ()
   local input = assert(self.input.input)

   while not link.empty(input) do
      local pkt = link.receive(input)

      -- Check packet is DNS.
      if filter:new("dst port 5353"):match(pkt.data, pkt.length) then
         local payload = ffi.new('uint8_t[?]', 256)
         local len = pkt.length - 40
         ffi.copy(payload, pkt.data + 40, len)

         --[[
         for i=0,len-1 do
            local c = string.lower(string.char(payload[i]))
            if c:match("%x") then
               io.write(c)
            end
         end
         io.write("\n")
         --]]
         print(ffi.string(payload, len))
      end
   end
end

function mDNS:log (pkt)

end

function run (args)
   -- local iface = assert(args[1], "Not valid interface: "..iface)
   local iface = "wlp3s0"

   local c = config.new()
   config.app(c, "nic", RawSocket, iface)
   config.app(c, "mDNS", mDNS)

   config.link(c, "mDNS.tx -> nic.rx")
   config.link(c, "nic.tx -> mDNS.input")

   engine.configure(c)
   engine.main()
end

function selftest()
   print("selftest")
   local mdns = mDNS.new({eth="02:02:02:00:00:00", ip="192.168.0.1"})
   local pkt = mdns.request
   local eth_hdr = ethernet:new_from_mem(pkt.data, 14)
   assert(ethernet:ntop(eth_hdr:src()) == "02:02:02:00:00:00")
   assert(ethernet:ntop(eth_hdr:dst()) == "01:00:5e:00:00:fb")
   assert(ntohs(eth_hdr:type()) == 0x0800)
   local ip_hdr = ipv4:new_from_mem(pkt.data + 14, 20)
   assert(ipv4:ntop(ip_hdr:src()) == "192.168.0.1")
   assert(ipv4:ntop(ip_hdr:dst()) == "224.0.0.251")
   local udp_hdr = udp:new_from_mem(pkt.data + 34, 20)
   assert(lib.ntohs(udp_hdr:dst_port()) == 5353)
   print("ok")
end
