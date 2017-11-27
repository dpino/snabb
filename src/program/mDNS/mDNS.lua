module(..., package.seeall)

local lib = require("core.lib")
local datagram = require("lib.protocol.datagram")
local ipv4 = require("lib.protocol.ipv4")
local ethernet = require("lib.protocol.ethernet")
local udp = require("lib.protocol.udp")

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

function mDNS:pull ()
   local tx = assert(pull.output.tx)
   local now = main.time()
   while not link.full(tx) do
      -- Send mDNS request every ellapse seconds.
      if not self.last or now - self.last > self.ellapse then
         link.transmit(output, self.request)
         self.last = now
      end
   end
end

function mDNS:push ()
   local input = assert(self.input.input)

   while not link.empty(input) do
      local pkt = link.receive(input)
      -- Check packet is DNS.
   end
end

function mDNS:log (pkt)

end

function run (args)
   local iface = assert(args[1], "Not valid interface: "..iface)

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
