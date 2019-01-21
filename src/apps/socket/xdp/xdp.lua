-- Use of this source code is governed by the Apache 2.0 license; see COPYING.

module(...,package.seeall)

local S = require("syscall")

local ffi = require("ffi")
local C = ffi.C

require("apps.socket.xdp.xdpsock_app_h")

XDPSocket = {}
XDPSocket.__index = XDPSocket

function XDPSocket:new (ifname)
   assert(ifname)

   local ret = C.init_xdp(ifname) 
   if not ret then
      print("Error initializing XDP Socket in "..ifname)
      os.exit(1)
   end

   local o = {
      rx_p = packet.allocate(),
      dev = {
         context = ret,
         can_receive = C.can_receive,
         can_transfer = C.can_transfer,
         receive = C.receive,
         transfer = C.transfer,
      }
   }
   return setmetatable(o, {__index = XDPSocket})
end

function XDPSocket:tx_only ()
   return self.dev.tx_only()
end

function XDPSocket:rx_drop_all ()
   return self.dev.rx_drop_all()
end

function XDPSocket:can_receive ()
   return self.dev.can_receive(self.dev.context)
end

function XDPSocket:receive ()
   local p = self.rx_p
   local len = self.dev.receive(self.dev.context, p.data)
   p.length = len
   return p
end

function XDPSocket:pull ()
   local tx = self.output and self.output.tx
   if not tx then return end
   local limit = engine.pull_npackets
   while limit > 0 and self:can_receive() do
      limit = limit - 1
      link.transmit(tx, self:receive())
   end
end

function XDPSocket:can_transmit()
   return self.dev.can_transfer(self.dev.context)
end

function XDPSocket:transfer (p)
   return self.dev.transfer(self.dev.context, p.data, p.length)
end

function XDPSocket:push ()
   local rx = self.input and self.input.rx
   if not rx then return end
   while not link.empty(rx) and self:can_transmit() do
      local p = link.receive(rx)
      self:transfer(p)
      packet.free(p)
   end
end

function selftest ()
   print("selftest:")
   local lib = require("core.lib")

   local if_name = lib.getenv("SNABB_PCI0")
   if not if_name then
      print("skipped")
      return main.exit(engine.test_skipped_code)
   end

   local xdp = XDPSocket:new(if_name)
   xdp.input = {
      rx = link.new("l_input")
   }
   xdp.output = {
      tx = link.new("l_output")
   }
   local pkt = packet.from_string(lib.hexundump([=[
   3c fd fe 9e 7f 71 ec b1 d7 98 3a c0 08 00 45 00
   00 2e 00 00 00 00 40 11 88 97 05 08 07 08 c8 14
   1e 04 10 92 10 92 00 1a 6d a3 34 33 1f 69 40 6b
   54 59 b6 14 2d 11 44 bf af d9 be aa
   ]=], 60))
   link.transmit(xdp.input.rx, pkt)
   xdp:push()
   link.transmit(xdp.output.tx, pkt)
   xdp:pull()
   print("ok")
end
