-- Use of this source code is governed by the Apache 2.0 license; see COPYING.

module(...,package.seeall)

local S = require("syscall")
local ffi = require("ffi")
local C = ffi.C

require("apps.socket.xdp.xdpsock_h")

local XDPSocket = {}
XDPSocket.__index = XDPSocket

function XDPSocket.new (ifname)
   assert(ifname)
   local sock_fd = C.xdp_open(ifname)
   if not sock_fd or sock_fd == -1 then
      os.exit("Could not open interface: "..ifname)
   end

   local o = {
      rx_p = packet.allocate(),
      dev = {
         sock_fd = sock_fd,
         can_receive = C.xdp_can_receive,
         can_transfer = C.xdp_can_transfer,
         receive = C.xdp_receive,
         transfer = C.xdp_transfer,
      }
   }
   return setmetatable(o, {__index = XDPSocket})
end

function XDPSocket:can_receive ()
   return self.dev.can_receive(self.dev.sock_fd)
end

function XDPSocket:receive ()
   local p = self.rx_p
   local len = self.dev.receive(self.dev.sock_fd, p.data, packet.max_payload)
   p.length = len
   return p
end

function XDPSocket:pull ()
   local tx = self.input and self.input.tx
   if not tx then return end
   local limit = engine.pull_npackets
   while limit > 0 and self:can_receive() do
      limit = limit - 1
      link.transmit(tx, self:receive())
   end
end

function XDPSocket:can_transfer()
   return self.dev.can_transfer(self.dev.sock_fd)
end

function XDPSocket:transfer (p)
   local sz = self.dev.transfer(self.dev.sock_fd, p.data, p.length)
   if sz >= 0 then
      assert(sz == p.length)
   end
end

function XDPSocket:push ()
   local rx = self.output and self.output.rx
   if not rx then return end
   while not link.empty(rx) and self:can_transfer() do
      local p = link.receive(rx)
      self:transfer(p)
      packet.free(p)
   end
end

function selftest ()
   print("selftest:")
   local fd = 1
   local len = packet.max_payload
   local buffer = ffi.new("uint8_t[?]", len)

   C.xdp_open("eth0");
   C.xdp_can_receive(fd);
   C.xdp_can_transfer(fd);
   C.xdp_receive(fd, buffer, packet.max_payload);
   C.xdp_transfer(fd, buffer, len);

   local xdp = XDPSocket.new("eth0")
   xdp.input = {
       tx = link.new("l_input")
   }
   xdp.output = {
       rx = link.new("l_output")
   }
   link.transmit(xdp.output.rx, packet.allocate())
   xdp:push()
   link.transmit(xdp.input.tx, packet.allocate())
   xdp:pull()
   print("ok")
end
