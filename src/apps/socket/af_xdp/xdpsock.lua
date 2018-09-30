-- Use of this source code is governed by the Apache 2.0 license; see COPYING.

module(..., package.seeall)

local S = require("syscall")
local h = require("syscall.helpers")
local bit = require("bit")
local link = require("core.link")
local packet = require("core.packet")
local counter = require("core.counter")
local ethernet = require("lib.protocol.ethernet")
local ffi = require("ffi")
local C = ffi.C
local n  = 10

local c, t = S.c, S.types.t

require("apps.socket.af_xdp.xdp_sock_h")

ffi.cdef[[
typedef struct data_val {
    char **data;
    int *sz;
    int numb_packs;
} data_val;
]]

AfxdpSocket = {}

function AfxdpSocket:new (ifname)
   assert(ifname)
   local index, err = S.util.if_nametoindex(ifname)
   if not index then error(err) end

   local tp = h.htons(c.ETH_P["ALL"])
   local cifname = ffi.new("char[?]", #ifname, ifname)
   local sock = C.get_sock(cifname)
   
   local index, err = S.util.if_nametoindex(ifname)
   if not index then
      error(err)
   end


   return setmetatable({sock = sock,
                        rx_p = packet.allocate(),
                        shm  = { rxbytes   = {counter},
                                 rxpackets = {counter},
                                 rxmcast   = {counter},
                                 rxbcast   = {counter},
                                 txbytes   = {counter},
                                 txpackets = {counter},
                                 txmcast   = {counter},
                                 txbcast   = {counter} }},
                       {__index = AfxdpSocket})
end

function AfxdpSocket:pull ()
   local l = self.output.tx
   if l == nil then return end
   local limit = engine.pull_npackets
   while limit > 0 and self:can_receive() do
      limit = limit - 1
      self:receive(l)
   end
    C.close_sock()
end

function AfxdpSocket:can_receive ()
   local t, err = S.select({readfds = {self.sock}}, 0)
   while not t and (err.AGAIN or err.INTR) do
      t, err = S.select({readfds = {self.sock}}, 0)
   end
   assert(t, err)
   return t.count == 1
end

function AfxdpSocket:receive (l)
   local p = self.rx_p
    local data_val = C.read_sock()
    local data = data_val.data
    local sz = data_val.sz
    local nbp = data_val.numb_packs
    if nbp ~= 0 then
      for i=0, nbp-1 do
         ffi.copy(p.data, data[i], sz[i])
         p.length = sz[i]
         counter.add(self.shm.rxbytes, sz[i])
         counter.add(self.shm.rxpackets)
         if ethernet:is_mcast(p.data) then
            counter.add(self.shm.rxmcast)
         end
         if ethernet:is_bcast(p.data) then
            counter.add(self.shm.rxbcast)
         end
         link.transmit(l, packet.clone(p))
      end
    end
end

function AfxdpSocket:push ()
   local l = self.input.rx
   if l == nil then return end
   while not link.empty(l) and self:can_transmit() do
      local p = link.receive(l)
      self:transmit(p)
      counter.add(self.shm.txbytes, p.length)
      counter.add(self.shm.txpackets)
      if ethernet:is_mcast(p.data) then
         counter.add(self.shm.txmcast)
      end
      if ethernet:is_bcast(p.data) then
         counter.add(self.shm.txbcast)
      end
      packet.free(p)
   end
   C.close_sock()
end

function AfxdpSocket:can_transmit ()
   local t, err = S.select({writefds = {self.sock}}, 0)
   while not t and (err.AGAIN or err.INTR) do
      t, err = S.select({writefds = {self.sock}}, 0)
   end
   assert(t, err)
   return t.count == 1
end

function AfxdpSocket:transmit (p)
   local sz = C.write_sock(self.sock, p.data, p.length)
   assert(sz == p.length)
end

function AfxdpSocket:stop()
   self.sock:close()
   packet.free(self.rx_p)
end

function selftest ()
   -- Send a packet over the loopback device and check
   -- that it is received correctly.
   local datagram = require("lib.protocol.datagram")
   local ethernet = require("lib.protocol.ethernet")
   local ipv6 = require("lib.protocol.ipv6")
   local Match = require("apps.test.match").Match

   -- Initialize AfxdpSocket and Match.
   local c = config.new()
   config.app(c, "lo", AfxdpSocket, "lo")
   config.app(c, "match", Match, {fuzzy=true})
   config.link(c, "lo.tx->match.rx")
   engine.configure(c)
   local link_in, link_cmp = link.new("test_in"), link.new("test_cmp")
   engine.app_table.lo.input.rx = link_in
   engine.app_table.match.input.comparator = link_cmp
   -- Construct packet.
   local dg_tx = datagram:new()
   local src = ethernet:pton("02:00:00:00:00:01")
   local dst = ethernet:pton("02:00:00:00:00:02")
   local localhost = ipv6:pton("0:0:0:0:0:0:0:1")
   dg_tx:push(ipv6:new({src = localhost,
                        dst = localhost,
                        next_header = 59, -- No next header.
                        hop_limit = 1}))
   dg_tx:push(ethernet:new({src = src,
                            dst = dst,
                            type = 0x86dd}))
   -- Transmit packets.
   link.transmit(link_in, dg_tx:packet())
   link.transmit(link_cmp, packet.clone(dg_tx:packet()))
   engine.app_table.lo:push()
   -- Run engine.
   engine.main({duration = 0.01, report = {showapps=true,showlinks=true}})
   assert(#engine.app_table.match:errors() == 0)
   print("selftest passed")

   -- XXX Another useful test would be to feed a pcap file with
   -- pings to 127.0.0.1 and ::1 into lo and capture/compare
   -- the responses with a pre-recorded pcap.
end
