module(..., package.seeall)

local RawSocket = require("apps.socket.raw").RawSocket
local ethernet = require("lib.protocol.ethernet")
local ipv4 = require("lib.protocol.ipv4")
local util = require("program.pingsweep.util")
local address_helper = require("program.pingsweep.address_helper")

local build_icmp_echo_pkt = util.build_icmp_echo_pkt
local iface_info = util.iface_info
local network_address = address_helper.network_address

PingSweep = {}

function PingSweep:new (ifname)
   local info = iface_info(assert(ifname, "required ifname"))
   local o = {
      ether = assert(info.ether, "no ethernet address"),
      src = assert(info.inet, "no inet address"),
      cidr = assert(info.cidr, "no cidr number"),
      count = 0,
      max = 1,
   }
   local packet_size = 64
   -- Fix: proper calculate broadcast address.
   local ip_broadcast = "192.168.86.255"
   o.pkt = build_icmp_echo_pkt(packet_size, info.ether, info.inet, ip_broadcast)
   o.discovered_hosts = {}
   return setmetatable(o, { __index = PingSweep })
end

function PingSweep:pull ()
   local o = assert(self.output.output)
   local now = os.time()

   while not link.full(o) do
      if os.time() - now > 1 then
         now = os.time()
         link.transmit(o, self.pkt)
         self.count = self.count + 1
      end

      if self.count == self.max then
         break
      end
   end
end

function PingSweep:push ()
   local i = assert(self.input.input)
   while not link.empty(i) do
      local pkt = link.receive(i)
      local ipv4_hdr = ipv4:new_from_mem(pkt.data + ethernet:sizeof(), pkt.length - ethernet:sizeof())
      local eth_hdr = ethernet:new_from_mem(pkt.data, ethernet:sizeof())
      if ipv4:ntop(ipv4_hdr:dst()) == self.src then
         local ip = ipv4:ntop(ipv4_hdr:src())
         self.discovered_hosts[ip] = ethernet:ntop(eth_hdr:src())
         packet.free(pkt)
      end
   end
end

function PingSweep:report ()
   for ip, eth in pairs(self.discovered_hosts) do
      print(("Discovered: %s (%s)"):format(ip, eth))
   end
end

local function parse_args (args)
   if #args ~= 1 then
      print("Usage: pingsweep <ifname>")
      main.exit(1)
   end
   return args[1]
end

function run (args)
   local ifname = parse_args(args)

   local c = config.new()

   config.app(c, "raw", RawSocket, ifname)
   config.app(c, "ping_sweep", PingSweep, ifname)

   config.link(c, "ping_sweep.output -> raw.rx")
   config.link(c, "raw.tx -> ping_sweep.input")

   engine.configure(c)
   engine.main({duration = 3, report = { show_apps = true}})

   local ping_sweep = engine.app_table.ping_sweep
   ping_sweep:report()
end
