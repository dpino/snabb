module(..., package.seeall)

local lib = require("core.lib")

local XDPSocket = require("apps.socket.xdp.xdp").XDPSocket 
local basic_apps = require("apps.basic.basic_apps")

function selftest()
   print("selftest")

   local pkt = packet.from_string(lib.hexundump([=[
      3c fd fe 9e 7f 71 ec b1 d7 98 3a c0 08 00 45 00
      00 2e 00 00 00 00 40 11 88 97 05 08 07 08 c8 14
      1e 04 10 92 10 92 00 1a 6d a3 34 33 1f 69 40 6b
      54 59 b6 14 2d 11 44 bf af d9 be aa
   ]=], 60))

   local c = config.new()
   config.app(c, "source", basic_apps.Source)
   config.app(c, "tee", basic_apps.Tee)
   config.app(c, "nic0", XDPSocket, "veth0")
   config.app(c, "sink", basic_apps.Sink)

   config.link(c, "source.tx -> tee.rx")
   config.link(c, "tee.tx -> nic0.rx")

   engine.configure(c)
   engine.app_table.source:set_packet(pkt)

   engine.main({duration=1, report={showlinks=true}})

   --[[
   local c = config.new()
   config.app(c, "source", basic_apps.Source)
   config.app(c, "tee", basic_apps.Tee)
   config.app(c, "nic0", XDPSocket, "veth0")
   config.app(c, "nic1", XDPSocket, "veth1")
   config.app(c, "sink", basic_apps.Sink)

   config.link(c, "source.tx -> tee.rx")
   config.link(c, "tee.tx -> nic0.rx")
   config.link(c, "nic1.tx -> sink.rx")

   engine.configure(c)
   engine.app_table.source:set_packet(pkt)

   engine.main({duration=0.1, report={showlinks=true}})
   --]]

   --[[
   local c = config.new()
   config.app(c, "nic1", XDPSocket, "veth1")
   config.app(c, "sink", basic_apps.Sink)

   config.link(c, "nic1.tx -> sink.rx")

   engine.configure(c)

   engine.main({duration=0.1, report={showlinks=true}})
   --]]
end
