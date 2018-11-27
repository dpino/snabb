-- Use of this source code is governed by the Apache 2.0 license; see COPYING.

module(..., package.seeall)

local pcap = require("apps.pcap.pcap")
local xdpsock = require("apps.socket.af_xdp.xdpsock")

function run (parameters)
   if not (#parameters == 2) then
      print("Usage: example_afxdp <pcap-file> <interface>")
      main.exit(1)
   end
   local pcap_file = parameters[1]
   local interface = parameters[2]

   local c = config.new()
   config.app(c, "capture", pcap.PcapReader, pcap_file)
   config.app(c, "playback", xdpsock.AfxdpSocket, interface)

   config.link(c, "capture.output -> playback.rx")

   engine.configure(c)
   engine.main({duration=1, report = {showlinks=true}})
   engine.app_table.playback:stop()
end
