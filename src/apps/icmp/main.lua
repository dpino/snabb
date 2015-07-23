local config = require("core.config")
local app = require("core.app")
local link = require("core.link")

local pcap = require("apps.pcap.pcap")
local icmp = require("apps.icmp.icmp")

function run (parameters)
   if not (#parameters == 2) then
      error("Usage: apps.icmp.icmp <input.pcap> <output.pcap>")
   end
   local input = parameters[1]
   local output = parameters[2]

   local c = config.new()
   config.app(c, "incoming", pcap.PcapReader, input)
   config.app(c, "icmp", icmp.icmp)
   config.app(c, "outgoing", pcap.PcapWriter, output)

   config.link(c, "incoming.output -> icmp.input")
   config.link(c, "icmp.output -> outgoing.input")

   app.configure(c)
   app.main({duration = 1, report = { showlinks = true}})
end

run(main.parameters)
