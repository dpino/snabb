module(..., package.seeall)

local pcap = require("apps.pcap.pcap")
local packet_filter = require("apps.packet_filter.pcap_filter")

local MartianFilter = {}

function MartianFilter.new ()
   return setmetatable({}, {__index=MartianFilter})
end

function MartianFilter:push ()
   local input, output = assert(self.input.input), assert(self.output.output)

   while not link.empty(input) do
      local pkt = link.receive(input)
      link.transmit(output, pkt)
   end
end

function run (args)
   local filein = assert(args[1], "No input file")
   local fileout = args[2] or "output.pcap"

   local c = config.new()
   config.app(c, "reader", pcap.PcapReader, filein)
   config.app(c, "filter", MartianFilter)
   config.app(c, "writer", pcap.PcapWriter, fileout)

   config.link(c, "reader.output -> filter.input")
   config.link(c, "filter.output -> writer.input")

   engine.configure(c)
   engine.main({duration=1, report={showlinks=true}})
end
