local app = require("core.app")
local config = require("core.config")
local pcap = require("apps.pcap.pcap")
local link = require("core.link")
local packet = require("core.packet")
local conntrack = require("apps.conntrack.conntrack")

function run(parameters)
   local filein, fileout = parameters[1], parameters[2]
   if not filein then
      filein = "apps/conntrack/tests/input.pcap"
   end
   if not fileout then
      fileout = "/tmp/output.pcap"
   end

   local c = config.new()
   config.app(c, "capture", pcap.PcapReader, filein)
   config.app(c, "conntrack_app", conntrack.ConntrackApp)
   config.app(c, "output_file", pcap.PcapWriter, fileout)

   config.link(c, "capture.output -> conntrack_app.input")
   config.link(c, "conntrack_app.output -> output_file.input")

   print(("Results written at: %s"):format(fileout))

   app.configure(c)
   app.main({duration=1})
end

run(main.parameters)
