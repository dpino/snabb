module(..., package.seeall)

local app = require("core.app")
local config = require("core.config")
local pcap = require("apps.pcap.pcap")
local link = require("core.link")
local packet = require("core.packet")
local bit = require("bit")

local Conntrack = require("lib.conntrack.conntrack")

ConntrackApp = {}

function ConntrackApp:new(arg)
   self.conntrack = Conntrack.new()
   return setmetatable({}, { __index = ConntrackApp })
end

function ConntrackApp:report()
   local conntrack = self.conntrack
   print("ConntrackApp:report")
   print("Total connections: "..self.conntrack:n_connections())
   print("Total packets: "..self.conntrack:n_packets())
end

function ConntrackApp:push()
   local i = assert(self.input.input, "input port not found")
   local o = assert(self.output.output, "output port not found")

   while not link.empty(i) and not link.full(o) do
      local packet = link.receive(i)
      if self.conntrack:has_connection(packet) then
         -- Do something
      end
      link.transmit(o, packet)
   end
end
