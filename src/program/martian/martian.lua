module(..., package.seeall)

local bit = require("bit")
local ipv4 = require("lib.protocol.ipv4")
local pcap = require("apps.pcap.pcap")

local lshift, band = bit.lshift, bit.band

-- Checks whether src IP address belong to dst network IP address.
function matches_network(src, dst)
   -- IP address in network-byte order, gets transformed to host-byte order uint32.
   local function touint32 (ip)
      return ip[0] * 2^24 + ip[1] * 2^16 + ip[2] * 2^8 + ip[3]
   end
   if not dst:match("/") then
      dst = dst.."/32"
   end
   local network_ip, cidr = dst:match("(%d+.%d+.%d+.%d+)/(%d+)")
   cidr = tonumber(cidr)
   assert(cidr > 0 and cidr <= 32, "Not valid cidr: "..cidr)
   network_ip = assert(ipv4:pton(network_ip),
      "Not valid network IP address: "..network_ip)
   src = assert(ipv4:pton(src), "Not valid IP address: "..src)
   local mask = lshift(2^(cidr+1)-1, 32-cidr)
   return band(touint32(src), mask) == touint32(network_ip)
end

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

function selftest ()
   print("selftest")
   assert(matches_network("10.0.0.1", "10.0.0.0/8"))
   assert(not matches_network("10.0.0.1", "10.0.0.0/32"))
   assert(not matches_network("10.0.0.1", "192.168.16.0/8"))
end
