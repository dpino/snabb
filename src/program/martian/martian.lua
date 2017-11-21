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
   if type(src) == "string" then
      src = assert(ipv4:pton(src), "Not valid IP address: "..src)
   end
   local mask = lshift(2^(cidr+1)-1, 32-cidr)
   return band(touint32(src), mask) == touint32(network_ip)
end

local MartianFilter = {}

function MartianFilter.new ()
   local o = {
      -- See https://en.wikipedia.org/wiki/Martian_packet.
      filtered_networks = {
         "0.0.0.0/8",
         "10.0.0.0/8",
         "100.64.0.0/10",
         "127.0.0.0/8",
         "127.0.53.53/32",
         "169.254.0.0/16",
         "172.16.0.0/12",
         "192.0.0.0/24",
         "192.0.2.0/24",
         "192.168.0.0/16",
         "198.18.0.0/15",
         "198.51.100.0/24",
         "203.0.113.0/24",
         "224.0.0.0/4",
         "240.0.0.0/4",
         "255.255.255.255/32",
      }
   }
   return setmetatable(o, {__index=MartianFilter})
end

function MartianFilter:is_martian (ip)
   for _, each in ipairs(self.filtered_networks) do
      if matches_network(ip, each) then
         return true
      end 
   end
   return false
end

function MartianFilter:push ()
   local input, output = assert(self.input.input), assert(self.output.output)

   while not link.empty(input) do
      local pkt = link.receive(input)
      local ip_hdr = ipv4:new_from_mem(pkt.data + 14, 20)
      local ret = self:is_martian(ip_hdr:src())
      if not self:is_martian(ip_hdr:src()) then
         link.transmit(output, pkt)
      end
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
