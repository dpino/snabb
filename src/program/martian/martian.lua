module(..., package.seeall)

local bit = require("bit")
local ipv4 = require("lib.protocol.ipv4")
local pcap = require("apps.pcap.pcap")

local band, lshift, tobit = bit.band, bit.lshift, bit.tobit

-- Checks whether IP address belong to network IP address.
function matches_network(ip, network)
   -- IP address in network-byte order, gets transformed to host-byte order uint32.
   local function touint32 (ip)
      return ip[0] * 2^24 + ip[1] * 2^16 + ip[2] * 2^8 + ip[3]
   end
   local function mask (cidr)
      return lshift(2^(cidr+1)-1, 32-cidr)
   end
   if type(ip) == "string" then
      ip = assert(ipv4:pton(ip), "Not valid IP address: "..ip)
   end
   if type(network) == "string" then
      if not network:match("/") then network = network.."/32" end
      local ip, cidr = network:match("(%d+.%d+.%d+.%d+)/(%d+)")
      ip = assert(ipv4:pton(ip), "Not valid network IP address: "..ip)
      cidr = assert(tonumber(cidr), "Not valid CIDR value: "..cidr)
      network = {ip=ip, cidr=cidr}
   else
      assert(network.ip and tonumber(network.cidr))
   end
   assert(network.cidr > 0 and network.cidr <= 32,
      "CIDR not it range [1, 32]: "..network.cidr)
   return band(touint32(ip), mask(network.cidr)) == tobit(touint32(network.ip))
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
      local ip = ip_hdr:src()
      if not self:is_martian(ip) then
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
   assert(matches_network("192.168.0.0", "192.168.0.0/16"))
   print("ok")
end
