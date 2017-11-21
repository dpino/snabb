module(..., package.seeall)

local bit = require("bit")
local ipv4 = require("lib.protocol.ipv4")
local pcap = require("apps.pcap.pcap")

local band, lshift, tobit = bit.band, bit.lshift, bit.tobit

-- Converts a CIDR address such as 10.0.0.0/8 to {ip, cidr}, where
-- ip is a network-byte ordered address
-- cidr is an integer
local function parse_cidr (network_ip)
   assert(type(network_ip) == "string")
   if not network_ip:match("/") then network_ip = network_ip.."/32" end
   local ip, cidr = network_ip:match("(%d+.%d+.%d+.%d+)/(%d+)")
   ip = assert(ipv4:pton(ip), "Not valid network_ip IP address: "..ip)
   cidr = assert(tonumber(cidr), "Not valid CIDR value: "..cidr)
   return {ip=ip, cidr=cidr}
end

-- Checks whether IP address belong to network IP address.
local function matches_network (ip, network)
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
      network = parse_cidr(network)
   end
   assert(network.ip and tonumber(network.cidr))
   assert(network.cidr > 0 and network.cidr <= 32,
      "CIDR not it range [1, 32]: "..network.cidr)
   return band(touint32(ip), mask(network.cidr)) == tobit(touint32(network.ip))
end

local MartianFilter = {}

function MartianFilter.new ()
   local o = {
      -- See https://en.wikipedia.org/wiki/Martian_packet.
      filtered_networks = {
         parse_cidr"0.0.0.0/8",
         parse_cidr"10.0.0.0/8",
         parse_cidr"100.64.0.0/10",
         parse_cidr"127.0.0.0/8",
         parse_cidr"127.0.53.53",
         parse_cidr"169.254.0.0/16",
         parse_cidr"172.16.0.0/12",
         parse_cidr"192.0.0.0/24",
         parse_cidr"192.0.2.0/24",
         parse_cidr"192.168.0.0/16",
         parse_cidr"198.18.0.0/15",
         parse_cidr"198.51.100.0/24",
         parse_cidr"203.0.113.0/24",
         parse_cidr"224.0.0.0/4",
         parse_cidr"240.0.0.0/4",
         parse_cidr"255.255.255.255/32",
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
      if self:is_martian(ip_hdr:src()) or self:is_martian(ip_hdr:dst()) then
         packet.free(pkt)
      else
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
