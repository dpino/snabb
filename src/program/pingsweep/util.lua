module(..., package.seeall)

local datagram = require("lib.protocol.datagram")
local ethernet = require("lib.protocol.ethernet")
local ffi = require("ffi")
local icmp = require("lib.protocol.icmp.header")
local ipv4 = require("lib.protocol.ipv4")

local ICMP_PROTO = 1

function iface_info (ifname)
   if not ifname_exists(ifname) then return end
   local output = execute("ip addr sh | grep -A 6 "..ifname)
   local ether = output:match("link/ether ([^%s]+)%s")
   local inet, cidr = output:match("inet ([^/]+)/([^%s]+)%s")
   return { ether = ether, inet = inet, cidr = cidr }
end

function ifname_exists (ifname)
   return execute("sudo ip link sh "..ifname, {exit_code = true}) == 0
end

function execute (command, opts)
   opts = opts or {}
   if opts.exit_code then
      command = command..' 1>/dev/null 2>/dev/null; echo $?'
   end
   local handle = io.popen(command)
   local ret = handle:read("*a")
   handle:close()
   return opts.exit_code and tonumber(ret) or ret
end

function build_icmp_echo_pkt (packet_size, ether_src, ipv4_src, ipv4_dst)
   local dgram = datagram:new(packet.allocate())

   local payload, payload_size = fillup_payload(packet_size)

   local eth_hdr = ethernet:new({
      src = ethernet:pton(ether_src),
      dst = ethernet:pton("ff:ff:ff:ff:ff:ff"),
      type = 0x0800,
   })
   local ipv4_hdr = ipv4:new({
      src = ipv4:pton(ipv4_src),
      dst = ipv4:pton(ipv4_dst), -- Mock address.
      protocol = ICMP_PROTO,
      ttl = 64,
   })
   ipv4_hdr:id(math.random(65335))
   ipv4_hdr:total_length(packet_size - ethernet:sizeof() - 8)
   ipv4_hdr:checksum()

   -- Echo request.
   local icmp_hdr = icmp:new(8, 0)
   icmp_hdr:checksum(payload, packet_size - (ethernet:sizeof() + ipv4:sizeof() + 8))

   dgram:payload(payload, payload_size - 4)
   dgram:push(icmp_hdr)
   dgram:push(ipv4_hdr)
   dgram:push(eth_hdr)

   return dgram:packet()
end

function fillup_payload (packet_size)
   local icmp_size = 8
   local payload_size = packet_size - ethernet:sizeof() - ipv4:sizeof() - icmp_size
   local payload = ffi.new("uint8_t[?]", payload_size)
   local start = 0x10
   for i=0,(payload_size - 4) - 1 do
      payload[i] = start
      start = start + 1
   end
   return payload, payload_size
end
