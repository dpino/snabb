module(..., package.seeall)

local lib = require("core.lib")
local RawSocket = require("apps.socket.raw").RawSocket
local basic_apps = require("apps.basic.basic_apps")
local ethernet = require("lib.protocol.ethernet")
local ipv4 = require("lib.protocol.ipv4")
local udp = require("lib.protocol.udp")

local ethernet_header_size = 14
local ipv4_header_size = 20
local udp_header_size = 8

local long_opts = {
   help = "h",
}

local function usage(exit_code)
   print(require("program.dnssd.README_inc"))
   main.exit(exit_code)
end

function parse_args (args)
   local handlers = {}
   function handlers.h (arg)
      usage(0)
   end
   args = lib.dogetopt(args, handlers, "hl:", long_opts)
   if #args > 1 then usage(1) end
   return args
end

function run(args)
   args = parse_args(args)
   local iface = assert(args[1])

   print(("Capturing packets from interface '%s'"):format(iface))

   local c = config.new()
   config.app(c, "iface", RawSocket, iface)
   config.app(c, "sink", basic_apps.Sink)
   config.link(c, "iface.tx -> sink.input")

   engine.configure(c)
   engine.main({duration=1, report = {showapps = true, showlinks = true}})
end

function selftest()
   print("selftest")
   function parse_mdns_response (pkt)
      local ether_hdr = ethernet:new_from_mem(pkt.data, ethernet_header_size)
      local ipv4_hdr = ipv4:new_from_mem(pkt.data + ethernet_header_size, ipv4_header_size)
      local udp_hdr = udp:new_from_mem(pkt.data + ethernet_header_size + ipv4_header_size, udp_header_size)

      assert(ethernet:ntop(ether_hdr:dst()) == "01:00:5e:00:00:fb")
      assert(ipv4:ntop(ipv4_hdr:dst()) == "224.0.0.251")
      assert(udp_hdr:dst_port() == 5353)
   end

   -- MDNS response.
   local pkt = packet.from_string(lib.hexundump ([[
      01:00:5e:00:00:fb 54:60:09:47:6b:88 08 00 45 00
      01 80 00 00 40 00 ff 11 82 88 c0 a8 56 40 e0 00
      00 fb 14 e9 14 e9 01 6c d2 12 00 00 84 00 00 00
      00 01 00 00 00 03 0b 5f 67 6f 6f 67 6c 65 63 61
      73 74 04 5f 74 63 70 05 6c 6f 63 61 6c 00 00 0c
      00 01 00 00 00 78 00 2e 2b 43 68 72 6f 6d 65 63
      61 73 74 2d 38 34 38 64 61 35 39 64 38 63 62 36
      34 35 39 61 39 39 37 31 34 33 34 62 31 64 35 38
      38 62 61 65 c0 0c c0 2e 00 10 80 01 00 00 11 94
      00 b3 23 69 64 3d 38 34 38 64 61 35 39 64 38 63
      62 36 34 35 39 61 39 39 37 31 34 33 34 62 31 64
      35 38 38 62 61 65 23 63 64 3d 37 32 39 32 37 38
      45 30 32 35 46 43 46 44 34 44 43 44 43 37 46 42
      39 45 38 42 43 39 39 35 42 37 13 72 6d 3d 39 45
      41 37 31 43 38 33 43 43 45 46 37 39 32 37 05 76
      65 3d 30 35 0d 6d 64 3d 43 68 72 6f 6d 65 63 61
      73 74 12 69 63 3d 2f 73 65 74 75 70 2f 69 63 6f
      6e 2e 70 6e 67 09 66 6e 3d 4b 69 62 62 6c 65 07
      63 61 3d 34 31 30 31 04 73 74 3d 30 0f 62 73 3d
      46 41 38 46 43 41 39 33 42 35 43 34 04 6e 66 3d
      31 03 72 73 3d c0 2e 00 21 80 01 00 00 00 78 00
      2d 00 00 00 00 1f 49 24 38 34 38 64 61 35 39 64
      2d 38 63 62 36 2d 34 35 39 61 2d 39 39 37 31 2d
      34 33 34 62 31 64 35 38 38 62 61 65 c0 1d c1 2d
      00 01 80 01 00 00 00 78 00 04 c0 a8 56 40
   ]], 398))
   parse_mdns_response(pkt)

   print("ok")
end
