-- Use of this source code is governed by the Apache 2.0 license; see COPYING.

module(..., package.seeall)

local usage = require("program.snabbmark.README_inc")

local basic_apps = require("apps.basic.basic_apps")
local pci           = require("lib.hardware.pci")
local ethernet      = require("lib.protocol.ethernet")
local lib = require("core.lib")
local ffi = require("ffi")
local C = ffi.C

function run (args)
   local command = table.remove(args, 1)
   if command == 'basic1' and #args == 1 then
      basic1(unpack(args))
   elseif command == 'nfvconfig' and #args == 3 then
      nfvconfig(unpack(args))
   elseif command == 'solarflare' and #args >= 2 and #args <= 3 then
      solarflare(unpack(args))
   elseif command == 'intel1g' and #args >= 2 and #args <= 3 then
      intel1g(unpack(args))
   elseif command == 'intel10g' and #args >= 2 and #args <= 3 then
      intel10g(unpack(args))
   elseif command == 'rawsocket' and #args ~= 3 then
      rawsocket(unpack(args))
   elseif command == 'xdpsocket' and #args ~= 3 then
      xdpsocket(unpack(args))
   elseif command == 'esp' and #args >= 2 then
      esp(unpack(args))
   elseif command == 'hash' and #args <= 1 then
      hash(unpack(args))
   elseif command == 'ctable' and #args == 0 then
      ctable(unpack(args))
   else
      print(usage) 
      main.exit(1)
   end
end

function gbits (bps)
   return (bps * 8) / (1024^3)
end

function basic1 (npackets)
   npackets = tonumber(npackets) or error("Invalid number of packets: " .. npackets)
   local c = config.new()
   -- Simple topology:
   --               .------.
   -- Source ---> Tee      Sink
   --               `------'
   -- Source generates packets, Tee duplicates them, Sink receives
   -- both duplicates.
   config.app(c, "Source", basic_apps.Source)
   config.app(c, "Tee", basic_apps.Tee)
   config.app(c, "Sink", basic_apps.Sink)
   config.link(c, "Source.tx -> Tee.rx")
   config.link(c, "Tee.tx1 -> Sink.rx1")
   config.link(c, "Tee.tx2 -> Sink.rx2")
   engine.configure(c)
   local start = C.get_monotonic_time()
   timer.activate(timer.new("null", function () end, 1e6, 'repeating'))
   while link.stats(engine.app_table.Source.output.tx).txpackets < npackets do
      engine.main({duration = 0.01, no_report = true})
   end
   local finish = C.get_monotonic_time()
   local runtime = finish - start
   local packets = link.stats(engine.app_table.Source.output.tx).txpackets
   engine.report()
   print()
   print(("Processed %.1f million packets in %.2f seconds (rate: %.1f Mpps)."):format(packets / 1e6, runtime, packets / runtime / 1e6))
end

function nfvconfig (confpath_x, confpath_y, nloads)
   local nfvconfig = require("program.snabbnfv.nfvconfig")
   nloads = tonumber(nloads)
      or error("Invalid number of iterations: " .. nloads)

   local pciaddr = lib.getenv("SNABB_PCI0")
   if not pciaddr then
      print("SNABB_PCI0 not set.")
      os.exit(engine.test_skipped_code)
   end

   local load_times, apply_times = {}, {}

   for i=1, nloads do
      -- Load and apply confpath_x.
      engine.configure(nfvconfig.load(confpath_x, pciaddr, "/dev/null"))

      -- Measure loading y.
      local start_load = C.get_monotonic_time()
      local c = nfvconfig.load(confpath_y, pciaddr, "/dev/null")
      local end_load = C.get_monotonic_time()

      -- Measure apply x -> y.
      local start_apply = C.get_monotonic_time()
      engine.configure(c)
      local end_apply = C.get_monotonic_time()

      -- Push results.
      table.insert(load_times, end_load - start_load)
      table.insert(apply_times, end_apply - start_apply)
   end

   engine.report()
   print()

   -- Print results.
   local load_mean, load_max = sumf(unpack(load_times))/#load_times, math.max(unpack(load_times))
   print("load_mean:", ("%.4fs"):format(load_mean))
   print("load_max:", ("%.4fs"):format(load_max))

   local apply_mean, apply_max = sumf(unpack(apply_times))/#apply_times, math.max(unpack(apply_times))
   print("apply_mean:", ("%.4fs"):format(apply_mean))
   print("apply_max:", ("%.4fs"):format(apply_max))

   -- Overall score is load_mean+apply_mean per second.
   print("score: ", ("%.2f"):format(1/(apply_mean + load_mean)))
end

function sumf(a, ...) return a and a + sumf(...) or 0 end

Source = {}

function Source:new(size)
   return setmetatable({}, {__index=Source})
end

function Source:pull()
   for _, o in ipairs(self.output) do
      for i = 1, engine.pull_npackets do
         local p = packet.allocate()
         ffi.copy(p.data, self.to_mac_address, 6)
         ffi.copy(p.data + 6, self.from_mac_address, 6)
         p.length = self.size
         link.transmit(o, p)
      end
   end
end

function Source:set_packet_addresses(from_mac_address, to_mac_address)
   self.from_mac_address, self.to_mac_address = from_mac_address, to_mac_address
   print(string.format("Sending from %02x:%02x:%02x:%02x:%02x:%02x to %02x:%02x:%02x:%02x:%02x:%02x",
                       self.from_mac_address[0],
                       self.from_mac_address[1],
                       self.from_mac_address[2],
                       self.from_mac_address[3],
                       self.from_mac_address[4],
                       self.from_mac_address[5],
                       self.to_mac_address[0],
                       self.to_mac_address[1],
                       self.to_mac_address[2],
                       self.to_mac_address[3],
                       self.to_mac_address[4],
                       self.to_mac_address[5]))
end

function Source:set_packet_size(size)
   self.size = size
end

function solarflare (npackets, packet_size, timeout)
   npackets = tonumber(npackets) or error("Invalid number of packets: " .. npackets)
   packet_size = tonumber(packet_size) or error("Invalid packet size: " .. packet_size)
   if timeout then
      timeout = tonumber(timeout) or error("Invalid timeout: " .. timeout)
   end

   local function load_driver ()
      return require("apps.solarflare.solarflare").SolarFlareNic
   end

   local status, SolarFlareNic = pcall(load_driver)
   if not status then
      print(SolarFlareNic)
      os.exit(engine.test_skipped_code)
   end

   local pciaddr0 = lib.getenv("SNABB_PCI_SOLARFLARE0") or lib.getenv("SNABB_PCI0")
   local pciaddr1 = lib.getenv("SNABB_PCI_SOLARFLARE1") or lib.getenv("SNABB_PCI1")
   local send_device = pciaddr0 and pci.device_info(pciaddr0)
   local receive_device = pciaddr1 and pci.device_info(pciaddr1)
   if not send_device
      or send_device.driver ~= 'apps.solarflare.solarflare'
      or not receive_device
      or receive_device.driver ~= 'apps.solarflare.solarflare'
   then
      print("SNABB_PCI_SOLARFLARE[0|1]/SNABB_PCI[0|1] not set or not suitable.")
      os.exit(engine.test_skipped_code)
   end

   print(string.format("Sending through %s (%s), receiving through %s (%s)",
                       send_device.interface, send_device.pciaddress,
                       receive_device.interface, receive_device.pciaddress))

   local c = config.new()

   -- Topology:
   -- Source -> Solarflare NIC#1 => Solarflare NIC#2 -> Sink

   config.app(c, "source", Source)
   config.app(c, send_device.interface, SolarFlareNic, {ifname=send_device.interface, mac_address = ethernet:pton("02:00:00:00:00:01")})
   config.app(c, receive_device.interface, SolarFlareNic, {ifname=receive_device.interface, mac_address = ethernet:pton("02:00:00:00:00:02")})
   config.app(c, "sink", basic_apps.Sink)

   config.link(c, "source.tx -> " .. send_device.interface .. ".rx")
   config.link(c, receive_device.interface .. ".tx -> sink.rx")

   engine.configure(c)

   engine.app_table.source:set_packet_addresses(engine.app_table[send_device.interface].mac_address,
                                                engine.app_table[receive_device.interface].mac_address)
   engine.app_table.source:set_packet_size(packet_size)

   engine.Hz = false

   local start = C.get_monotonic_time()
   timer.activate(timer.new("null", function () end, 1e6, 'repeating'))
   local n = 0
   local n_max
   if timeout then
      n_max = timeout * 100
   end
   while link.stats(engine.app_table.source.output.tx).txpackets < npackets
      and (not timeout or n < n_max)
   do
      engine.main({duration = 0.01, no_report = true})
      n = n + 1
   end
   local finish = C.get_monotonic_time()
   local runtime = finish - start
   local packets = link.stats(engine.app_table.source.output.tx).txpackets
   engine.report()
   engine.app_table[send_device.interface]:report()
   engine.app_table[receive_device.interface]:report()
   print()
   print(("Processed %.1f million packets in %.2f seconds (rate: %.1f Mpps, %.2f Gbit/s)."):format(packets / 1e6,
                                                                                                   runtime, packets / runtime / 1e6,
                                                                                                   gbits(packets * packet_size / runtime)))
   if link.stats(engine.app_table.source.output.tx).txpackets < npackets then
      print("Packets lost. Test failed!")
      main.exit(1)
   end
end

function intel1g (npackets, packet_size, timeout)
   npackets = tonumber(npackets) or error("Invalid number of packets: " .. npackets)
   packet_size = tonumber(packet_size) or error("Invalid packet size: " .. packet_size)
   if timeout then
      timeout = tonumber(timeout) or error("Invalid timeout: " .. timeout)
   end

   local function load_driver ()
      return require("apps.intel.intel1g").Intel1g
   end

   local status, Intel1gNic = pcall(load_driver)
   if not status then
      print(Intel1gNic)
      os.exit(engine.test_skipped_code)
   end

   local pciaddr0 = lib.getenv("SNABB_PCI0")
   local pciaddr1 = lib.getenv("SNABB_PCI1")
   local send_device = pciaddr0 and pci.device_info(pciaddr0)
   local receive_device = pciaddr1 and pci.device_info(pciaddr1)
print("send_device= ", send_device, "  receive_device= ", receive_device)
   if not send_device
      or send_device.driver ~= 'apps.intel.intel1g'
      or not receive_device
      or receive_device.driver ~= 'apps.intel.intel1g'
   then
      print("SNABB_PCI[0|1] not set, or not suitable Intel i210/i350 NIC.")
      os.exit(engine.test_skipped_code)
   end

send_device.interface= "tx1GE"
receive_device.interface= "rx1GE"

   print(string.format("Sending through %s (%s), receiving through %s (%s)",
                       send_device.interface, send_device.pciaddress,
                       receive_device.interface, receive_device.pciaddress))

   local c = config.new()

   -- Topology:
   -- Source -> Intel1g NIC#1 => Intel1g NIC#2 -> Sink

   config.app(c, "source", Source)
   --config.app(c, send_device.interface, Intel1gNic, {ifname=send_device.interface, mac_address = ethernet:pton("02:00:00:00:00:01")})
   --config.app(c, receive_device.interface, Intel1gNic, {ifname=receive_device.interface, mac_address = ethernet:pton("02:00:00:00:00:02")})
   config.app(c, send_device.interface, Intel1gNic, {pciaddr=pciaddr0})
   config.app(c, receive_device.interface, Intel1gNic, {pciaddr=pciaddr1, rxburst=512})
   config.app(c, "sink", basic_apps.Sink)

   config.link(c, "source.tx -> " .. send_device.interface .. ".input")
   config.link(c, receive_device.interface .. ".output -> sink.rx")

   engine.configure(c)

   --engine.app_table.source:set_packet_addresses(engine.app_table[send_device.interface].mac_address,
   --                                             engine.app_table[receive_device.interface].mac_address)
   engine.app_table.source:set_packet_addresses(ethernet:pton("02:00:00:00:00:01"),
                                                ethernet:pton("02:00:00:00:00:02"))
   engine.app_table.source:set_packet_size(packet_size)

   engine.Hz = false

   local start = C.get_monotonic_time()
   timer.activate(timer.new("null", function () end, 1e6, 'repeating'))
   local n = 0
   local n_max
   if timeout then
      n_max = timeout * 100
   end
   while link.stats(engine.app_table.source.output.tx).txpackets < npackets
      and (not timeout or n < n_max)
   do
      engine.main({duration = 0.01, no_report = true})
      n = n + 1
   end
   local finish = C.get_monotonic_time()
   local runtime = finish - start
   local txpackets = link.stats(engine.app_table.source.output.tx).txpackets
   local rxpackets = link.stats(engine.app_table.sink.input.rx).rxpackets
   engine.report()
   engine.app_table[send_device.interface]:report()
   engine.app_table[receive_device.interface]:report()
   print()
   print(("Processed %.1f million packets in %.2f seconds (rate: %.1f Mpps, %.2f Gbit/s, %.2f %% packet loss)."):format(
    txpackets / 1e6, runtime, 
    txpackets / runtime / 1e6,
    ((txpackets * packet_size * 8) / runtime) / (1024*1024*1024),
    (txpackets - rxpackets) *100 / txpackets
   ))
   if link.stats(engine.app_table.source.output.tx).txpackets < npackets then
      print("Packets lost. Test failed!")
      main.exit(1)
   end
end

local function w (...) io.stdout:write(...) end
local function wln (...) w(...) w("\n") end
local function skip (...)
   wln(...)
   os.exit(engine.test_skipped_code)
end
local function device_info (pciaddr)
   pciaddr = assert(tostring(pciaddr), "Invalid pciaddr: "..pciaddr)
   local device = pciaddr and pci.device_info(pciaddr)
   if not (device or device.driver == 'apps.intel_mp.intel_mp') then
      print("SNABB_PCI[0|1] not set, or not suitable Intel 10G.")
      os.exit(engine.test_skipped_code)
   end
   return device
end

function intel10g (npackets, packet_size, timeout)
   local function load_driver ()
      return require("apps.intel_mp.intel_mp").Intel
   end
   local function stats (runtime, txpackets, rxpackets, packet_size)
      local processed = txpackets / 1e6
      local rate = txpackets / runtime / 1e6
      local mpps = ((txpackets * packet_size * 8) / runtime) / (1024*1024*1024)
      print()
      print(("Processed %.1f million packets in %.2f seconds "..
             "(rate: %.1f Mpps, %.2f Gbit/s)"):format(processed,
                                                      runtime,
                                                      rate,
                                                      mpps))
   end

   local pciaddr0 = lib.getenv("SNABB_PCI0")
   if not pciaddr0 then
      skip("SNABB_PCI0 not set")
   end
   local pciaddr1 = lib.getenv("SNABB_PCI1")
   if not pciaddr1 then
      skip("SNABB_PCI1 not set")
   end
   local status, Intel10gNic = pcall(load_driver)
   if not status then
      skip("Could not find driver: "..Intel10gNic)
   end

   npackets = tonumber(npackets) or error("Invalid number of packets: " .. npackets)
   packet_size = tonumber(packet_size) or error("Invalid packet size: " .. packet_size)
   if timeout then
      timeout = tonumber(timeout) or error("Invalid timeout: " .. timeout)
   end

   local nic0 = device_info(pciaddr0)
   local nic1 = device_info(pciaddr1)

   nic0.interface = "nic0"
   nic1.interface = "nic1"

   w(("Sending through %s (%s); "):format(nic0.interface,
                                          nic0.pciaddress))
   wln(("Receiving through %s (%s)"):format(nic1.interface,
                                            nic1.pciaddress))

   -- Topology:
   -- Source -> Intel10g NIC#1 => Intel10g NIC#2 -> Sink

   -- Initialize apps.
   local c = config.new()
   config.app(c, "source", basic_apps.Source, packet_size)
   config.app(c, "tee", basic_apps.Tee)
   config.app(c, "sink", basic_apps.Sink)
   config.app(c, nic0.interface, Intel10gNic, {
      pciaddr = pciaddr0,
   })
   config.app(c, nic1.interface, Intel10gNic, {
      pciaddr = pciaddr1,
   })
   config.app(c, "sink", basic_apps.Sink)

   -- Set links.
   config.link(c, "source.tx -> tee.rx")
   config.link(c, "tee.tx -> "..nic0.interface.."."..nic0.rx)
   config.link(c, nic1.interface.."."..nic1.tx.." -> sink.rx")

   -- Set engine.
   engine.configure(c)
   engine.Hz = false

   local start = C.get_monotonic_time()
   timer.activate(timer.new("null", function () end, 1e6, 'repeating'))
   while link.stats(engine.app_table.source.output.tx).txpackets < npackets do
      engine.main({duration = 0.01, no_report = true})
   end
   local finish = C.get_monotonic_time()
   local runtime = finish - start
   local txpackets = link.stats(engine.app_table.source.output.tx).txpackets
   local rxpackets = link.stats(engine.app_table.sink.input.rx).rxpackets

   local packets = link.stats(engine.app_table.source.output.tx).txpackets
   engine.report()

   stats(runtime, txpackets, rxpackets, packet_size)

   if link.stats(engine.app_table.source.output.tx).txpackets < npackets then
      print("Packets lost. Test failed!")
      main.exit(1)
   end
end

local function socket (driver, npackets, packet_size, timeout)
   local ifname0 = lib.getenv("SNABB_PCI0")
   if not ifname0 then
      print("SNABB_PCI0 not set.")
      os.exit(engine.test_skipped_code)
   end
   local ifname1 = lib.getenv("SNABB_PCI1")
   if not ifname1 then
      print("SNABB_PCI1 not set.")
      os.exit(engine.test_skipped_code)
   end

   function stats (txpackets, rxpackets, runtime, packet_size)
      local total = txpackets / 1e6
      local mpps = txpackets / runtime / 1e6
      local gbps = ((txpackets * packet_size * 8) / runtime) / (1024*1024*1024)
      local loss = (txpackets - rxpackets) * 100 / txpackets
      print()
      print(("Processed %.1f million packets in %.2f seconds (rate: %.1f Mpps, %.2f Gbit/s, %.2f %% packet loss)."):format(
              total, runtime, mpps, gbps, loss))
   end

   print(("Packets: %d; Packet Size: %d; Timeout: %d"):format(npackets, packet_size, timeout))
   print(("Sending through %s, receiving through %s"):format(ifname0, ifname1))

   -- Topology:
   -- Source -> Socket NIC#1 => Socket NIC#2 -> Sink

   local pkt = packet.from_string(lib.hexundump([=[
      3c fd fe 9e 7f 71 ec b1 d7 98 3a c0 08 00 45 00
      00 2e 00 00 00 00 40 11 88 97 05 08 07 08 c8 14
      1e 04 10 92 10 92 00 1a 6d a3 34 33 1f 69 40 6b
      54 59 b6 14 2d 11 44 bf af d9 be aa
   ]=], 60))

   local c = config.new()
   config.app(c, "source", basic_apps.Source)
   config.app(c, "tee", basic_apps.Tee)
   config.app(c, ifname0, driver, ifname0)
   config.app(c, ifname1, driver, ifname1)
   config.app(c, "sink", basic_apps.Sink)

   --[[
   config.link(c, "source.tx -> tee.rx")
   config.link(c, "tee.tx -> "..ifname0..".rx")
   --]]

   config.link(c, "source.tx -> tee.rx")
   config.link(c, "tee.tx -> "..ifname0..".rx")
   config.link(c, ifname1..".tx -> sink.input")

   engine.configure(c)
   engine.app_table.source:set_packet(pkt)

   print("hi")
   engine.main({duration=0, report={showlinks=true}})

   --[=[
   -- Initialize apps.
   local c = config.new()

   config.app(c, "source", Source)
   config.app(c, "tee", basic_apps.Tee)
   config.app(c, ifname0, driver, ifname0)
   config.app(c, ifname1, driver, ifname1)
   config.app(c, "sink", basic_apps.Sink)

   -- Set links.
   config.link(c, "source.tx -> tee.rx")
   config.link(c, "tee.tx -> "..ifname0..".rx")
   config.link(c, ifname1..".tx -> sink.input")

   -- Set engine.
   engine.configure(c)
   local from, to = ethernet:pton("02:00:00:00:00:01"), ethernet:pton("02:00:00:00:00:02")
   engine.app_table.source:set_packet_addresses(from, to)
   engine.app_table.source:set_packet_size(packet_size)
   engine.Hz = false

   local start = C.get_monotonic_time()
   timer.activate(timer.new("null", function () end, 1e6, 'repeating'))
   local txpackets = 0
   local n, n_max = 0, timeout and timeout * 100
   while txpackets < npackets and n < n_max do
      txpackets = link.stats(engine.app_table.source.output.tx).txpackets
      engine.main({duration = 0.01, no_report = true})
      n = n + 1
   end

   local finish = C.get_monotonic_time()
   local runtime = finish - start
   local rxpackets = link.stats(engine.app_table.sink.input.input).rxpackets
   if rxpackets >= txpackets then
      rxpackets = txpackets
   end
   engine.report()

   stats(txpackets, rxpackets, runtime, packet_size)

   if txpackets < npackets then
      print(("Packets lost. Rx: %d. Lost: %d"):format(txpackets, npackets - txpackets))
      main.exit(1)
   end
   --]=]
end

function rawsocket (npackets, packet_size, timeout)
   local driver = require("apps.socket.raw").RawSocket
   npackets = tonumber(npackets) or 10e3
   packet_size = tonumber(packet_size) or 550
   timeout = tonumber(timeout) or 1000
   return socket(driver, npackets, packet_size, timeout)
end

function xdpsocket (npackets, packet_size, timeout)
   local driver = require("apps.socket.xdp.xdp").XDPSocket
   npackets = tonumber(npackets) or 10e3
   packet_size = tonumber(packet_size) or 550
   timeout = tonumber(timeout) or 1000
   return socket(driver, npackets, packet_size, timeout)
end

function esp (npackets, packet_size, mode, direction, profile)
   local esp = require("lib.ipsec.esp")
   local ethernet = require("lib.protocol.ethernet")
   local ipv6 = require("lib.protocol.ipv6")
   local datagram = require("lib.protocol.datagram")
   local profiler = profile and require("jit.p")

   npackets = assert(tonumber(npackets), "Invalid number of packets: " .. npackets)
   packet_size = assert(tonumber(packet_size), "Invalid packet size: " .. packet_size)
   local payload_size = packet_size - ethernet:sizeof() - ipv6:sizeof()
   local payload = ffi.new("uint8_t[?]", payload_size)
   local d = datagram:new(packet.allocate())
   local ip = ipv6:new({})
   ip:payload_length(payload_size)
   d:payload(payload, payload_size)
   d:push(ip)
   if not mode == "tunnel" then
      local eth = ethernet:new({type=0x86dd})
      d:push(eth)
   end
   local plain = d:packet()
   local conf = { spi = 0x0,
                  mode = "aes-gcm-128-12",
                  key = "00112233445566778899AABBCCDDEEFF",
                  salt = "00112233"}
   local enc, dec = esp.encrypt:new(conf), esp.decrypt:new(conf)
   local encap, decap
   if mode == "tunnel" then
      encap = function (p) return enc:encapsulate_tunnel(p, 41) end
      decap = function (p) return dec:decapsulate_tunnel(p) end
   else
      encap = function (p) return enc:encapsulate_transport6(p) end
      decap = function (p) return dec:decapsulate_transport6(p) end
   end
   if direction == "encapsulate" then
      if profile then profiler.start(profile) end
      local start = C.get_monotonic_time()
      for i = 1, npackets do
         packet.free(encap(packet.clone(plain)))
      end
      local finish = C.get_monotonic_time()
      if profile then profiler.stop() end
      local bps = (packet_size * npackets) / (finish - start)
      print(("Encapsulation (packet size = %d): %.2f Gbit/s")
            :format(packet_size, gbits(bps)))
   else
      local encapsulated = encap(packet.clone(plain))
      if profile then profiler.start(profile) end
      local start = C.get_monotonic_time()
      for i = 1, npackets do
         packet.free(decap(packet.clone(encapsulated)))
         dec.seq.no = 0
         dec.window[0] = 0
      end
      local finish = C.get_monotonic_time()
      if profile then profiler.stop() end
      local bps = (packet_size * npackets) / (finish - start)
      print(("Decapsulation (packet size = %d): %.2f Gbit/s")
            :format(packet_size, gbits(bps)))
   end
end

local pmu = require('lib.pmu')
local has_pmu_counters, err = pmu.is_available()
if not has_pmu_counters then
   io.stderr:write('No PMU available: '..err..'\n')
end

if has_pmu_counters then pmu.setup() end

local function measure(f, iterations)
   local set
   if has_pmu_counters then set = pmu.new_counter_set() end
   local start = C.get_time_ns()
   if has_pmu_counters then pmu.switch_to(set) end
   local res = f(iterations)
   if has_pmu_counters then pmu.switch_to(nil) end
   local stop = C.get_time_ns()
   local ns = tonumber(stop-start)
   local cycles = nil
   if has_pmu_counters then cycles = pmu.to_table(set).cycles end
   return cycles, ns, res
end

local function test_perf(f, iterations, what)
   require('jit').flush()
   io.write(tostring(what or f)..': ')
   io.flush()
   local cycles, ns, res = measure(f, iterations)
   if cycles then
      cycles = cycles/iterations
      io.write(('%.2f cycles, '):format(cycles))
   end
   ns = ns/iterations
   io.write(('%.2f ns per iteration (result: %s)\n'):format(
         ns, tostring(res)))
   return res
end

function hash (key_size)
   if key_size then
      key_size = assert(tonumber(key_size))
   else
      key_size = 4
   end
   local value_t = ffi.typeof("uint8_t[$]", key_size)
   local band = require('bit').band
   local fill = require('ffi').fill

   local function baseline_hash(ptr) return ptr[0] end
   local murmur = require('lib.hash.murmur').MurmurHash3_x86_32:new()
   local function murmur_hash(v)
      return murmur:hash(v, key_size, 0ULL).u32[0]      
   end
   local lib_siphash = require('lib.hash.siphash')
   local sip_hash_1_2_opts = { size=key_size, c=1, d=2 }
   local sip_hash_2_4_opts = { size=key_size, c=2, d=4 }

   local function test_scalar_hash(iterations, hash)
      local value = ffi.new(ffi.typeof('uint8_t[$]', key_size))
      local result
      for i=1,iterations do
	 fill(value, key_size, band(i, 255))
	 result = hash(value)
      end
      return result
   end

   local function test_parallel_hash(iterations, hash, width)
      local value = ffi.new('uint8_t[?]', key_size*width)
      local result = ffi.new('uint32_t[?]', width)
      for i=1,iterations,width do
	 fill(value, key_size*width, band(i+width-1, 255))
	 hash(value, result)
      end
      return result[width-1]
   end

   local function hash_tester(hash)
      return function(iterations)
         return test_scalar_hash(iterations, hash)
      end
   end

   local function sip_hash_tester(opts, width)
      local opts = lib.deepcopy(opts)
      opts.size = key_size
      if width > 1 then
         opts.width = width
         local hash = lib_siphash.make_multi_hash(opts)
	 return function(iterations)
	    return test_parallel_hash(iterations, hash, width)
	 end
      else
         return hash_tester(lib_siphash.make_hash(opts))
      end
   end

   test_perf(hash_tester(baseline_hash), 1e8, 'baseline')
   test_perf(hash_tester(murmur_hash), 1e8, 'murmur hash (32 bit)')
   for _, opts in ipairs({{c=1,d=2}, {c=2,d=4}}) do
      for _, width in ipairs({1,2,4,8}) do
         test_perf(sip_hash_tester(opts, width), 1e8,
                   string.format('sip hash c=%d,d=%d (x%d)',
                                 opts.c, opts.d, width))
      end
   end
end

function ctable ()
   local ctable = require('lib.ctable')
   local bnot = require('bit').bnot
   local ctab = ctable.new(
      { key_type = ffi.typeof('uint32_t[2]'),
        value_type = ffi.typeof('int32_t[5]') })
   local occupancy = 2e6
   ctab:resize(occupancy / 0.4 + 1)

   local function test_insertion(count)
      local k = ffi.new('uint32_t[2]');
      local v = ffi.new('int32_t[5]');
      for i = 1,count do
         k[0], k[1] = i, i
         for j=0,4 do v[j] = bnot(i) end
         ctab:add(k, v)
      end
   end

   local function test_lookup_ptr(count)
      local k = ffi.new('uint32_t[2]');
      local result = ctab.entry_type()
      for i = 1, count do
         k[0], k[1] = i, i
         result = ctab:lookup_ptr(k)
      end
      return result
   end

   local function test_lookup_and_copy(count)
      local k = ffi.new('uint32_t[2]');
      local result = ctab.entry_type()
      for i = 1, count do
         k[0], k[1] = i, i
         ctab:lookup_and_copy(k, result)
      end
      return result
   end

   test_perf(test_insertion, occupancy, 'insertion (40% occupancy)')
   test_perf(test_lookup_ptr, occupancy, 'lookup_ptr (40% occupancy)')
   test_perf(test_lookup_and_copy, occupancy, 'lookup_and_copy (40% occupancy)')

   local stride = 1
   repeat
      local streamer = ctab:make_lookup_streamer(stride)
      local function test_lookup_streamer(count)
         local result
         for i = 1, count, stride do
            local n = math.min(stride, count-i+1)
            for j = 0, n-1 do
               streamer.entries[j].key[0] = i + j
               streamer.entries[j].key[1] = i + j
            end
            streamer:stream()
            result = streamer.entries[n-1].value[0]
         end
         return result
      end
      -- Note that "result" is part of the value, not an index into
      -- the table, and so we expect the results to be different from
      -- ctab:lookup().
      test_perf(test_lookup_streamer, occupancy,
                'streaming lookup, stride='..stride)
      stride = stride * 2
   until stride > 256
end
