-- Source -> NIC1 -> NIC2 -> Sink

-- Execute in "chur":
--    sudo ./snabb snsh source_nic_sink_3.lua

-- link report:
--            8,622,310 sent on nic2.tx -> sink.in1 (loss rate: 0%)
--           11,217,903 sent on repeater_ms.output -> nic1.rx (loss rate: 0%)
--                    1 sent on source_ms.out -> repeater_ms.input (loss rate: 0%)

local BasicNAT    = require("apps.basicnat.basicnat").BasicNAT
local Intel82599  = require("apps.intel.intel_app").Intel82599
local PcapReader  = require("apps.pcap.pcap").PcapReader
local basic_apps  = require("apps.basic.basic_apps")
local counter     = require("core.counter")
local ffi         = require("ffi")
local lib         = require("core.lib")

local C = ffi.C

local function bench(engine, params)
   local function format (str, t)
      for key, _ in str:gmatch("{([a-zA-Z_]+)}") do
         str = str:gsub("{"..key.."}", t[key])
      end
      return str
   end
   local function report (breaths, bytes, packets, runtime)
      local values = {
         breath_in_nanosecond = ("%.2f"):format(runtime / breaths * 1e6),
         breaths              = lib.comma_value(breaths),
         bytes                = bytes,
         million_packets      = ("%.1f"):format(packets / 1e6),
         packets_per_breath   = ("%.2f"):format(packets / breaths),
         rate_gbps            = ("%.2f"):format((bytes * 8 ) / 1e9 / runtime),
         rate_mpps            = ("%.3f"):format(packets / runtime / 1e6),
         runtime              = ("%.2f"):format(runtime),
      }
      print("\n"..format([[
Processed {million_packets} million packets in {runtime} seconds ({bytes} bytes; {rate_gbps} Gbps)
Made {breaths} breaths: {packets_per_breath} packets per breath; {breath_in_nanosecond} us per breath
Rate(Mpps): {rate_mpps}
      ]], values))
   end

   local start = C.get_monotonic_time()
   engine.main(params)
   local finish = C.get_monotonic_time()

   -- local input = link.stats(engine.app_table.nic2.output.tx)
   -- local input = link.stats(engine.app_table.basicnat.output.output)
   local input = link.stats(engine.app_table.nic1.input.rx)
   local breaths = tonumber(counter.read(engine.breaths))
   local bytes = input.txbytes
   local packets = input.txpackets
   local runtime = finish - start
   report(breaths, bytes, packets, runtime)
end

local function testInternalLoopbackFromPcapFile (pcidev, pcap_file)
   engine.configure(config.new())
   local c = config.new()

   config.app(c, 'basicnat', BasicNAT, {
      public_ip  = "198.76.29.7",
      private_ip = "10.33.96.5",
      network    = "10.33.96.0/24",
   })

   config.app(c, "pcap", PcapReader, pcap_file)
   config.app(c, 'repeater_ms', basic_apps.Repeater)
   config.app(c, 'sink', basic_apps.Sink)
   config.app(c, 'nic1', Intel82599, {
      pciaddr = pcidev,
      vmdq = true,
      macaddr = '52:54:00:00:00:01',
   })
   config.app(c, 'nic2', Intel82599, {
      pciaddr = pcidev,
      vmdq = true,
      macaddr = '52:54:00:00:00:02',
   })

   config.link(c, 'pcap.output        -> repeater_ms.input')
   config.link(c, 'repeater_ms.output -> basicnat.input')
   config.link(c, 'basicnat.output    -> nic1.rx')
   config.link(c, 'nic2.tx            -> sink.in1')

   engine.configure(c)

   print("-- testInternalLoopbackFromPcapFile")
   bench(engine, {duration=5, report={showlinks=true}})
end

-- echo-request from 10.33.96.5 to 198.76.29.4
local function echo_request ()
   return lib.hexundump ([[
      52:54:00:00:00:02 52:54:00:00:00:01 08 00 45 00
      00 54 15 b6 40 00 40 01 8f 66 0a 21 60 05 c6 4c
      1d 04 08 00 e8 f9 26 2c 00 02 13 63 c3 55 00 00
      00 00 48 4c 0b 00 00 00 00 00 10 11 12 13 14 15
      16 17 18 19 1a 1b 1c 1d 1e 1f 20 21 22 23 24 25
      26 27 28 29 2a 2b 2c 2d 2e 2f 30 31 32 33 34 35
      36 37
   ]], 98)
end

-- echo-reply from 198.76.29.4 to 10.33.96.5
local function echo_reply ()
   return lib.hexundump ([[
     52:54:00:00:00:02 52:54:00:00:00:01 08 00 45 00
     00 54 00 00 00 00 31 01 f4 1c c6 4c 1d 04 c6 4c
     1d 07 00 00 15 f3 26 1a 00 01 e9 62 c3 55 00 00
     00 00 53 66 05 00 00 00 00 00 10 11 12 13 14 15
     16 17 18 19 1a 1b 1c 1d 1e 1f 20 21 22 23 24 25
     26 27 28 29 2a 2b 2c 2d 2e 2f 30 31 32 33 34 35
     36 37
   ]], 98)
end

function testInternalLoopback (pcidev)
   local d1 = echo_request()
   local d2 = echo_reply()

   engine.configure(config.new())
   local c = config.new()

   config.app(c, 'basicnat', BasicNAT, {
      public_ip  = "198.76.29.7",
      private_ip = "10.33.96.5",
      network    = "10.33.96.0/24",
   })
   config.app(c, 'source_ms', basic_apps.Join)
   config.app(c, 'repeater_ms', basic_apps.Repeater)
   config.app(c, 'sink', basic_apps.Sink)
   config.app(c, 'nic1', Intel82599, {
      pciaddr = pcidev,
      vmdq = true,
      macaddr = '52:54:00:00:00:01',
   })
   config.app(c, 'nic2', Intel82599, {
      pciaddr = pcidev,
      vmdq = true,
      macaddr = '52:54:00:00:00:02',
   })

   config.link(c, 'source_ms.out      -> repeater_ms.input')
   config.link(c, 'repeater_ms.output -> basicnat.input')
   config.link(c, 'basicnat.output    -> nic1.rx')
   config.link(c, 'nic2.tx            -> sink.in1')

   engine.configure(c)
   link.transmit(engine.app_table.source_ms.output.out, packet.from_string(d1))
   link.transmit(engine.app_table.source_ms.output.out, packet.from_string(d2))

   print("-- testInternalLoopback")
   bench(engine, {duration=5, report={showlinks=true}})
end

function testTwoDifferentNICs(pcidevA, pcidevB)
   local d1 = echo_request()
   local d2 = echo_reply()

   engine.configure(config.new())
   local c = config.new()

   config.app(c, 'basicnat', BasicNAT, {
      public_ip  = "198.76.29.7",
      private_ip = "10.33.96.5",
      network    = "10.33.96.0/24",
   })
   config.app(c, 'source_ms', basic_apps.Join)
   config.app(c, 'repeater_ms', basic_apps.Repeater)
   config.app(c, 'sink', basic_apps.Sink)
   config.app(c, 'nic1', Intel82599, {
               pciaddr = pcidevA,
               macaddr = '52:54:00:00:00:01',
   })
   config.app(c, 'nic2', Intel82599, {
               pciaddr = pcidevB,
               macaddr = '52:54:00:00:00:02',
   })

   config.link(c, 'source_ms.out      -> repeater_ms.input')
   config.link(c, 'repeater_ms.output -> basicnat.input')
   config.link(c, 'basicnat.output    -> nic1.rx')
   config.link(c, 'nic2.tx            -> sink.in1')

   engine.configure(c)
   link.transmit(engine.app_table.source_ms.output.out, packet.from_string(d1))
   link.transmit(engine.app_table.source_ms.output.out, packet.from_string(d2))

   print("-- testTwoDifferentNICs")
   bench(engine, {duration=5, report={showlinks=true}})
end

-- Snabb Lab's Chur: Network carsd 05:00.0 and 05:00.1 are cabled together
-- local pcidevA, pcidevB = '0000:05:00.0', '0000:05:00.1'

-- Igalia's Snabb:   Network cards 04:00.0 and 05:00.0 are cabled together
local pcidevA, pcidevB = '0000:04:00.0', '0000:05:00.0'
local pcap_file = "apps/basicnat/pcap/ping-550.pcap"
-- testInternalLoopback(pcidevA)
testInternalLoopbackFromPcapFile(pcidevA, pcap_file)
-- testTwoDifferentNICs(pcidevA, pcidevB)
