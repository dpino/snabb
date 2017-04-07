module(..., package.seeall)

local PcapReader = require("apps.pcap.pcap").PcapReader
local Synth = require("apps.test.synth").Synth
local lib = require("core.lib")
local basic_apps = require("apps.basic.basic_apps")
local ethernet = require("lib.protocol.ethernet")

local ethernet_header_size = 14

function usage (code)
   print(require("program.l2fwd.README_inc"))
   main.exit(code)
end

function fatal (...)
   print(unpack{...})
   main.exit(1)
end

function parse_args (args)
   local opts = {
      driver = "pci",
      duration = 1,
   }
   local handlers = {}

   function handlers.h ()
      usage(1)
   end
   function handlers.D (num)
      opts.duration = assert(tonumber(num), "Duration must be a number")
   end
   function handlers.driver (arg)
      assert(arg == "pci" or arg == "virtio" or arg == "tap", "Not valid driver")
      opts.driver = arg
   end
   args = lib.dogetopt(args, handlers, "hD:", { help = "h" , duration = "D",
      driver = 1 })
   if #args ~= 2 then usage(1) end
   return opts, unpack(args)
end

local function config_nic (c, app_name, val, driver)
   if driver == "pci" then
      local Intel82599 = require("apps.intel.intel_app").Intel82599
      config.app(c, app_name, Intel82599, {
         pciaddr = val,
      })
   elseif driver == "tap" then
      local Tap = require("apps.tap.tap").Tap
      config.app(c, app_name, Tap, val)
   elseif driver == "virtio" then
      local Virtio = require("apps.virtio_net.virtio_net").VirtoNet
      config.app(c, app_name, VirtioNet, {
         pciaddr = val,
      })
   end
end

-- Swaps ethernet source and destination addresses of incoming packets and
-- forwards them.
L2Fwd = {}

function L2Fwd.new ()
   return setmetatable({}, { __index = L2Fwd })
end

function L2Fwd:push ()
   local i, o = assert(self.input.input), assert(self.output.output)

   while not link.empty(i) do
      local p = link.receive(i)
      local ether_hdr = ethernet:new_from_mem(p.data, ethernet_header_size)
      ether_hdr:swap()
      link.transmit(o, p)
   end
end

-- Forwards packets that only match ethernet source and destination addresses.
Filter = {}

function Filter:new (args)
   local o = {
      eth_src = assert(args.eth_src),
      eth_dst = assert(args.eth_dst),
      count = 0,
   }
   return setmetatable(o, { __index = Filter })
end

function Filter:push ()
   local i, o = assert(self.input.input), assert(self.output.output)

   while not link.empty(i) do
      local p = link.receive(i)
      local eth_hdr = ethernet:new_from_mem(p.data, ethernet_header_size)
      if eth_hdr:ntop(eth_hdr:dst()) == self.eth_dst and
            eth_hdr:ntop(eth_hdr:src()) == self.eth_src then
         link.transmit(o, p)
      else
         packet.free(p)
      end
   end
end

function run (args)
   local opts, pci0, pci1 = parse_args(args)

   local c = config.new()

   local sizes = {64}
   local eth_src = "02:00:00:00:00:01"
   local eth_dst = "02:00:00:00:00:02"

   local input, output = "rx", "tx"
   if opts.driver == "tap" then
      input, output = "input", "output"
   end

   config.app(c, "source", Synth, {sizes = sizes, src = eth_src, dst = eth_dst})
   config_nic(c, "nic0", pci0, opts.driver)
   config_nic(c, "nic1", pci1, opts.driver)
   config.app(c, "l2fwd", L2Fwd)
   config.app(c, "filter", Filter, {
      eth_src = eth_dst,
      eth_dst = eth_src,
   })
   config.app(c, "sink", basic_apps.Sink)

   config.link(c, "source.tx -> nic0."..input)
   config.link(c, "nic1."..output.." -> l2fwd.input")
   config.link(c, "l2fwd.output -> nic1."..input)
   config.link(c, "nic0."..output.." -> filter.input")
   config.link(c, "filter.output -> sink.input")

   engine.configure(c)
   engine.main({duration = opts.duration, report = { showlinks = true }})
end
