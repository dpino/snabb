module(..., package.seeall)

local DNS = require("program.dnssd.lib.mdns").DNS
local MDNS = require("program.dnssd.lib.mdns").MDNS
local RawSocket = require("apps.socket.raw").RawSocket
local basic_apps = require("apps.basic.basic_apps")
local ffi = require("ffi")
local lib = require("core.lib")
local pcap = require("apps.pcap.pcap")

local long_opts = {
   help = "h",
   pcap = "p",
   interface = "i",
}

local function usage(exit_code)
   print(require("program.dnssd.README_inc"))
   main.exit(exit_code)
end

function parse_args (args)
   local function fexists (filename)
      local fd = io.open(filename, "r")
      if fd then
         fd:close()
         return true
      end
      return false
   end
   local opts = {}
   local handlers = {}
   function handlers.h (arg)
      usage(0)
   end
   function handlers.p (arg)
      opts.pcap = arg
   end
   function handlers.i (arg)
      opts.interface = arg
   end
   args = lib.dogetopt(args, handlers, "hp:i:", long_opts)
   if opts.pcap or opts.interface then
      if #args ~= 0 then usage(1) end
   else
      if #args ~= 1 then usage(1) end
      local filename = args[1]
      if fexists(filename) then
         opts.pcap = filename
      else
         opts.interface = filename
      end
   end
   return opts, args
end

DNSSD = {}

function DNSSD.new (args)
   local o = {
      interval = 2, -- Delay between broadcast messages.
   }
   return setmetatable(o, {__index = DNSSD})
end

local pkt = packet.from_string(lib.hexundump([[
   01:00:5e:00:00:fb c8:5b:76:ca:30:44 08 00 45 00
   00 4a f2 f4 40 00 ff 11 e6 d3 c0 a8 00 36 e0 00
   00 fb 14 e9 14 e9 00 36 a2 21 00 00 00 00 00 01
   00 00 00 00 00 00 09 5f 73 65 72 76 69 63 65 73
   07 5f 64 6e 73 2d 73 64 04 5f 75 64 70 05 6c 6f
   63 61 6c 00 00 0c 00 01
]], 88))

-- Generate a new broadcast mDNS packet every interval seconds.
function DNSSD:pull ()
   local output = assert(self.output.output)

   while not link.full(output) do
      local now = os.time()
      if now > self.threshold then
         self.threshold = now + self.interval
         -- Send packet.
         local pkt = MDNS.query()
         link.transmit(output, pkt)
      end
   end
end

function DNSSD:push ()
   local input = assert(self.input.input)

   while not link.empty(input) do
      local pkt = link.receive(input)
      if MDNS.is_mdns(pkt) then
         self:log(pkt)
      end
      packet.free(pkt)
   end
end

function DNSSD:log (pkt)
   if not (MDNS.is_mdns(pkt) and MDNS.is_response(pkt)) then return end
   local response = MDNS.parse_response(pkt)
   local answer_rrs = response.answer_rrs
   if #answer_rrs > 0 then
      for _, rr in ipairs(answer_rrs) do
         DNS.print(rr)
      end
   end
   local additional_rrs = response.additional_rrs
   if #additional_rrs > 0 then
      for _, rr in ipairs(additional_rrs) do
         DNS.print(rr)
      end
   end
end

function run(args)
   local opts, args = parse_args(args)

   local duration
   local c = config.new()
   config.app(c, "dnssd", DNSSD)
   -- config.link(c, "dnssd.output -> iface.rx")
   if opts.pcap then
      print("Reading from file: "..opts.pcap)
      config.app(c, "pcap", pcap.PcapReader, opts.pcap)
      config.link(c, "pcap.output-> dnssd.input")
      duration = 3
   elseif opts.interface then
      local iface = opts.interface
      print(("Capturing packets from interface '%s'"):format(iface))
      config.app(c, "iface", RawSocket, iface)
      config.link(c, "iface.tx -> dnssd.input")
   else
      error("Unreachable")
   end
   engine.configure(c)
   engine.main({duration = duration, report = {showapps = true, showlinks = true}})
end
