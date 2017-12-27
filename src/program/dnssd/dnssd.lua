module(..., package.seeall)

local DNS = require("program.dnssd.lib.mdns").DNS
local MDNS = require("program.dnssd.lib.mdns").MDNS
local RawSocket = require("apps.socket.raw").RawSocket
local basic_apps = require("apps.basic.basic_apps")
local ffi = require("ffi")
local lib = require("core.lib")

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

DNSSD = {}

function DNSSD.new (args)
   local o = {
      interval = 2, -- Delay between broadcast messages.
   }
   return setmetatable(o, {__index = DNSSD})
end

-- Generate a new broadcast mDNS packet every interval seconds.
--[[
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
--]]

function DNSSD:push ()
   local input = assert(self.input.input)

   while not link.empty(input) do
      local pkt = link.receive(input)
      if MDNS.is_mdns(pkt) then
         print("is_mdns")
         self:log(pkt)
      end
      packet.free(pkt)
   end
end

function DNSSD:log (pkt)
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
   args = parse_args(args)
   local iface = assert(args[1])

   print(("Capturing packets from interface '%s'"):format(iface))

   local c = config.new()
   config.app(c, "iface", RawSocket, iface)
   config.app(c, "dnssd", DNSSD)
   -- config.link(c, "dnssd.output -> iface.rx")
   config.link(c, "iface.tx -> dnssd.input")

   engine.configure(c)
   engine.main({report = {showapps = true, showlinks = true}})
end
