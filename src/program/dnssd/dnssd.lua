module(..., package.seeall)

local RawSocket = require("apps.socket.raw").RawSocket
local basic_apps = require("apps.basic.basic_apps")
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
