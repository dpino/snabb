module(..., package.seeall)

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
   local iface = parse_args(args)

   print("dnssd")
end

function selftest()
   print("selftest")
   print("ok")
end
