-- Use of this source code is governed by the Apache 2.0 license; see COPYING.

module(..., package.seeall)

local engine    = require("core.app")
local timer     = require("core.timer")
local lib       = require("core.lib")
local pci       = require("lib.hardware.pci")

local function is_device_suitable (pcidev, patterns)
   if not pcidev.usable or not pcidev.driver:match('intel') then
      return false
   end
   if #patterns == 0 then
      return true
   end
   for _, pattern in ipairs(patterns) do
      if pci.qualified(pcidev.pciaddress):gmatch(pattern)() then
         return true
      end
   end
end

local function loadgen (name)
   local path = name:match("intel_mp") and "apps.intel_mp.loadgen"
                                       or  "apps.intel.loadgen"
   return require(path).LoadGen
end

local function driver (path)
   return require(path).driver
end

function run_loadgen (c, patterns, opts)
   assert(type(opts) == "table")
   local use_loadgen = opts.loop == nil or opts.loop
   local nics = 0
   pci.scan_devices()
   for _,device in ipairs(pci.devices) do
      if is_device_suitable(device, patterns) then
         nics = nics + 1
         local name = "nic"..nics
         local pciaddr = device.pciaddress
         local info = pci.device_info(pciaddr)
         if use_loadgen then
            config.app(c, name, loadgen(info.driver), pciaddr)
         else
            config.app(c, name, driver(info.driver), {pciaddr = pciaddr})
         end
         config.link(c, "source."..tostring(nics).."->"..name..".input")
      end
   end
   assert(nics > 0, "<PCI> matches no suitable devices.")
   engine.busywait = true
   engine.configure(c)

   local report = {}
   if use_loadgen then
      local fn = function ()
         print("Transmissions (last 1 sec):")
         engine.report_apps()
      end
      local t = timer.new("report", fn, 1e9, 'repeating')
      timer.activate(t)
   else
      report = {showlinks = true}
   end

   if opts.duration then engine.main({duration=opts.duration, report=report})
   else             engine.main() end
end

local function show_usage(exit_code)
   print(require("program.packetblaster.README_inc"))
   main.exit(exit_code)
end

function run(args)
   if #args == 0 then show_usage(1) end
   local command = string.gsub(table.remove(args, 1), "-", "_")
   local modname = ("program.packetblaster.%s.%s"):format(command, command)
   if not lib.have_module(modname) then
      show_usage(1)
   end
   require(modname).run(args)
end
