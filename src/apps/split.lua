#!/usr/bin/env lua

local content = [=[
Lorem ipsum dolor sit amet, consectetur adipisicing elit,
sed do eiusmod tempor incididunt ut labore et dolore magna 
aliqua. Ut enim ad minim veniam, quis nostrud exercitation 
ullamco laboris nisi ut aliquip ex ea commodo consequat.
]=]

local function split(str, sep)
   local result = {}
   local regex = string.format("([^%s]+)", sep)
   for line,_ in str:gmatch(regex) do
      table.insert(result, line)
   end
   return result
end

local lines = split(content, "\n")
for _,line in ipairs(lines) do
   print(line)
end
