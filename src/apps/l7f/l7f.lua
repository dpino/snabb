module(..., package.seeall)

local ffi = require('ffi')
local C = ffi.C

local pcap = ffi.load("pcap")
local link = require("core.link")
local dpi = require("lib.dpi.dpi")

ffi.cdef([[
/* Pcap */
typedef struct pcap pcap_t;
struct pcap_pkthdr {
  uint64_t ts_sec;         /* timestamp seconds */
  uint64_t ts_usec;        /* timestamp microseconds */
  uint32_t incl_len;       /* number of octets of packet saved in file */
  uint32_t orig_len;       /* actual length of packet */
};

int printf(const char *format, ...);
pcap_t *pcap_open_offline(const char *fname, char *errbuf);
void pcap_close(pcap_t *p);
const uint8_t *pcap_next(pcap_t *p, struct pcap_pkthdr *h);
]])

local onProtocol = require("apps.l7f.protocol_handler")

L7F = {}

function L7F:new(arg)
   self.dpi = dpi.new()
   self.dpi.init()
   self.dpi.setDatalinkType(handle)
   self.dpi.addProtocolHandler(onProtocol)
   return setmetatable({}, { __index = L7F })
end

function L7F:push()
   local i = assert(self.input.input, "input port not found")
   local o = assert(self.output.output, "output port not found")

   while not link.empty(i) and not link.full(o) do
      local packet = link.receive(i)
      if self.dpi.processPacket(header, packet) then
         link.transmit(o, packet)
      end
   end
end

function L7F:report()
   self.dpi.finish()
end
