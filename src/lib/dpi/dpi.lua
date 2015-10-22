local ffi = require("ffi")
local C = ffi.C

ffi.cdef([[
typedef void (*callback)(int, const uint8_t *packet);
typedef struct pcap pcap_t;
struct pcap_pkthdr {
  uint64_t ts_sec;         /* timestamp seconds */
  uint64_t ts_usec;        /* timestamp microseconds */
  uint32_t incl_len;       /* number of octets of packet saved in file */
  uint32_t orig_len;       /* actual length of packet */
};

void init();
void addProtocolHandler(callback handler);
void processPacket(const struct pcap_pkthdr *header, const uint8_t *packet);
void finish();
]])

DPI = {}

function DPI:new(arg)
	local o = {}
	o.ndpi = ffi.load("ndpi")
	return setmetatable(o, { __index = DPI })
end

function DPI:init()
	self.ndpi.init()
end

function DPI:addProtocolHandler(f)
	self.ndpi.addProtocolHandler(f)
end

function processPacket(header, packet)
	self.ndpi.processPacket(header, packet)
end

function finish()
	self.ndpi.finish()
end