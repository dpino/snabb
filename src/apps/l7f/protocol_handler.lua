local PROTOCOL = {
   DHCP = 18,
   DNS = 5,
   DropBox = 121,
   Google = 126,
   HTTP = 7,
   ICMP = 81,
   IMAPS = 51,
   NTP = 9,
   SSL = 91,
   Spotify = 156,
   Twitter = 120,
   YouTube = 124,
}

function onProtocol(id, packet)
   io.write("### ")
   if id == PROTOCOL.DHCP then
      print("DHCP")
   end
   if id == PROTOCOL.DNS then
      print("DNS")
   end
   if id == PROTOCOL.DropBox then
      print("DropBox")
   end
   if id == PROTOCOL.Google then
      print("Google")
   end
   if id == PROTOCOL.HTTP then
      print("HTTP")
   end
   if id == PROTOCOL.ICMP then
      print("ICMP")
   end
   if id == PROTOCOL.IMAPS then
      print("IMAPS")
   end
   if id == PROTOCOL.NTP then
      print("NTP")
   end
   if id == PROTOCOL.SSL then
      print("SSL")
   end
   if id == PROTOCOL.Spotify then
      print("Spotify")
   end
   if id == PROTOCOL.Twitter then
      print("Twitter")
   end
   if id == PROTOCOL.YouTube then
      print("YouTube")
   end
end

return onProtocol

