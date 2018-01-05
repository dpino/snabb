DNS-SD
------

Implement DNS Service Discovery.

DNS-SD sends a local-link request to the broadcast address 224.0.0.251 port 5353.  The default query is "_service.dns-sd._tcp.local", unless a different query is set in the argument list. If there are any devices or services listening to Multicast DNS request in the network, they will announce their domain-name to 224.0.0.251.  The app listens to mDNS response and prints out A, PTR, SRV and TXT records.

Example:

```
$ sudo ./snabb dnssd wlan0
Capturing packets from interface 'wlan0'
PTR: (name: _services._dns-sd._udp.local; domain-name: _googlecast._tcp)
PTR: (name: _services._dns-sd._udp.local; domain-name: _googlezone._tcp)
PTR: (name: _services._dns-sd._udp.local; domain-name: _spotify-connect._tcp)
```

Further information of _googlecast._tcp.local:

```
$ sudo ./snabb dnssd wlan0 _googlecast._tcp.local
Capturing packets from interface 'wlan0'
PTR: (name: _googlecast._tcp.local; domain-name: Google-Home-00000000000000000000000000000000)
TXT: (id=00000000000000000000000000000000;cd=00000000000000000000000000000000;rm=0000000000000000;ve=00;md=Google Home;ic=/setup/icon.png;fn=Home;ca=0000;st=0;bs=000000000000;nf=0;rs=;)
SRV: (target: d81d02e1-e48a-1f0b-7d2c-bac88f2df820)
Address: 192.168.0.11

PTR: (name: _googlecast._tcp.local; domain-name: Chromecast-Audio-00000000000000000000000000000001)
TXT: (id=00000000000000000000000000000001;cd=00000000000000000000000000000000;rm=0000000000000000;ve=00;md=Chromecast Audio;ic=/setup/icon.png;fn=Audio;ca=0000;st=0;bs=000000000000;nf=0;rs=;)
SRV: (target: 0000000000000-0000-0000-000000000000)
Address: 192.168.0.12

PTR: (name: _googlecast._tcp.local; domain-name: Google-Cast-Group-00000000000000000000000000000002)
TXT: (id=00000000-0000-0000-0000-000000000002;cd=00000000-0000-0000-0000-000000000002;rm=0000000000000000;ve=00;md=Google Cast Group;ic=/setup/icon.png;fn=Group;ca=0000;st=0;bs=000000000000;nf=0;rs=;)
SRV: (target: 00000000-0000-0000-0000-000000000000)
Address: 192.168.0.12
```
