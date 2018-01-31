from scapy.all import *
from scapy.layers import http
import os

if len(sys.argv) == 2:
  iface = str(sys.argv[1])
else:
  iface = "wlx4494fc2560a1"

filter_response = "tcp src port 80 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)"
filter_beacon = "subtype probe-resp or subtype beacon"

channels = [1,6,11]
ap_dict = {}

def BeaconHandler(pkt) :
  if pkt.addr2 not in ap_dict.keys() :
    ap_dict[pkt.addr2] = pkt.info

def HTTPHandler(pkt):
  if pkt.haslayer('HTTP'):
    if "CoinHive.Anonymous" in pkt.load:
      mac = pkt.addr2
      if mac in ap_dict.keys() :
        ssid = ap_dict[mac]
        reason = "Coinhive_miner"
        print "Find Rogue AP: %s(%s) -- %s" %(ssid, mac, reason)
      else:
        print mac

print "WiFi-Miner-Detector"
print "Detecting malicious WiFi with mining cryptocurrency.\n"
print "https://github.com/360PegasusTeam/WiFi-Miner-Detector"
print "by qingxp9 @ 360PegasusTeam\n"

print "[+] Set iface %s to monitor mode" %(iface)
os.system("ifconfig " + iface + " down")
os.system("iwconfig " + iface + " mode monitor")
os.system("ifconfig " + iface + " up")

print "[+] Sniffing on channel " + str(channels) + "\n"
while True:
    for channel in channels:
        os.system("iwconfig " + iface + " channel " + str(channel))
        #print "[+] Sniffing on channel " + str(channel)
#Get surrounding WiFi SSID
        sniff(iface=iface, prn=BeaconHandler, filter=filter_beacon , timeout=1)
#Analyze HTTP
        sniff(iface=iface, prn=HTTPHandler, filter=filter_response, timeout=10)
