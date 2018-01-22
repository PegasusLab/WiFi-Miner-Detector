# WiFi-Miner-Detector
by qingxp9 @ 360PegasusTeam

##Overview
Detecting malicious WiFi with mining cryptocurrency.

##Requirements
```
sudo apt install python-pip
pip install scapy
pip install scapy_http
```

And you'll need a WiFi card that supports monitor mode. You can check by running: iw list. Something like:

```
	Supported interface modes:
		 * IBSS
		 * managed
		 * AP
		 * AP/VLAN
		 * monitor
		 * mesh point
```

I test on TP-Link TL-WN722N (chipset Atheros AR9271), and it works well.

##Usage
sudo python wifi_miner_detector.py wlan0

![demo](https://github.com/360PegasusTeam/WiFi-Miner-Detector/blob/master/demo.gif)
