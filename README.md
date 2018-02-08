# WiFi Miner Detector
by qingxp9 @ 360PegasusTeam

## Overview
A tool for detecting malicious WiFi with mining cryptocurrency.

Some weeks ago I read a news "Starbucks Wi-Fi Hijacked People's Laptops to Mine Cryptocurrency". The attackers inject the CoinHive javascript miner to HTTP Response, so I write this tool to detect malicious WiFi with miner scripts, include:

- [coinhiveMiner](https://coinhive.com/)
- [deepMiner](https://github.com/deepwn/deepMiner)

It is based on analyzing the unencrypted 802.11 Data Frame to find keywords in HTTP data, Because this attack is major occured in public open WiFi.

## Requirements
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

I tested it with TP-Link TL-WN722N (chipset Atheros AR9271), and works well.

## Usage
```
sudo python wifi_miner_detector.py wlan0
```

![demo](https://github.com/360PegasusTeam/WiFi-Miner-Detector/blob/master/demo.gif)

you can add any rules in **HTTPHandler** to expand it. Just pull a request if you have any idea. 

## References

- http://www.freebuf.com/articles/web/161010.html
- https://www.anquanke.com/post/id/95697
- https://twitter.com/qingxp9/status/957908040556015616
