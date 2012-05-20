HaoQi's Barnacle Wifi Tether Fork
==================
A Wifi tether that only provides ad-hoc Wifi. 
It is the [original Barnacle][1] but without NAT and DHCP binaries running, providing a simplified interface for just ad-hoc Wifi.

When running this app for the first time, a prompt will ask about a WPA Supplicant. Keep choosing "Yes" and it will create the WPA supplicant so you can press "Start" successfully the second time.

Change IP address
----------------
The same way as the original Barnacle app:

* Barnacle -> Settings -> DHCP -> Gateway -> [new IP address] --> Okay
* Stop and Start (i.e. restart)

[Original Barnacle Wifi Tether's README][1]
====================

Barnacle is a combination of tools to provide wifi tethering 
on an Android phone:
 * NAT
 * DHCP server
 * WLAN ad-hoc setup

How to build Barnacle
---------------------
[see original Barnacle README][1]

[1]: https://github.com/haoqili/barnacle

