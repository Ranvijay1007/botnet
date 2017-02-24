#!/usr/bin/env python

import socket
import nmap

PORT = 21395
print("Scaning for port %d on LAN" %PORT)
BASE_ADDR = '192.168.0.0/24'
nm = nmap.PortScanner()
nm.scan(hosts=BASE_ADDR, arguments='-sV -p '+str(PORT))

for x in nm.all_hosts():
	if nm[x]['tcp'][PORT]['state']=='open':
		print x , " listening "
	else:
		print x , " not listening"
