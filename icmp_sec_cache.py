# ------------------------
# Author: Raquel Alvarez
# Date:   11/22/2017 
# ------------------------
#
# Ts solution is based on the algorithm developed on the paper:
# Nikhil Tripathi, BM Mehtre, 
# “An ICMP based secondary cache approach for the detection and preventio of ARP poisoning” in 4th IEEE International Conference on Computational Intelligence and Computing Research (ICCIC). 
# Publication year: 2013,


# imports
import socket
from scapy.all import *
import subprocess


# Function for E-SDE soltuion
def arp_reply_intercept_esde(pkt):
	# do soemthing if packet is a reply
	if pkt[ARP].op == 2:
		ip_src = pkt[ARP].psrc
		mac_src = pkt[ARP].hwsrc
		# send ICMP packet with new IP to MAC specified
		icmp_ans, icmp_unans = srp(Ether(pdst=mac_src)/IP(dst=ip_scr)/ICMP())
		# response?
		#	Yes: send an ICMP message with our IP instead to MAC
		#		Response: 	yes? intermediate attacker, fire alert
		#				no? leave entry
		# 	No: weak attacker, fire alert
		if icmp_ans.summary() != "":
			# Send another icmp message with our IP instead
			hostname = socket.gethostname()
			my_ip = socket.gethostbyname(hostname)
			icmp_ans, icmp_unans = srp(Ether(pdst=mac_scr)/IP(dst=my_ip)/ICMP())
			if icmp_ans != "":
				# Intermediate attacker detected, fire alert
				print "ALERT : Intermediate attacker detected!"
				pkt.sprintf("Attacking MAC Addr:%ARP.hwsrc%")
		else:
			# Weak attacker detected, fire alert
			print "ALERT : Weak attacker detected!"
			pkt.sprintf("Attacking MAC Addr:%ARP.hwsrc%")



# Function for Secondary Cache solution
def arp_reply_intercept_sec_cache(pkt):
	# send an ICMP echo msg to the MAC that sent the ARP reply
	if pkt[ARP].op == 2:
		ip_src = pkt[ARP].psrc
		mac_scr = pkt[ARP].hwsrc
		# send ICMP packet
		icmp_ans, icmp_unans = srp(Ether(pdst=mac_src)/IP(dst=ip_src)/ICMP())
		# if no response, update ARP table to previous entry
		# otherwise, update secondary cache with new mapping
		if icmp_ans.summary() != "":	
			# update secondary cache
			# secondary cache: key = IP, value = MAC
			icmp_cache[mac_src] = ip_src
		else:
			# Alert about the attacker
			print "ALERT : Weak attacker detected!"
			pkt.sprintf("Attacking MAC Addr: %ARP.hwsrc%")
			print "Adding static entry to ARP table..."
			print "Please enter admin password when prompted."
			# Get old mappings from cache
			old_ip = icmp_cache[mac_src]
			old_mac = mac_src
			# Adding static entry
			subprocess.check_call(["sudo", "arp", "-s", old_ip, old_mac])
			print "Done updating ARP table."


# Setup Secondary Cache
# 1. Get IP-MAC bindings from current ARP cache table
#icmp_cache
# [router 	10.0.0.1   	00:50:f1:80:00:00]
# [phone	10.0.0.224 	B8:D7:AF:B1:F0:59]
# [miniMAC	10.0.0.151 	78:31:C1:C1:3B:72]
# [bigMAC	10.0.0.109 	80:E6:50:0C:F7:C4]
router_ip = '10.0.0.1'
router_mac = '00:50:f1:80:00:00'

attacker_ip = '10.0.0.151'
attacker_mac = '78:31:C1:C1:3B:72'

icmp_cache = dict(zip([router_mac,attacker_mac], [router_ip,attacker_ip]))

# Get arp packets
sniff(iface="en0", filter="arp", store=0, prn=arp_reply_intercept_sec_cache)
