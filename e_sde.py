# ------------------------
# Author: Raquel Alvarez
# Date:   11/22/2017 
# ------------------------
#
# This solution is based on the algorithm developed on the paper:
# P. Pandey. Prevention of ARP spoofing: A probe packet based technique. IEEE IACC, 2013.

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
		hostname = socket.gethostname()
		my_ip = socket.gethostbyname(hostname)
		my_mac = get_if_hwaddr('en0')

		print '\033[94m'+"--- ----------- ---------- ---"+'\033[0m'
		print '\033[1m'+"Received ARP Reply IP "+ip_src+" - MAC "+mac_src+'\033[0m'

		# Send the packet again if we don't get a response right away...

		# Check for malicious activity if the MAC addr is not mine
		if mac_src != my_mac:
			# send ICMP packet with new IP to MAC specified
			# send two packets in case the first one gets lost
			icmp_ans0, icmp_unans0 = srp(Ether(dst=mac_src)/IP(dst=ip_src)/ICMP(), timeout=2)
			icmp_ans1, icmp_unans1 = srp(Ether(dst=mac_src)/IP(dst=ip_src)/ICMP(), timeout=2)
			# response?
			#	Yes: send an ICMP message with our IP instead to MAC
			#		Response: 	yes? intermediate attacker, fire alert
			#				no? Send and ARP broadcast to check for strong attacker
			#					+2 responses? Strong attacker detected 
			# 	No: weak attacker, fire alert

			# Keep checking if we get a response from the first ICMP echo request
			# or if we don't get a response for the first one, but we do for the next one
			if len(icmp_ans0) > 0 or (len(icmp_ans0) == 0 and len(icmp_ans1) > 0):
				# Send another icmp message with our IP instead
				print "Sending ICMP Packet with my IP."
				icmp_ans, icmp_unans = srp(Ether(dst=mac_src)/IP(dst=my_ip)/ICMP(), timeout=2)
				if len(icmp_ans) > 0:
					# Intermediate attacker detected, fire alert
					print "ALERT : Intermediate attacker detected!"
					pkt.sprintf("Attacking MAC Addr:%ARP.hwsrc%")
				else:
					# If it all looks good, we send an ARP Request
					# If we get more than one reply, we know there is a strong attacker
					arp_ans, arp_unans = srp(Ether(dst="FF:FF:FF:FF:FF:FF")/ARP(pdst=ip_src))
					if len(arp_ans) > 1:
						print "ALERT : Strong attacker detected!"
						print "Attacker MAC Addr cannot be determined."
			else:
				# If neither echo message was successful, assume it's an attacker
				# Weak attacker detected, fire alert
				print '\033[91m'+"ALERT : Weak attacker detected!"+'\033[0m'
				print "Attacking MAC Addr: "+mac_src
		print '\033[94m'+"--- ----------- ---------- ---"+'\033[0m'




# Function for Secondary Cache solution
def arp_reply_intercept_sec_cache(pkt):
	# send an ICMP echo msg to the MAC that sent the ARP reply
	if pkt[ARP].op == 2:
		ip_src = pkt[ARP].psrc
		mac_scr = pkt[ARP].hwsrc
		# send ICMP packet
		icmp_ans, icmp_unans = srp(Ether(dst=mac_src)/IP(dst=ip_src)/ICMP())
		# if no response, update ARP table to previous entry
		# otherwise, update secondary cache with new mapping
		if len(icmp_ans) > 0:	
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
# [bigMAC	10.0.0.150 	78:31:C1:C1:3B:72]
# [miniMAC	10.0.0.109 	80:E6:50:0C:F7:C4]
router_ip = '10.0.0.1'
router_mac = '00:50:f1:80:00:00'

attacker_ip = '10.0.0.150'
attacker_mac = '78:31:C1:C1:3B:72'

victim_ip = '10.0.0.109'
victim_mac = '80:E6:50:0C:F7:C4'

icmp_cache = dict(zip([router_mac,attacker_mac,victim_mac], [router_ip,attacker_ip,victim_ip]))

# Get arp packets
sniff(iface="en0", filter="arp", store=0, prn=arp_reply_intercept_esde)
