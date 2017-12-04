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
		my_mac = get_if_hwaddr(ethernet_interface)
		# debug -> my_mac = "11:11:11:11:11:11" -> to see ARP Reply pkts coming from host machine

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
			print "Two probe packets sent..."
			if len(icmp_ans0) > 0:
				print icmp_ans0[ICMP].summary()
			if len(icmp_ans1) > 0:
				print icmp_ans1[ICMP].summary()
			# Keep checking if we get a response from the first ICMP echo request
			# or if we don't get a response for the first one, but we do for the next one
			if (len(icmp_ans0) > 0) or (len(icmp_ans0) == 0 and len(icmp_ans1) > 0):
				# Send another icmp message with our IP instead
				print "Sending ICMP Packet with my IP."
				icmp_ans, icmp_unans = srp(Ether(dst=mac_src)/IP(dst=my_ip)/ICMP(), timeout=2)
				if len(icmp_ans) > 0:
					# Intermediate attacker detected, fire alert
					print '\033[91m'+"ALERT : Intermediate attacker detected!"+'\033[0m'
					print "Attacking MAC Addr: "+mac_src
				else:
					# If it all looks good, we send an ARP Request
					# If we get more than one reply, we know there is a strong attacker
					arp_ans, arp_unans = srp(Ether(dst="FF:FF:FF:FF:FF:FF")/ARP(pdst=ip_src))
					print arp_ans[ARP].summary()
					if arp_ans[0][1].hwsrc != mac_src:
						print '\033[91m'+"ALERT : Strong attacker detected!"+'\033[0m'
						print "Attacker MAC Addr cannot be determined."
			else:
				# If neither echo message was successful, assume it's an attacker
				# Weak attacker detected, fire alert
				print '\033[91m'+"ALERT : Weak attacker detected!"+'\033[0m'
				print "Attacking MAC Addr: "+mac_src
		print '\033[94m'+"--- ----------- ---------- ---"+'\033[0m'


# Set up ethernet interface
ethernet_interface = "en0"

# Sniff ARP packets
sniff(iface=ethernet_interface, filter="arp", store=0, prn=arp_reply_intercept_esde)
