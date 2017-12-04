# ------------------------
# Author: Raquel Alvarez
# Date:   11/22/2017 
# ------------------------
#
# This solution is based on the algorithm developed on the paper:
# Nikhil Tripathi, BM Mehtre, 
# An ICMP based secondary cache approach for the detection and preventio of ARP poisoning.
# 4th IEEE International Conference on Computational Intelligence and Computing Research (ICCIC). 
# Publication year: 2013,

# imports
import socket
from scapy.all import *
import subprocess


# Function for Secondary Cache solution
def arp_reply_intercept_sec_cache(pkt):
	# send an ICMP echo msg to the MAC that sent the ARP reply
	if pkt[ARP].op == 2:
		ip_src = pkt[ARP].psrc
		mac_src = pkt[ARP].hwsrc
		hostname = socket.gethostname()
		my_ip = socket.gethostbyname(hostname)
		my_mac = get_if_hwaddr(ethernet_interface)
		# debug -> my_mac = "11:11:11:11:11:11" -> to see ARP Reply pkts coming from host machine

		print '\033[94m'+"--- ----------- ---------- ---"+'\033[0m'
		print '\033[1m'+"Received ARP Reply IP "+ip_src+" - MAC "+mac_src+'\033[0m'

		# Check for attacker if the ARP Reply wasn't sent by this host
		if mac_src != my_mac:
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
				print '\033[91m'+"ALERT : Weak attacker detected!"+'\033[0m'
				print "Attacking MAC Addr: "+mac_src
				print "Adding static entry to ARP table..."
				print "Please enter admin password when prompted."
				# Get old mappings from cache
				old_ip = icmp_cache[mac_src]
				old_mac = mac_src
				# Adding static entry
				subprocess.check_call(["sudo", "arp", "-s", old_ip, old_mac])
				print "Done updating ARP table."
		print '\033[94m'+"--- ----------- ---------- ---"+'\033[0m'



# Setup Secondary Cache
# Set IP-MAC bindings from current ARP cache table
print "Setting up Secondary Cache..."
router_ip = ''
router_mac = ''

victim_ip = ''
victim_mac = ''

attacker_ip = ''
attacker_mac = ''

icmp_cache = dict(zip([router_mac,attacker_mac,victim_mac], [router_ip,attacker_ip,victim_ip]))

ethernet_interface = "en0"

# Get arp packets
sniff(iface=ethernet_interface, filter="arp", store=0, prn=arp_reply_intercept_sec_cache)
