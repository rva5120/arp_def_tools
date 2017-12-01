# ------------------------
# Author: Raquel Alvarez
# Date:   11/22/2017 
# ------------------------
#
# This code provides an implementation of the algorithms described in:
# P. Pandey. Prevention of ARP spoofing: A probe packet based technique. IEEE IACC, 2013.


# imports
import socket
from scapy.all import *
import subprocess

'''
# ARP #
# send an ARP broadcast message
#ans,unans=srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst="192.168.1.0/24"), timeout=2)
#ans.summary(lambda (s,r): r.sprintf("%Ether.src% %ARP.psrc%"))
#for snd,rcv in ans:
#	print rcv.sprintf(r"%Ether.src% & %ARP.psrc%\n")

print "Testing ARP..."
def arp_monitor_callback(pkt):
	if ARP in pkt and pkt[ARP].op in (1,2):	#who-has or is-at
		return pkt.sprintf("%ARP.hwsrc% %ARP.psrc%\n")

#sniff(prn=arp_monitor_callback, filter="arp", store=0)
'''

'''
# ICMP #
print "Testing ICMP.."
p = sr1(IP(dst="192.168.2.19")/ICMP())
if p:
	print "Showing p..."
	p.show()

# send ICMP ping
#ans,unans = sr(IP(dst="192.168.1.1-254")/ICMP())
#ans.summary(lambda (s,r): r.sprintf("%IP.src% is alive"))
'''


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
			# secondary_cache[IP] = MAC
		else:
			# Alert about the attacker
			print "ALERT : Weak attacker detected!"
			pkt.sprintf("Attacking MAC Addr: %ARP.hwsrc%")
			print "Adding static entry to ARP table..."
			print "Please enter admin password when prompted."
			# Get old mappings from cache
			old_ip = "10.0.0.3" # ip
			old_mac = "00:00:00:00:00:00" # secondary_cache[ip]
			# Adding static entry
			subprocess.check_call(["sudo", "arp", "-s", old_ip, old_mac])
			print "Done updating ARP table."

# Get arp packets
sniff(iface="en0", filter="arp", store=0, prn=arp_reply_intercept)

'''
# Send ARP broadcast request
#responses,unanswered = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst="192.168.2.19"), timeout=2, retry=10)
#for s,r in responses:
#	print r[Ether].src
'''
