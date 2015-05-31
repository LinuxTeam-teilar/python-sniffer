##########################################################################
# Copyright (C) Chatzopoulos Dimos 2010 <dimosch@gmail.com>              #
#                                                                        #
# This program is free software: you can redistribute it and/or modify   #
# it under the terms of the GNU General Public License as published by   #
# the Free Software Foundation, either version 3 of the License, or      #
# (at your option) any later version.                                    #
#                                                                        #
# This program is distributed in the hope that it will be useful,        #
# but WITHOUT ANY WARRANTY; without even the implied warranty of         #
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the          #
# GNU General Public License for more details.                           #
#                                                                        #
# You should have received a copy of the GNU General Public License      #
# along with this program.  If not, see <http://www.gnu.org/licenses/>.  #
##########################################################################


import dpkt
import socket
import netifaces
import signal
import sys
import binascii
import time


# convert binary mac to hex
def eth_ntoa(buffer):
    mac_lst=[]
    for i in range(0, len(binascii.hexlify(buffer)), 2):
        mac_lst.append(binascii.hexlify(buffer)[i:i+2])
    mac = ':'.join(mac_lst)
    return mac

# convert hex mac to binary
def eth_aton(buffer):
    sp = buffer.split(':')
    buffer = ''.join(sp)
    return binascii.unhexlify(buffer)

# Get IP address from a local interface
def get_device_ip(device):
    try:
        return str(netifaces.ifaddresses(device)[netifaces.AF_INET][0]['addr'])
    except KeyError:
        print 'Error: Device \"',device,'\" seems to be down.'
        sys.exit(0)
    except ValueError:
        print 'Error: Device \"',device,'\" does not exist.'
        sys.exit(0)

# Get MAC address from a local interface
def get_device_mac(device):
    try:
        return str(netifaces.ifaddresses(device)[netifaces.AF_LINK][0]['addr'])
    except ValueError:
        print 'Error: Device \"',device,'\" does not exist.'
        sys.exit(0)

# Get a remote host's MAC address
def get_mac(ipaddr, device):

    def handler(signum, frame):
        print ipaddr, 'seems to be down'
        sys.exit(0)


    arp = dpkt.arp.ARP()

    arp.sha = eth_aton(get_device_mac(device)) # source mac address
    arp.spa = socket.inet_aton(get_device_ip(device)) # source ip address
    arp.tha = eth_aton('00:00:00:00:00:00') # destination mac address
    arp.tpa = socket.inet_aton(ipaddr) #destination ip address
    arp.op = dpkt.arp.ARP_OP_REQUEST # ARP message opcode
    eth = dpkt.ethernet.Ethernet()
    eth.src = arp.sha # ethernet header source mac address
    eth.dst = eth_aton('ff:ff:ff:ff:ff:ff') # ethernet header destination mac address
    eth.data = arp # ethernet frame data
    eth.type = dpkt.ethernet.ETH_TYPE_ARP # ethernet frame type

    s = socket.socket(socket.PF_PACKET, socket.SOCK_RAW) # open socket
    s.bind((device, dpkt.ethernet.ETH_TYPE_ARP))

    s.send(eth.pack()) #send frame
    arp_answer = dpkt.arp.ARP()

    signal.signal(signal.SIGALRM, handler)
    signal.alarm(4) # set alarm to 4 seconds to break loop in case no packet received.


    while 1:

        data = s.recv(1024) # receive data
        answer = dpkt.ethernet.Ethernet(data) # asign data to object
        if answer.type == dpkt.ethernet.ETH_TYPE_ARP:
            arp_answer = answer.data # get arp message
            if (arp_answer.spa == arp.tpa) and (arp_answer.tpa == arp.spa) and (arp_answer.op == dpkt.arp.ARP_OP_REPLY): # check if it's the right ARP message
                s.close() # close socket
                signal.alarm(0) # disable alarm
                print socket.inet_ntoa(arp_answer.spa), '=>', eth_ntoa(arp_answer.sha)
                return eth_ntoa(arp_answer.sha)# return the mac address

# Print ethernet packets short description (check for datalink type in main prog
def eth_cap_desc(ts, pkt): # to be called with pcap.pcap.loop()
    eth = dpkt.ethernet.Ethernet(pkt)
    p1 = eth.data
    if hasattr(p1, 'data'):
        p2 = p1.data

    if eth.type == dpkt.ethernet.ETH_TYPE_IP: # check for IP protocol
        spa = socket.inet_ntoa(p1.src) # get source ip address
        dpa = socket.inet_ntoa(p1.dst) # get destination ip address

        if p1.p == dpkt.ip.IP_PROTO_UDP or p1.p == dpkt.ip.IP_PROTO_TCP:  # check for TCP or UDP control protocols and get source and destination ports
            sport = p2.sport
            dport = p2.dport
            print time.strftime('%H:%M:%S',time.localtime(ts)), '%s(%s) %s:%d  =>  %s:%d' % (p1.__class__.__name__, p2.__class__.__name__, spa, sport, dpa, dport) #print protocol names and source and dest. ip addresses
        else:
            print time.strftime('%H:%M:%S',time.localtime(ts)), '%s(%s) %s  =>  %s' % (p1.__class__.__name__, p2.__class__.__name__, spa, dpa) # print protocol names & source and destination ip addresses

    elif eth.type == dpkt.ethernet.ETH_TYPE_IP6: # check for IPv6 and get ip addresses
        spa = socket.inet_ntop(socket.AF_INET6, p1.src)
        dpa = socket.inet_ntop(socket.AF_INET6, p1.dst)
        print time.strftime('%H:%M:%S',time.localtime(ts)), '%s(%s) %s  =>  %s' % (p1.__class__.__name__, p2.__class__.__name__, spa, dpa) # print protocol names & source and destination ipv6 addresses

    elif eth.type == dpkt.ethernet.ETH_TYPE_ARP: # check for ARP protocol & get source and dest. MAC addresses
        sha = eth_ntoa(eth.src)
        dha = eth_ntoa(eth.dst)
        if p1.op == dpkt.arp.ARP_OP_REPLY: #check ARP opcode
            op = 'REPLY'
        elif p1.op == dpkt.arp.ARP_OP_REQUEST:
            op = 'REQUEST'

        print time.strftime('%H:%M:%S',time.localtime(ts)),'%s(%s) %s  =>  %s' % (p1.__class__.__name__, op, sha, dha) # print protocol name, type and MAC addresses

    else: # if any other protocol get source and dest. MAC addresses and print them with protocol name.
        sha = eth_ntoa(eth.src)
        dha = eth_ntoa(eth.dst)
        print time.strftime('%H:%M:%S',time.localtime(ts)), '%s %s  =>  %s' % (p1.__class__.__name__,sha, dha)

# check if an IP address is valid, returns True for valid, and False for invalid
def check_ip(addr):
    try:
        socket.inet_aton(addr)
        return True
    except socket.error:
        return False
