#!/usr/bin/env python

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


import functs
import attacks
from multiprocessing import Process
import pcap, dpkt, time, sys, optparse

# define command line options with optparse module
p = optparse.OptionParser()
p.add_option('-i', '--interface', dest='interface', help='Network interface to listen (ex. -i eth0).')
p.add_option('-f', '--filter', dest='filter', default='', help='Set the capture filter (logical expresion \"quoted\").')
p.add_option('-m', '--mitm', dest='targets', nargs=2, help='Perform ARP cache poisoning MITM attack, against two targets (ex. -m 192.168.1.1 192.168.1.4) separated by space.')
p.add_option('-x', '--hexdump', action='store_true', dest='hexdump', default=False, help='Print the packet in hex and ASCII.')
p.add_option('-s', '--snaplen', dest='snaplen', default=65535, type='int', help='Set the capture snapshot length in bytes (default is 65535).')
p.add_option('-w', '--dumpfile', dest='dumpfile', help='Dump packets in a file (.pcap).')
p.add_option('-p', '--promisc', action='store_true', dest='promisc', default=False, help='Enable promiscuous mode for the network interface.')

options, arguments = p.parse_args() # get options and arguments

if options.interface:
    try:
        pc = pcap.pcap(name = options.interface, snaplen = options.snaplen, promisc = options.promisc)
        pc.setfilter(options.filter)
    except OSError, e:
        print e
        sys.exit(0)
    pc.setnonblock(True)
    if options.hexdump and options.dumpfile: # make sure that -w and -x options are not going to be used together
        print 'Options -w and -x may not be used together\n'
        p.print_help()
    else:
        try:
            if options.targets: # if -m: run the attack in a separate process
                target1, target2 = options.targets #get the targets from -m dest tuple
                if functs.check_ip(target1)==True and functs.check_ip(target2)==True: # check for valid targets (functs.check_ip)
                    mitm=Process(target=attacks.mitm, args=(target1, target2, options.interface))
                    mitm.start()
                    mitm.join(6) # get the stdout for 6 secs
                    if mitm.is_alive():pass #check if the mitm process exited
                    else:sys.exit(0)
                else:
                    print 'Targets are not valid IP addresses'
                    sys.exit(0)

            print 'Listening on %s:\n' % options.interface

            if options.dumpfile:
                print 'Writing packets to file %s....\n' % options.dumpfile
                writer = dpkt.pcap.Writer(open(options.dumpfile, 'wb')) # create Writer and open dump file
                for ts, pkt in pc:
                    writer.writepkt(pkt) # write packets.
            elif options.hexdump:
                for ts, pkt in pc:
                    print '\n', dpkt.hexdump(pkt) # print hex and ASCII
            else:
                pc.loop(functs.eth_cap_desc) # describe ethernet packets.
        except KeyboardInterrupt:
            if options.targets:
                mitm.join(3)
                mitm.terminate()
            if options.dumpfile: writer.close()
            precv, pdrop, pifdrop = pc.stats()
            # print statistics
            print '\n%d packets received by filter' % precv
            print '%d packets dropped by kernel' % pdrop
            print '%d packets dropped by interface' % pifdrop

else:
    print 'Interface not specified\n'
    print p.print_help() # print help
