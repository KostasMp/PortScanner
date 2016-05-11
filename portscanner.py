#!/usr/bin/python

import socket
import sys
import os
import argparse

def main():
	parser = argparse.ArgumentParser(description = "Test a specified ip/host for open ports.")
	mutex = parser.add_mutually_exclusive_group(required=True)
	parser.add_argument('ip', metavar='IP', help='The ip/host to be scanned for open ports')
	parser.add_argument('-v', '--verbose', help='Add extra verbosity to the output of the scanner', action='store_true')
	parser.add_argument('-t', '--type', help='The type of the ports to be scanned', choices=['tcp', 'TCP', 'udp', 'UDP'], metavar='[ udp | tcp ]', default='tcp')
	mutex.add_argument('-a', '--all', help='Scan all the possible ports', action='store_true')
	mutex.add_argument('-p', '--ports', help='Scan the specified ports only', type=int, metavar='PORT', choices=range(0,65536), nargs='*', default=[])

	args = parser.parse_args()

	ports = []
	if args.all:
		ports = range(0, 65536)
	elif args.ports:
		ports = args.ports
    
	try:
		ip = socket.gethostbyname(args.ip)
	except socket.gaierror:
		sys.exit('Invalid ip address!')
	try:
		host = socket.gethostbyaddr(ip)[0]
	except socket.herror:
		host = 'Uknown Host'
	protocol = args.type

	print ''
	ping_response = os.system('ping -q -c1 -w2 ' + ip)

	for port in ports:		    # For every given port attempt to connect...
		if (args.type == 'tcp' or args.type == 'TCP'):
			s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		elif (args.type == 'udp' or args.type == 'UDP'):
			s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		banner = False
		s.settimeout(3)
		try:
			serv = socket.getservbyport(port)
		except socket.error:
			serv = 'Uknown Service'
		try:
			if args.verbose:
				print '--> Attempting to connect to ' + ip + '(' + host + ')' + ':' + str(port) + '/' + protocol.upper() + ' [' + serv.upper() + ']'
			s.connect((ip ,int(port)))
			s.send("Port Checking")
			try:
				banner = s.recv(1024)
			except socket.timeout:
				banner = ''
		except socket.error:	    # If a socket.error exception is caught, it means the attempt to connect has failed, 
			continue		    # hence the port is closed... In that case advance to the next port.
		if banner=='':
			banner = 'No Response...'
		print '[+] Port ' + str(port) + '/' + protocol.upper() + ' [' + serv.upper() + ']' + ' is open!' + '  ==> Reply: ' + str(banner)
		s.close()

if __name__ =='__main__':
	main()
