#!/usr/bin/python

import socket
import sys
import os
import argparse

class colors:
	HOST='\033[32m'
	PORT='\033[36m'
	TYPE='\033[33m'
	SERVICE='\033[35m'
	WARNING='\033[31m'
	INFO='\033[34m'
	END='\033[0m'

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
		sys.exit(colors.WARNING + '[!] ' + colors.END + 'Invalid ip-address/hostname!\n' + colors.WARNING + '[!] ' + colors.END + 'Exiting...')
	try:
		host = socket.gethostbyaddr(ip)[0]
	except socket.herror:
		host = 'Uknown Host'
	protocol = args.type

	print colors.INFO + '[+] ' + colors.END + 'Pinging host ' + ip + ":" + host
	os.system('ping -q -c1 -w2 ' + ip)
	print ""

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
				print colors.INFO + '[+] ' + colors.END + 'Attempting to connect to ' + colors.INFO + '::' + colors.END + colors.HOST + ip + colors.END + colors.INFO + ':' + colors.END + colors.HOST +  host + colors.END + colors.INFO + '::' + colors.END + ' via port ' + colors.PORT + str(port) + colors.END + '/' + colors.TYPE + protocol.upper() + colors.END + ' [' + colors.SERVICE + serv.upper() + colors.END + ']'
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
		print colors.INFO + '[+] ' + colors.END + 'Port ' + colors.PORT + str(port) + colors.END + '/' + colors.TYPE + protocol.upper() + colors.END + ' [' + colors.SERVICE +serv.upper() + colors.END + ']' + ' is open!' + '  ' + colors.INFO + '==>' + colors.END + ' Reply: ' + str(banner)
		s.close()

if __name__ =='__main__':
	main()
