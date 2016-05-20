#!/usr/bin/python

import socket
import sys
import os
import argparse

from source.colors import Colors

class Host:	
	"""Represents a host by storing its ip address and its name (whenever its possible)"""

	def __init__(self, ip_or_host):     # The constructor of the class
		self.validate_ip(ip_or_host)
		self.validate_hostname(self.ip)

	def validate_ip(self, ip_or_host):  # Matches a hostname to an ip address and stores it (if an ip was given in the first place it is stored untouched)
		try:
			self.ip = socket.gethostbyname(ip_or_host)
		except socket.gaierror:
			sys.exit(Colors.WARNING + '[!] ' + Colors.END + 'Invalid ip-address/hostname!\n' + Colors.WARNING + '[!] ' + Colors.END + 'Exiting...')	

	def validate_hostname(self, ip):    # Attempts to match the given ip to a hostname and stores it
		try:
			self.name = socket.gethostbyaddr(ip)[0]
		except socket.herror:
			self.name = 'Uknown Host'

class Service:
	"""Represents a network service associated with a port"""

	def __init__(self, port):         # The constructor of the class
		self.verify_service(port.num)
		self.port = port

	def verify_service(self, port):   # Implement service resolving, if possible, given a port
		try:
			self.name = socket.getservbyport(port)
		except socket.error:
			self.name = 'Uknown Service'

class Port:
	"""Represents a port by storing its number and its type"""

	def __init__(self, port_num, port_type):   # The constructor of the class
		self.num = port_num
		self.protocol = port_type

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
	host = Host(args.ip)

	ping(host.ip, host.name)	

	for port_num in ports:
		port = Port(port_num, args.type.upper())
		if (port.protocol == 'TCP'):								#
			s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)   # Protocol
		elif (port.protocol == 'UDP'):                          	# Checking
			s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)    #
		service = Service(port)
		banner = False
		s.settimeout(3)
		
		try:
			if args.verbose:
				verbose_message(host.ip, host.name, port.num, port.protocol, service.name)
			s.connect((host.ip, port.num))	# Connect to an ip using the specified port
			s.send("Port Checking")		# Send the message 'Port Checking' to the connected server
			try:
				banner = s.recv(1024)		# Attempt to get a response message
			except socket.timeout:
				banner = ''
		except socket.error:        # If a socket.error exception is caught the attempt to connect has failed, 
			continue                # hence the port is closed. In that case advance to the next port
		if banner=='':
			banner = 'No Response...'
		results_message(port.num, port.protocol, service.name, banner)
		s.close()

def verbose_message(ip, hostname, port_num, port_protocol, service_name):   # The extra message printed if the verbose option is on
	print Colors.INFO + '[+] ' + Colors.END + 'Attempting to connect to ' + Colors.INFO + '::' + Colors.END + Colors.HOST + ip + Colors.END + Colors.INFO + ':' + Colors.END + Colors.HOST + hostname + Colors.END + Colors.INFO + '::' + Colors.END + ' via port ' + Colors.PORT + str(port_num) + Colors.END + '/' + Colors.TYPE + port_protocol + Colors.END + ' [' + Colors.SERVICE + service_name.upper() + Colors.END + ']'

def results_message(port_num, port_protocol, serv_name, banner):   # The message printed for open ports
	print Colors.INFO + '[+] ' + Colors.END + 'Port ' + Colors.PORT + str(port_num) + Colors.END + '/' + Colors.TYPE + port_protocol + Colors.END + ' [' + Colors.SERVICE +serv_name.upper() + Colors.END + ']' + ' is open!' + '  ' + Colors.INFO + '==>' + Colors.END + ' Reply: ' + str(banner)

def ping(ip, hostname):   # The ping implementation
	print ''
	print Colors.INFO + '[+] ' + Colors.END + 'Pinging host ' + ip + ":" + hostname
	print ''
	os.system('ping -q -c1 -w2 ' + ip)
	print ''

if __name__ =='__main__':
	main()
