#!/usr/bin/python

import socket
import sys
import argparse

def main():
	parser = argparse.ArgumentParser(description = "Test a specified IP for open ports.")
	mutex = parser.add_mutually_exclusive_group()
	parser.add_argument('ip', metavar='IP', help='The ip to be scanned for open ports')
	parser.add_argument('-v', '--verbose', help='Add extra verbosity to the output of the scanner', action='store_true')
	mutex.add_argument('-a', '--all', help='Scan all the possible ports', action='store_true')
	mutex.add_argument('-p', '--ports', help='Scan the specified ports only', type=int, metavar='PORT', choices=range(0,65536), nargs='*', default=[])

	args = parser.parse_args()

	if args.all:
		ports = range(0, 65536)
	elif args.ports:
		ports = args.ports
	else:
		ports = userPortInput()
    
	ip = args.ip

	for port in ports:		    # For every given port attempt to connect...
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		banner = False
		try:
			if args.verbose:
				print "--> Attempting to connect to " + ip + ":" + str(port)
			s.connect((ip ,int(port)))
			s.send("Port Checking")
			banner = s.recv(1024)
		except(socket.error):	    # If a socket.error exception is caught, it means the attempt to connect has failed, 
			continue		    # hence the port is closed... In that case advance to the next port.
		if banner=='':
			banner = "No Response..."
		print "[+] Port "+ str(port) +" is open!"+ "  ==> Reply: "+ str(banner)
		s.close()

if __name__ =="__main__":
	main()
