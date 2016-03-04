#!/usr/bin/python

import socket
import sys

def userPortInput():		    # Ask the user for the ports to be read.
    input = raw_input("Enter the ports to be checked(sepparated by spaces): ")
    input = input.split(" ")
    return input

def main():
    options = ""	
    verbose = False

    if len(sys.argv) == 1:	    # If no arguments were given in the script call userPortInput() function
        ports = userPortInput()
    elif len(sys.argv) > 1:	    # ...otherwise continue with the execution of the scanner
        ports = sys.argv[1:]
        if ports[0][0] == '-':	    # Check for options
	    options = ports[0]
	    ports = ports[1:]
	    for o in options[1:]:
                if o == 'a':
                    ports = range(0,65535)
                if o == 'v':
                    verbose = True;
	        if o == 'h':
		    print "Usage: portscanner.py [OPTIONS] [PORTS]\nPossible options:\n\t-a (Check all possible ports [0 - 65535])\n\t-v (Print more information for every port scanned)\n\t-h (This help text)"
    for port in ports:		    # For every given port attempt to connect...
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        banner = False
        try:
            if verbose == True:
                print "--> Attempting to connect to 127.0.0.1:" + str(port)
            s.connect(('127.0.0.1',int(port)))
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
