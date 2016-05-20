import socket

class Port:
	"""Represents a port by storing its number and its type"""

	def __init__(self, port_num, port_type):   # The constructor of the class
		self.num = port_num
		self.protocol = port_type

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
