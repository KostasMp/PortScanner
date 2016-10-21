import sys
from colors import Colors

def verbose_message(ip, hostname, port_num, port_protocol, service_name):   # The extra message printed if the verbose option is on
    print Colors.INFO + '[+] ' + Colors.END + 'Attempting to connect to ' + Colors.INFO + '::' + Colors.END + Colors.HOST + ip + Colors.END + Colors.INFO + ':' + Colors.END + Colors.HOST + hostname + Colors.END + Colors.INFO + '::' + Colors.END + ' via port ' + Colors.PORT + str(port_num) + Colors.END + '/' + Colors.TYPE + port_protocol + Colors.END + ' [' + Colors.SERVICE + service_name.upper() + Colors.END + ']'

def results_message(port_num, port_protocol, serv_name, banner):   # The message printed for open ports
    print Colors.INFO + '[+] ' + Colors.END + 'Port ' + Colors.PORT + str(port_num) + Colors.END + '/' + Colors.TYPE + port_protocol + Colors.END + ' [' + Colors.SERVICE +serv_name.upper() + Colors.END + ']' + ' is open!' + '  ' + Colors.INFO + '==>' + Colors.END + ' Reply: ' + str(banner)

