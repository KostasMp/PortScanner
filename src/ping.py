import sys
import os
from colors import Colors


def ping(ip, hostname):   # The ping implementation
    print ''
    print Colors.INFO + '[+] ' + Colors.END + 'Pinging host ' + ip + ":" + hostname
    print ''
    os.system('ping -q -c1 -w2 ' + ip)
    print ''
