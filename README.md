# PortScanner	
PortScanner is a port scanner (wow!) implemented in the Python Programming Language (2.7.9)	    
The projects name will be changed as soon as i find a fancy one.

## Functionality    
Currently PortScanner supports the following features:    
- Open port scanning    
- Both UDP and TCP support    
- Multiple host support    
- Host pinging    
- Service resolving    
- Hostname-to-IP/IP-to-Hostname resolving     

## Use    
       
To execute it:     
`./portscanner.py [OPTIONS] HOST/IP`    
        
To learn about all the available options:    
`./portscanner.py -h`    
	
## Implementation    
Great efforts have-been/will-be made to keep PortScanner's code as simple and understandable as possible.    
The _argparse_ module has been used as the mechanism for parsing the user's input.    
The "networking" parts of the code are implemented with sockets (with use of the _socket_ module).    

## Acknowledgements    
The idea and part of the initial code was taken by the **Primal Security** website: [Primal Security - Python Port Scanner Tutorial][pspt]    
**Special Thanks** to [DaknOb][daknob] for making my life as hard (and creative) as possible and for always keeping track of the issues list     
so that its never empty.     

License
---
The MIT License (MIT)

[pspt]: <http://www.primalsecurity.net/0x1-python-tutorial-port-scanner/>
[daknob]: <https://blog.daknob.net/>
