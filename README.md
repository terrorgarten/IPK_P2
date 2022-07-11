# Packet sniffer ipk-sniffer for the IPK course, FIT BUT, 2022
ipk-sniffer is a tool for analyzing and capturing packets on the web. 
It allows for advanced filtering via definig transport and network layer protocols
Currently manages both ipv4 and ipv6 + arp on network layer and udp, tcp, icmp and icmp6 on transport layer.

## Version:
0.1.1 - Currently considered unstable, WIP

## Usage:
see -h for help with options.
Make sure to use root mode for correct connction to interfaces.
Using other than ethernet interfaces results in warning and the output may be corrupted.

## Run examples:

View aviable interfaces:
```
$ ./ipk-sniffer -i
```

View 20 packets of any protocol on eth0 interface:
```
$ ./ipk-sniffer -i eth0 -n 20 
```

View 20 packets on eth0 interface, which are tcp or udp
```
$ ./ipk-sniffer -i eth0 -n 20 --tcp --udp
```

View 1 packet (default -n) on eth0 interface, which are tcp and on port 1000
```
$ ./ipk-sniffer -i eth0 --tcp -p 1000
```
