# SDN-Based Firewall using POX

## Features
- Rule-based filtering (IP, MAC, Port)
- Drop rule installation using OpenFlow
- Logging of blocked packets
- Learning switch forwarding
- Traffic analysis using ping and iperf

## Technologies Used
- POX Controller
- Mininet
- OpenFlow

## How to Run

1. Start controller:
   cd ~/pox
   ./pox.py openflow.of_01 forwarding.l2_learning misc.firewall

2. Start Mininet:
   sudo mn --topo single,3 --controller=remote

## Testing

- Blocked:
  h1 ping h2

- Allowed:
  h1 ping h3

- Throughput:
  h3 iperf -s &
  h1 iperf -c 10.0.0.3

- Port filtering:
  h3 python3 -m http.server 80 &
  h1 wget http://10.0.0.3

## Logs
cat ~/firewall.log

## Author
Rachith M

