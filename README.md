# SDN-Based Firewall using POX

## Features
- Rule-based filtering (IP, MAC, Port)
- Drop rule installation using OpenFlow
- Logging of blocked packets
- Learning switch forwarding
- Traffic analysis using ping and iperf

## Architecture
Host A  ----\
              \ 
               Switch ---- Controller (Firewall Logic)
              /
Host B  ----/

## Summary
Traditional networks use distributed control, but SDN centralizes decision-making. This allows dynamic firewall rule enforcement from a controller.
The controller installs flow rules in the switch so future packets are dropped without contacting the controller.Higher priority ensures firewall rules override normal forwarding.
The firewall correctly differentiates between allowed and blocked traffic using rule-based filtering


## Technologies Used
- POX Controller
- Mininet
- OpenFlow

## How to Run

1. Start controller:
    pox/
    └── pox/
        └── misc/
            └── firewall.py

   cd ~/pox
   ./pox.py openflow.of_01 forwarding.l2_learning misc.firewall

3. Start Mininet:
   sudo mn --topo single,3 --controller=remote

## Testing

- IP filtering:
  h1 ping h2 (blocked)
  h1 ping h3 (allowed)

- MAC filtering:
  h1 ping h3 (blocked)

- Port filtering:
  h3 python3 -m http.server 8080 &
  h1 wget http://10.0.0.3:8080    (allowed)
  h3 pkill -f http.server         (reset)
  h3 python3 -m http.server 80 &
  h1 wget http://10.0.0.3         (blocked)

- Throughput:
  h3 pkill -f iperf    (reset)
  h3 iperf -s &
  h1 iperf -c 10.0.0.3 (allowed)
  h1 iperf -c 10.0.0.2 (blocked)
 
## Flow table
  dpctl dump-flows
 
## Logs
  cat ~/firewall.log

## Author
  Rachith M

