# Router - Communication Protocols - Project 1

A pdf with the detailed description can be found in the repo.

#

I have solved the following requirements:

- ARP protocol
- Routing process
- ICMP protocol
- BONUS: incremental checksum update

In the main function, I extract the headers from the received packet.

The type of the packet (ARP or ICMP) is determined by the presence of ARP or ICMP headers.

The handleARP or handleICMP functions are called, which return a bool. This bool is false if the packet needs to be dropped or if its functionality has ended and it is not needed further.

If the bool is true, the code reaches handleForwarding where the packet is forwarded further.

## Handle ARP

The type of the ARP packet (request or reply) is determined by checking the value of arp_hdr->op.

If it is a request, an ARP reply is sent to the source where the request came from.

If it is a reply, it checks if there are any packets in the saved packet queue. If there are, it verifies the checksum (ttl is not checked because it was already updated when it was added to the queue). If everything is okay, it finds the route and if it exists, it updates the ethernet_header with the corresponding MAC and sends the packet.

## Handle ICMP

The ttl and icmp checksum are checked. If the packet is for the current router and is an echo request, then an ICMP is sent back to the source.

## Handle Forwarding

The ttl and checksum are checked. The ttl is updated and the checksum is updated as well. A route is searched for and if it does not exist, an ICMP error is sent back to the source.

The necessary MAC address is searched for in the ARP table. If it does not exist, the packet is placed in the queue and an ARP broadcast is sent.

If a MAC address is found, the ethernet header is updated with the MAC of the next hop and the packet is sent.

## TTL Decrement Checksum

Updating the checksum following modification of the ttl.

The logic is taken from here: https://datatracker.ietf.org/doc/rfc1624/

## Get route

It linearly traverses the routing table. In the comments, there is an attempt at binary search. The table is initially sorted with a merge sort based on the prefix and mask.

## Send ARP and ICMP

It creates the necessary headers from the given arguments. It creates a new packet in which it inserts these headers and sends it.
