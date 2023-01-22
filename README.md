# PCAPa
BASH Script to parse out relevant artifacts from PCAP files.

This project was inspired by a packet threat hunting script from Chris Greer @packetpioneer. Most of the outputs were meant as a
learning project in BASH.

To use any of the versions of PCAPa, place PCAP file(s) in the same folder as the PCAPa-v#.# file, and run via command line,
(i.e. "./PCAPa-0.91"). TShark is required to run this, so a PATH variable is prefered.

As time goes on, I will be researching more efficient ways to run this script. Currently (v0.91), the tshark filters are ran twice,
once to generate a count of each type of packet in an investigaion summary text file, and second to export those packets into
individual PCAP files groupd by category:

- DNS Packets
- Strange Ports Packets
- RDP Packets
- TLSv1 Packets
- NMAP Activity Packets
- "Bad" Country Packets
- Suspected ARP Poisoning Packets (duplicate Ip per MAC)

NOTE: Be cautious of the naming of original PCAP files. This script will delete files with the following naming conventions as part of cleanup actions:
- dns-*
- strangeports-*
- RDP-*
- TLSVer-*
- nmap-*
- country-*
- arp-*
