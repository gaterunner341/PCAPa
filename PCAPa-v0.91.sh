#!/bin/bash
# By Phillip Kittelson
# Adapted script from Chris Greer @packetpioneer
# 20220912
# v0.91

# Variables
report='1.InvestigationSummary.txt'
lineBreak='----------------------------------------------------------------'

# Setup PCAP investigation summary, include current user name, path to current directory, date, and hash origional PCAP files
touch $report
echo PCAP Investigation Summary >> $report
echo $lineBreak >> $report
echo User: $(whoami) >> $report
echo Host: $(hostname) >> $report
echo Path: $(pwd) >> $report
echo $lineBreak >> $report
echo Date: $(date) >> $report
echo $lineBreak >> $report
echo Original File: >> $report
echo $lineBreak >> $report

# Loop though all PCAPs in the folder, and provide summary of findings
for f in *.pcap; do md5sum $f >> $report;
echo DNS Packets: "$(tshark -r $f -Y "dns" | wc -l)" >> $report;
echo Strange Ports Packets: "$(tshark -r $f -Y "!tcp.port in {22,23,25,80,443,445,993,995,8000..8005} or not dns" | wc -l)" >> $report; 
echo RDP Packets: "$(tshark -r $f -Y "tcp.port==3389" | wc -l)" >> $report;
echo TLSv1 Packets: "$(tshark -r $f -Y "tls.handshake.version < 0x0303" | wc -l)" >> $report;
echo NMAP Activity Packets: "$(tshark -r $f -Y "tcp.flags.syn==1 and tcp.flags.ack==0 and tcp.window_size<=1024" | wc -l)" >> $report;
echo Bad Country Packets: "$(tshark -r $f -Y "ip.geoip.country_iso in {CN,RU,NK}" | wc -l)" >> $report;
echo Suspected ARP Poison: "$(tshark -r $f -Y "arp.duplicate-address-frame" | wc -l)" >> $report;
done

echo $lineBreak >> $report

# Loop through each PCAP file in the current folder, use tshark to apply filter, dump each into a separate PCAP
for f in *.pcap; do tshark -r $f -Y "dns" -w dns-$f; done
mergecap -w 2.allDNS.pcapng dns-*
rm dns-*

for f in *.pcap; do tshark -r $f -Y "!tcp.port in {22,23,25,80,443,445,993,995,8000..8005} or not dns" -w strangeports-$f; done
mergecap -w 3.allSTRANGE.pcapng strangeports-*
rm strangeports-*

for f in *.pcap; do tshark -r $f -Y "tcp.port==3389" -w RDP-$f; done
mergecap -w 4.allRDP.pcapng RDP-*
rm RDP-*

for f in *.pcap; do tshark -r $f -Y "tls.handshake.version < 0x0303" -w TLSVer-$f; done
mergecap -w 5.allTLSVer1.pcapng TLSVer-*
rm TLSVer-*

for f in *.pcap; do tshark -r $f -Y "tcp.flags.syn==1 and tcp.flags.ack==0 and tcp.window_size<=1024" -w nmap-$f; done
mergecap -w 6.allNMAP.pcapng nmap-*
rm nmap-*

for f in *.pcap; do tshark -r $f -Y "ip.geoip.country_iso in {CN,RU,NK}" -w country-$f; done
mergecap -w 7.allBADCN.pcapng country-*
rm country-*

for f in *.pcap; do tshark -r $f -Y "arp.duplicate-address-frame" -w arp-$f; done
mergecap -w 8.allARP-P.pcapng arp-*
rm arp-*


# Continue PCAP investigation summary, listing all derived PCAP files, including hashes
echo Derived PCAP Files: >> $report
echo $lineBreak >> $report
for f in *.pcapng; do md5sum $f >> $report; done

# Output HTTP User Agents to a investigation summary
echo $lineBreak >> $report
echo HTTP User Agents: >> $report
echo $lineBreak >> $report
for f in *.pcap; do tshark -r *.pcap -Y http.request -T fields -e http.host -e http.user_agent | sort | uniq -c | sort -n >> $report; done