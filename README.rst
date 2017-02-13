
Parse PCAP file and output selected protocol to a text file.
Support BGP and OpenFlow.

Output fields for BGP: timestamp, src_ip, dst_ip, proto, type, nlri, withdraw
Output fields for OpenFlow: timestamp, src_ip, dst_ip, proto, type, xtra_info
(i.e. flowmod match, and actions)

run with --h to see options
