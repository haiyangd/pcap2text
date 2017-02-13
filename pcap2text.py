#!/usr/bin/env python

# Extract timestamp and related information of packets from pcap file to a text file
# Supported BGP (type, and some info), and OpenFlow (type, info), UDP and TCP (header only).

from scapy.all import *
import sys, os
import collections
import numpy as np
import ipaddr
import struct

from oslo_config import cfg

CONF = cfg.CONF

CONF.register_cli_opt(
        cfg.StrOpt('file',
                   help='path to pcap file'))
CONF.register_cli_opt(
        cfg.StrOpt('proto',
                   help='type of protocol to extract timestamp of' \
                   '. Supported: BGP, OpenFlow, UDP and TCP'))
CONF.register_cli_opt(
        cfg.IntOpt('port',
                   help='TCP/UDP port to interpret the protocol'))

class OpenFlowHdr(Packet):
    name = "OpenFlowHeader"
    fields_desc = [ ByteField("version", '0x04'),
                    ByteField("type", None),
                    ShortField('len', None)]

def extract_ts_bgp(eth_pkt, port=179):

    def format_prefix(prefix): # tuple (24, '192.168.10.0')
        prefixlen, subnet = prefix
        return "%s/%s" % (subnet, prefixlen)

    info_line = '{ts};{src_ip};{dst_ip};{proto};{type_};{nlri};{withdraw}'
    ret = {}
    ip_pkt = eth_pkt.payload
    tcp_pkt = ip_pkt.payload
    if (tcp_pkt.sport == port or tcp_pkt.dport == port):
        if tcp_pkt.flags == 24: #TCP PUSH
            tcp_pkt.decode_payload_as(BGPHeader)
            bgp_pkt = tcp_pkt.payload
            type_ = None
            nlri = []
            withdraw = []
            attrs = []
            if bgp_pkt.type == 2: #UPDATE
                type_ = 'UPDATE'
                bgp_update = bgp_pkt.payload
                withdraw = bgp_update.withdrawn
                withdraw = str([format_prefix(p) for p in withdraw]).translate(None, "'")
                nlri = bgp_update.nlri
                nlri = str([format_prefix(p) for p in nlri]).translate(None, "'")
                attrs_ = bgp_update.total_path
                for attr in attrs_:
                    if attr.type == 2: #AS_PATH
                        pass
            else:
                type_ = bgp_pkt.type

            ret = {'ts':'%f' % eth_pkt.time, 'src_ip': ip_pkt.src,
                    'dst_ip': ip_pkt.dst, 'proto': 'BGP',
                    'type_': type_, 'nlri': nlri, 'withdraw': withdraw}
    if ret:
        print info_line.format(**ret)
    return ret

def decode_of_pkt(raw_payload):
    version, = struct.unpack('!B', raw_payload[:1])
    type_, = struct.unpack('!B', raw_payload[1:2])
    len_, = struct.unpack('!H', raw_payload[2:4])
    tcp_pkt = TCP()
    if version in ofp_version and type_ in ofp_type:
        tcp_pkt.add_payload(raw_payload[:len_])
        tcp_pkt.decode_payload_as(ofpt_cls[type_])
        of_pkt = tcp_pkt.payload
        return (tcp_pkt.payload, raw_payload[len_:])
    return (None, [])

def parse_of_pkt(of_pkt):
    """
    of_pkt (e.g. OFPTFlowMod)
    """
    proto = ofp_version[of_pkt.version]
    type_ = ofp_type[of_pkt.type]
    xid = of_pkt.xid
    info = {'proto': proto, 'type_': type_, 'xid': of_pkt.xid, 'xtra_info': ''}
    if of_pkt.type == 14: #FlowMod
        xtra_info = ''
        cmd = of_pkt.cmd
        if cmd == 0:
            xtra_info = 'ADD,'
        elif cmd == 1:
            xtra_info = 'MODIFY,'
        elif cmd == 2:
            xtra_info = 'MODIFY_STRICT,'
        elif cmd == 3:
            xtra_info = 'DELETE,'
        elif cmd == 4:
            xtra_info = 'DELETE_STRICT,'
        else:
            xtra_info = 'Unknown command,'
        if OFPMatch in of_pkt:
            for name, cls in [
                    ('eth_src', OFBEthSrc),
                    ('eth_dst', OFBEthDst),
                    ('vlan_vid', OFBVLANVID),
                    ('mpls_label', OFBMPLSLabel),
                    ('ipv4_src', OFBIPv4Src),
                    ('ipv4_dst', OFBIPv4Dst),
                    ('ipv4_dst', OFBIPv4DstHM),
                    ('ipv6_src', OFBIPv6Src),
                    ('ipv6_dst', OFBIPv6Dst),
                    ('ipv6_dst', OFBIPv6DstHM)]:
                if cls in of_pkt:
                    xtra_info += name + '=' + str(of_pkt[cls].getfieldval(name))
                    try:
                        mask = of_pkt[cls].getfieldval('ipv4_dst_mask')
                        mask = ipaddr.IPAddress(mask)
                        mask = ipaddr.IPNetwork(
                                '0.0.0.0/%s' % str(mask)).prefixlen
                        xtra_info += '/%s' % mask
                    except Exception as e:
                        pass
                    xtra_info += ','
        for inst in of_pkt.instructions:
            if inst.type == 4: # Apply actions
                xtra_info += 'actions='
                for action in inst.actions:
                    if action.__class__.__name__ == 'OFPATSetField':
                        xtra_info += 'set '
                        for name, cls in [
                                ('eth_src', OFBEthSrc),
                                ('eth_dst', OFBEthDst)]:
                            if cls in action:
                                xtra_info += name + '=' + str(
                                        action[cls].getfieldval(name)) + ','
        info['xtra_info'] = xtra_info

    return info

def extract_ts_openflow(eth_pkt, port=6633):
    info_line = '{ts};{src_ip};{dst_ip};{proto};{type_};{xid};{xtra_info}'
    ip_pkt = eth_pkt.payload
    tcp_pkt = ip_pkt.payload
    info = {}
    if tcp_pkt.sport == port or tcp_pkt.dport == port:
        if tcp_pkt.flags == 24: #TCP PUSH
            #print tcp_pkt.payload.__class__.__name__
            tcp_pkt.decode_payload_as(Raw)
            raw_payload = tcp_pkt.payload.load
            of_pkt = {}
            while of_pkt is not None and len(raw_payload) > 0:
                of_pkt, raw_payload = decode_of_pkt(raw_payload)
                if of_pkt:
                    info = {'ts': '%f' % eth_pkt.time,
                            'src_ip': ip_pkt.src,
                            'dst_ip': ip_pkt.dst}
                    info.update(parse_of_pkt(of_pkt))
                    print info_line.format(**info)

def extract_packets(pcap, func, **args):

    for eth_pkt in pcap:
        if eth_pkt.type != 2048: # No an IP
            continue
        if not (eth_pkt.payload.proto == 6): # Not a TCP
            continue
        func(eth_pkt, **args)

if __name__ == "__main__":
    CONF(args=sys.argv[1:])
    filename = CONF.file
    if not filename:
        print "run with -h to see options"
        sys.exit(1)
    pcap = PcapReader(filename)
    port = None
    if CONF.proto == 'bgp':
        load_contrib('bgp')
        func = extract_ts_bgp
        port = 179
    elif CONF.proto == 'openflow':
        load_contrib('openflow3')
        #from scapy.contrib.openflow3 import *
        func = extract_ts_openflow
        port = 6633
    if CONF.port:
        port = CONF.port
    extract_packets(pcap, func, port=port)
