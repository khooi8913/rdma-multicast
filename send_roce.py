#!/usr/bin/python3

from scapy.all import *


class RETH(Packet):
    name = "RETH"
    fields_desc = [
            BitField("v_addr", 0, 64),
            BitField("r_key", 0, 32),
            BitField("dma_len", 0, 32)
            ]

class BTH(Packet):
    name = "BTH"
    fields_desc = [
        BitField("opcode", 0, 8),
        BitField("solicited", 0, 1),
        BitField("migreq", 0, 1),
        BitField("padcount", 0, 2),
        BitField("version", 0, 4),
        XShortField("pkey", 0xffff),
        BitField("fecn", 0, 1),
        BitField("becn", 0, 1),
        BitField("resv6", 0, 6),
        BitField("dqpn", 0, 24),
        BitField("ackreq", 0, 1),
        BitField("resv7", 0, 7),
        BitField("psn", 0, 24)
    ]

class ICRC(Packet):
    name = "ICRC"
    fields_desc = [
        BitField("icrc", 0, 32)
    ]

eth = Ether(src='b8:ce:f6:04:6b:d0', dst='b8:ce:f6:04:6c:05')
ip = IP(src='10.10.10.1', dst='10.10.10.255', ihl=5, len=76, frag=0, flags=2, ttl=64)
udp = UDP(sport=59000, dport=4791, len=56, chksum=0)
bth = BTH(opcode=10, solicited=0, migreq=1, padcount=0, version=0, pkey=65535, fecn=0, becn=0, resv6=0, dqpn=399, ackreq=1, resv7=0, psn=3515407)
reth = RETH(v_addr=93882802875152, r_key=394756, dma_len=16)
raw = bytes("lala", "utf-8") + b'\x00' * 12
icrc = ICRC(icrc=0)

pkt = eth/ip/udp/bth/reth/raw/icrc
sendp(pkt, iface='ens2f0')
print(len(pkt))
# print(pkt)
print(pkt.show())