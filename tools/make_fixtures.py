#!/usr/bin/env python3
"""Construct synthetic test traffic; no packet parsing or dissection occurs here."""
import json
import pathlib
import struct
import argparse
ROOT = pathlib.Path(__file__).resolve().parents[1]

def checksum(data):
    data += b'\0' * (len(data) % 2)
    n = sum(struct.unpack('!' + 'H' * (len(data)//2), data))
    while n >> 16:
        n = (n & 65535) + (n >> 16)
    return (~n) & 65535

def eth(data, kind=0x0800):
    return bytes.fromhex('020000000002020000000001') + struct.pack('!H', kind) + data

def ip(data, protocol=6, options=b'', fragment=0, ident=1):
    h = struct.pack('!BBHHHBBH4s4s', 0x45+len(options)//4,0,20+len(options)+len(data),ident,fragment,64,protocol,0,b'\xc0\x00\x02\x01',b'\xc0\x00\x02\x02')+options
    return h[:10]+struct.pack('!H',checksum(h))+h[12:]+data

def tcp(data=b'',port=80,seq=1,options=b'',flags=0x18):
    h=struct.pack('!HHIIBBHHH',40000,port,seq,0,(5+len(options)//4)<<4,flags,4096,0,0)+options
    pseudo=bytes.fromhex('c0000201c00002020006')+struct.pack('!H',len(h)+len(data))
    h=h[:16]+struct.pack('!H',checksum(pseudo+h+data))+h[18:]
    return h+data

def udp(data=b'ABCD'):
    return struct.pack('!HHHH',40000,40001,8+len(data),0)+data

def tlv(tag, value):
    n=len(value)
    length=bytes([n]) if n<128 else bytes([0x82])+struct.pack('!H',n)
    return bytes([tag])+length+value

def dnp_crc(data):
    value=0
    for byte in data:
        value ^= byte
        for _ in range(8):
            value=(value>>1)^0xa6bc if value&1 else value>>1
    return struct.pack('<H',value^0xffff)

def fixtures():
    items=[]
    def add(name, frames, protocols, linktype=1, reported=None, note=''):
        items.append(dict(name=name,linktype=linktype,protocols=protocols,origin='Hand-constructed synthetic bytes by tools/make_fixtures.py; documentation addresses only.',note=note,
                          frames=[dict(hex=b.hex(' '),reported=(reported[i] if reported else len(b))) for i,b in enumerate(frames)]))
    add('ethernet_ipv4_tcp',[eth(ip(tcp(flags=2)))],['eth','ip','tcp'])
    add('ethernet_ipv4_udp',[eth(ip(udp(),17))],['eth','ip','udp'])
    arp=bytes.fromhex('0001080006040001 020000000001 c0000201 000000000000 c0000202')
    add('arp',[eth(arp,0x0806)],['eth','arp'])
    icmp=bytes.fromhex('0800000012340001')+b'PING';icmp=icmp[:2]+struct.pack('!H',checksum(icmp))+icmp[4:]
    add('icmp',[eth(ip(icmp,1))],['eth','ip','icmp'])
    add('vlan',[eth(bytes.fromhex('a0640800')+ip(udp(),17),0x8100)],['eth','vlan','ip','udp'])
    v6=bytes.fromhex('60000000')+struct.pack('!HBB',12,17,64)+bytes.fromhex('20010db8000000000000000000000001 20010db8000000000000000000000002')+udp()
    add('ipv6',[eth(v6,0x86dd)],['eth','ipv6','udp'],note='UDP checksum intentionally zero to exercise Wireshark expert reporting in IPv6.')
    add('tcp_options',[eth(ip(tcp(options=bytes.fromhex('020405b401030307'),flags=2)))],['eth','ip','tcp'])
    add('ipv4_options',[eth(ip(udp(),17,options=bytes.fromhex('01010000')))],['eth','ip','udp'])
    add('bit_fields',[eth(ip(tcp(flags=0x12),fragment=0x4000))],['eth','ip','tcp'])
    full=eth(ip(tcp()));add('truncated',[full[:30]],['eth','ip'],reported=[len(full)])
    malformed=bytearray(full);malformed[14]=0x41;add('malformed',[bytes(malformed)],['eth','ip'],note='IPv4 header length 1 is deliberately invalid.')
    modbus=bytes.fromhex('123400000006010300000002')
    add('modbus',[eth(ip(tcp(modbus,502)))],['eth','ip','tcp','mbtcp','modbus'])
    iec=bytes.fromhex('680e0000000001010300010001000001')
    add('iec104',[eth(ip(tcp(iec,2404)))],['eth','ip','tcp','iec60870_104','iec60870_asdu'])
    add('tcp_reassembly',[eth(ip(tcp(modbus[:8],502,1))),eth(ip(tcp(modbus[8:],502,9),ident=2))],['eth','ip','tcp','mbtcp','modbus'],note='Modbus message split at byte 8; application PDU is a separate reassembled data source on frame 2.')
    datagram=udp(b'0123456789abcdef');add('ip_reassembly',[eth(ip(datagram[:16],17,fragment=0x2000,ident=42)),eth(ip(datagram[16:],17,fragment=2,ident=42))],['eth','ip','udp'],note='Two IPv4 fragments; last fragment has reassembled IP data source.')
    goose=b''.join([tlv(0x80,b'LD0/LLN0$GO$gcb'),tlv(0x81,b'\x03\xe8'),tlv(0x82,b'LD0/LLN0$ds'),tlv(0x83,b'go1'),tlv(0x84,b'\0'*8),tlv(0x85,b'\1'),tlv(0x86,b'\1'),tlv(0x87,b'\0'),tlv(0x88,b'\1'),tlv(0x89,b'\0'),tlv(0x8a,b'\1'),tlv(0xab,tlv(0x83,b'\x01'))])
    goose=tlv(0x61,goose);add('goose',[eth(struct.pack('!HHHH',0x1000,len(goose)+8,0,0)+goose,0x88b8)],['eth','goose'])
    asdu=b''.join([tlv(0x80,b'MU01'),tlv(0x82,b'\0\1'),tlv(0x83,b'\0\0\0\1'),tlv(0x85,b'\x02'),tlv(0x87,b'\0'*8)])
    sv=tlv(0x60,tlv(0x80,b'\1')+tlv(0xa2,tlv(0x30,asdu)))
    add('sampled_values',[eth(struct.pack('!HHHH',0x4000,len(sv)+8,0,0)+sv,0x88ba)],['eth','sv'])
    # Wireshark Exported PDU: tag 12 is dissector name, padded to 4 bytes, then end tag.
    mms=struct.pack('!HH',12,4)+b'mms\0'+b'\0'*4+bytes.fromhex('a0050201018200')
    add('mms',[mms],['mms'],linktype=252,note='Synthetic Wireshark Upper PDU encapsulation: MMS Confirmed-Request identify, invokeID=1. Tests MMS generically without inventing an OSI connection handshake.')
    header=bytes.fromhex('056405c001000004');dnp=header+dnp_crc(header)
    add('dnp3',[eth(ip(tcp(dnp,20000)))],['eth','ip','tcp','dnp3'],note='DNP3 link-layer reset request, destination 1, source 1024, valid link-header CRC; no application data.')
    many=tlv(0x61,tlv(0x80,b'LD0/LLN0$GO$bench')+tlv(0x81,b'\x03\xe8')+tlv(0x82,b'bench')+tlv(0x84,b'\0'*8)+tlv(0x85,b'\1')+tlv(0x86,b'\1')+tlv(0x87,b'\0')+tlv(0x88,b'\1')+tlv(0x89,b'\0')+tlv(0x8a,b'\x02\x00')+tlv(0xab,tlv(0x83,b'\1')*512))
    add('goose_many_fields',[eth(struct.pack('!HHHH',0x1001,len(many)+8,0,0)+many,0x88b8)],['eth','goose'],note='512 synthetic Boolean dataset members; reproducible complex-packet benchmark.')
    add('zero_length',[b''],[],reported=[0],note='Zero captured and reported bytes.')
    return items

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--output',type=pathlib.Path,default=ROOT/'build-fixtures');parser.add_argument('--write-source',action='store_true');a=parser.parse_args()
    a.output.mkdir(parents=True,exist_ok=True)
    data=fixtures()
    if a.write_source:
        (ROOT/'tests/fixtures/packets.json').write_text(json.dumps(data,indent=2)+'\n')
    else:
        checked=json.loads((ROOT/'tests/fixtures/packets.json').read_text())
        if checked!=data: raise SystemExit('Source fixtures differ from generator')
    for item in data:
        pcap=struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,262144,item['linktype'])
        for i,f in enumerate(item['frames']):
            raw=bytes.fromhex(f['hex']);pcap+=struct.pack('<IIII',1700000000+i,0,len(raw),f['reported'])+raw
        (a.output/(item['name']+'.pcap')).write_bytes(pcap)
if __name__=='__main__': main()
