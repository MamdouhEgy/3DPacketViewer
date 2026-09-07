#!/usr/bin/env python3
"""Synthetic traffic construction only. Never used by the analyzer to interpret packets."""
import argparse, importlib.util, json, pathlib, struct
ROOT=pathlib.Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('base',ROOT/'tools/make_fixtures.py');base=importlib.util.module_from_spec(spec);spec.loader.exec_module(base)
class Conversation:
    def __init__(self,port):self.port=port;self.seq=[1000,2000];self.frames=[]
    def add(self,data=b'',reverse=False,ms=0,flags=0x18,sequence=None):
        k=int(reverse);src=bytes.fromhex('c0000202' if reverse else 'c0000201');dst=bytes.fromhex('c0000201' if reverse else 'c0000202')
        h=struct.pack('!HHIIBBHHH',self.port if reverse else 40000,40000 if reverse else self.port,self.seq[k] if sequence is None else sequence,self.seq[1-k],0x50,flags,4096,0,0)
        check=base.checksum(src+dst+b'\x00\x06'+struct.pack('!H',len(h)+len(data))+h+data);h=h[:16]+struct.pack('!H',check)+h[18:]+data
        ip=struct.pack('!BBHHHBBH',0x45,0,20+len(h),len(self.frames)+1,0x4000,64,6,0)+src+dst;ip=ip[:10]+struct.pack('!H',base.checksum(ip))+ip[12:]
        mac=bytes.fromhex('020000000001020000000002' if reverse else '020000000002020000000001')
        self.frames.append((ms,mac+b'\x08\x00'+ip+h))
        if sequence is None:self.seq[k]+=len(data)+(1 if flags&3 else 0)
    def handshake(self):self.add(ms=0,flags=2);self.add(reverse=True,ms=1,flags=0x12);self.add(ms=2,flags=0x10)
def iec(cot=6,tx=0,rx=0,value=1,ioa=1007,typ=45):
    asdu=bytes([typ,1,cot,0,2,0])+ioa.to_bytes(3,'little')+(struct.pack('<f',value)+b'\0' if typ==13 else bytes([value]))
    return b'\x68'+bytes([len(asdu)+4])+struct.pack('<HH',tx*2,rx*2)+asdu
def goose(st,sq,mac='020000000001',conf=1):
    tlv=base.tlv;body=tlv(0x61,b''.join([tlv(0x80,b'SYNTHETIC/LLN0$GO$gcb'),tlv(0x81,b'\x03\xe8'),tlv(0x82,b'SYNTHETIC/dataset'),tlv(0x83,b'go-test'),tlv(0x84,b'\0'*8),tlv(0x85,st.to_bytes(4,'big')),tlv(0x86,sq.to_bytes(4,'big')),tlv(0x87,b'\0'),tlv(0x88,bytes([conf])),tlv(0x89,b'\0'),tlv(0x8a,b'\1'),tlv(0xab,tlv(0x83,b'\1'))]))
    return bytes.fromhex('010ccd010001'+mac+'88b8')+struct.pack('!HHHH',0x1000,len(body)+8,0,0)+body
def rgoose(pdus,spdu=1):
    # Synthetic R-GOOSE over CLTP/UDP, following the pinned dissector's decoded
    # framing. This is not an authentication/conformance test or a packet parser.
    payload=b''.join(struct.pack('!BBHH',0x81,0,appid,len(body))+body for appid,body in pdus)
    session=bytes.fromhex('a1178015')+struct.pack('!IIH',len(payload)+21,spdu,1)+b'\0'*11
    data=b'\x01\x40'+session+struct.pack('!I',len(payload))+payload
    src=bytes.fromhex('c0000201');dst=bytes.fromhex('e8000001')
    udp=struct.pack('!HHHH',40000,102,8+len(data),0)+data
    ip=struct.pack('!BBHHHBBH',0x45,0,20+len(udp),spdu,0x4000,64,17,0)+src+dst
    ip=ip[:10]+struct.pack('!H',base.checksum(ip))+ip[12:]
    return bytes.fromhex('01005e0000010200000000010800')+ip+udp
def sv(count,conf=1):
    tlv=base.tlv;asdu=tlv(0x80,b'SYNTHETIC-MU')+tlv(0x82,count.to_bytes(2,'big'))+tlv(0x83,conf.to_bytes(4,'big'))+tlv(0x85,b'\2')+tlv(0x87,struct.pack('!iI',2312,0))
    body=tlv(0x60,tlv(0x80,b'\1')+tlv(0xa2,tlv(0x30,asdu)))
    return bytes.fromhex('010ccd04000102000000000188ba')+struct.pack('!HHHH',0x4000,len(body)+8,0,0)+body
def fixtures():
    all=[]
    def add(name,frames,link=1,note=''):all.append(dict(name=name,linktype=link,origin='Deterministic synthetic construction; documentation addresses; not evidence of a real attack.',note=note,frames=[dict(ms=t,hex=b.hex(' ')) for t,b in frames]))
    c=Conversation(2404);c.handshake();c.add(bytes.fromhex('680407000000'),ms=10);c.add(bytes.fromhex('68040b000000'),True,20);c.add(iec(),ms=100);c.add(iec(7,0,1),True,124);c.add(iec(10,1,1),True,142)
    for i,v in enumerate([101.2,102.1,150.4,151.0]):c.add(iec(3,i+2,1,v,1007,13),True,1000+i*1000)
    add('iec104_normal_temporal',c.frames,note='STARTDT, command frames 6/7/8 (42 ms), float measurements frames 9–12; synthetic abrupt shift with valid sequencing. No unit or attack verdict implied.')
    for name,mode in [('iec104_boundary',0),('iec104_missing_confirmation',1),('iec104_missing_termination',2),('iec104_sequence',3)]:
        c=Conversation(2404);c.handshake();c.add(iec(),ms=100)
        if mode==1:c.add(iec(10,0,1),True,142)
        if mode==2:c.add(iec(7,0,1),True,124);c.add(ms=6000,flags=0x10)
        if mode==3:c.add(iec(3,12,1,150.4,1007,13),True,1000);c.add(iec(3,14,1,151.,1007,13),True,2000)
        add(name,c.frames)
    c=Conversation(2404);c.handshake();message=iec();c.add(message[:7],ms=100);c.add(message[7:],ms=101);c.add(iec(7,0,1),True,124);c.add(iec(10,1,1),True,142);add('iec104_segmented',c.frames)
    c=Conversation(2404);c.handshake();seq=c.seq[0];c.add(iec(),ms=100);c.add(iec(),ms=101,sequence=seq);c.add(iec(7,0,1),True,124);c.add(iec(10,1,1),True,142);add('iec104_retransmission',c.frames)
    c=Conversation(2404);c.handshake();c.add(iec(3,32767,0,101.,1007,13),True,100);c.add(iec(3,0,0,102.,1007,13),True,200);add('iec104_wrap',c.frames)
    c=Conversation(2404);c.handshake();c.add(iec(3,0,0,101.,1007,13)+iec(3,1,0,202.,1008,13),True,100);add('iec104_multi_pdu',c.frames)
    c=Conversation(2404);c.handshake();asdu=bytes([13,0x82,3,0,2,0])+int(1007).to_bytes(3,'little')+struct.pack('<fBfB',101.,0,202.,0);message=b'\x68'+bytes([len(asdu)+4])+b'\0'*4+asdu;c.add(message,True,100);add('iec104_sequence_objects',c.frames,note='SQ=1, two IOAs. Wireshark derives the second IOA; analyzer never increments a raw address itself.')
    for name,values in [('iec104_drift',[100.+i*.2 for i in range(20)]),('iec104_small_bias',[100.+(i%4)*.01+(i//4)*.1 for i in range(20)])]:
        c=Conversation(2404);c.handshake()
        for i,v in enumerate(values):c.add(iec(3,i,0,v,1007,13),True,100+i*1000)
        add(name,c.frames,note='Synthetic temporal evolution. No assertion of malicious intent or physical engineering units.')
    add('goose_normal',[(0,goose(42,0)),(100,goose(42,1)),(200,goose(43,0))])
    add('goose_regression',[(0,goose(54,0)),(100,goose(17,0))])
    add('goose_duplicate_publisher',[(0,goose(54,0)),(100,goose(54,1,'020000000009')),(200,goose(54,2))])
    add('sv_gap',[(0,sv(1)),(.25,sv(2)),(.75,sv(4))]);add('sv_wrap',[(0,sv(3999)),(.25,sv(0)),(.5,sv(1))])
    c=Conversation(502);c.handshake();request=bytes.fromhex('123400000006010600050009');c.add(request,ms=100);c.add(request,True,115);add('modbus_write',c.frames)
    c=Conversation(502);c.handshake();c.add(bytes.fromhex('123400000006010300000002'),ms=100);c.add(bytes.fromhex('12340000000701030400010002'),True,115);add('modbus_read',c.frames)
    # Upper-PDU exported MMS with explicit IPv4 endpoint TLVs, no invented OSI handshake.
    def mms(data,reverse=False):
        src=bytes.fromhex('c0000202' if reverse else 'c0000201');dst=bytes.fromhex('c0000201' if reverse else 'c0000202')
        return struct.pack('!HH',12,4)+b'mms\0'+struct.pack('!HH',20,4)+src+struct.pack('!HH',21,4)+dst+b'\0'*4+bytes.fromhex(data)
    add('mms_identify',[(0,mms('a0050201018200')),(10,mms('a11c020101a217800453594e548106535350412d548207302e312e302020',True))],252,note='Synthetic confirmed identify exchange; valid ASN.1 lengths checked by Wireshark.')
    def dnp(app,reverse=False):
        transport=b'\xc0';data=transport+app;h=bytes.fromhex('0564')+bytes([5+len(data),0x44 if reverse else 0xc4])+struct.pack('<HH',1024 if reverse else 1,1 if reverse else 1024)
        return h+base.dnp_crc(h)+data+base.dnp_crc(data)
    c=Conversation(20000);c.handshake();c.add(dnp(bytes.fromhex('c0013c0206')),ms=100);c.add(dnp(bytes.fromhex('c0810000'),True),True,120);add('dnp3_read',c.frames)
    add('rgoose_normal',[(0,rgoose([(0x1000,goose(42,0)[22:])])),(100,rgoose([(0x1000,goose(42,1)[22:])],2)),(200,rgoose([(0x1000,goose(43,0)[22:])],3))],note='Synthetic unprotected CLTP/UDP routed GOOSE; publisher semantics only, no cryptographic verification.')
    add('rgoose_regression',[(0,rgoose([(0x1000,goose(54,0)[22:])])),(100,rgoose([(0x1000,goose(17,0)[22:])],2))])
    add('rgoose_multi_pdu',[(0,rgoose([(0x1000,goose(42,0)[22:]),(0x2000,goose(17,3)[22:])]))],note='Two independent APPIDs in one datagram; no flattening or cross-publisher correlation.')
    return all
def main():
    p=argparse.ArgumentParser();p.add_argument('--output',type=pathlib.Path,default=ROOT/'build-semantic-fixtures');p.add_argument('--write-source',action='store_true');a=p.parse_args();items=fixtures();source=ROOT/'semantic/tests/fixtures/packets.json'
    if a.write_source:source.write_text(json.dumps(items,indent=2)+'\n')
    elif json.loads(source.read_text())!=items:raise SystemExit('Checked-in fixture source differs')
    a.output.mkdir(parents=True,exist_ok=True)
    for item in items:
        out=struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,262144,item['linktype'])
        for f in item['frames']:
            b=bytes.fromhex(f['hex']);us=round(f['ms']*1000);out+=struct.pack('<IIII',1700000000+us//1000000,us%1000000,len(b),len(b))+b
        (a.output/(item['name']+'.pcap')).write_bytes(out)
if __name__=='__main__':main()
