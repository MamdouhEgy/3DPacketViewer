#!/usr/bin/env python3
"""Validate known locations independently, then compare metadata with tshark PDML."""
import argparse
import json
import os
import pathlib
import subprocess
import xml.etree.ElementTree as ET
ROOT=pathlib.Path(__file__).resolve().parents[2]
p=argparse.ArgumentParser();p.add_argument('--bin',type=pathlib.Path,required=True);p.add_argument('--fixtures',type=pathlib.Path,required=True);p.add_argument('--output',type=pathlib.Path,required=True);a=p.parse_args()
a.output.mkdir(parents=True,exist_ok=True)
config=a.output/'config';config.mkdir(exist_ok=True)
env={**os.environ,'WIRESHARK_CONFIG_DIR':str(config.resolve())}
results=[];models={};oracle={}
def check(name,condition,detail=''):
    results.append(dict(test=name,pass_=bool(condition),detail=detail))
for fixture in json.loads((ROOT/'tests/fixtures/packets.json').read_text()):
    name=fixture['name'];output=a.output/(name+'.json');capture=a.fixtures/(name+'.pcap')
    subprocess.run([str(a.bin/'packetviewer_extract'),str(capture),str(output)],check=True,env=env)
    ms=json.loads(output.read_text());models[name]=ms
    pdml=subprocess.check_output([str(a.bin/'tshark'),'-r',str(capture),'-T','pdml'],env=env)
    oracle[name]=ET.fromstring(pdml).findall('packet')
    found={f['abbr'] for m in ms for f in m['fields']}
    check(name+': dissectors',set(fixture['protocols'])<=found,','.join(fixture['protocols']))
    for i,m in enumerate(ms):
        label=f'{name}/{i+1}'
        raw=bytes.fromhex(fixture['frames'][i]['hex'])
        check(label+': captured/report lengths',m['captured']==len(raw) and m['reported']==fixture['frames'][i]['reported'])
        current=[s for s in m['sources'] if s['current']]
        check(label+': bytes unchanged',any(bytes.fromhex(s['hex'])==raw for s in current) or not raw)
        check(label+': hierarchy',all(f['id']==idx and -1<=f['parent']<idx for idx,f in enumerate(m['fields'])))
        check(label+': generated geometry',all(not f['ranges'] and not f['wire'] for f in m['fields'] if f['generated']))
        check(label+': provenance',all(not f['wire'] for f in m['fields'] if f['source']>=0 and not m['sources'][f['source']]['current']))
        bounds=True
        for f in m['fields']:
            for start,length in f['ranges']:
                bounds &= f['source']>=0 and 0<=start<start+length<=m['sources'][f['source']]['captured']*8
        check(label+': range bounds',bounds)
        canonical=True
        for source,s in enumerate(m['sources']):
            pos=0
            for tile in [t for t in m['tiles'] if t['source']==source]:
                canonical &= tile['start']==pos and tile['length']>0
                pos+=tile['length']
                if tile['field']>=0:
                    f=m['fields'][tile['field']]
                    canonical &= not f['generated'] and any(tile['start']>=r[0] and tile['start']+tile['length']<=sum(r) for r in f['ranges'])
            canonical &= pos==s['captured']*8
        check(label+': canonical partition',canonical)
        pdfields=oracle[name][i].findall('.//field')
        agreement=True;compared=0
        for f in m['fields']:
            if f['generated'] or f['hidden'] or f['source']<0:continue
            if not m['sources'][f['source']]['current']:continue
            matches=[o for o in pdfields if o.get('name')==f['abbr'] and o.get('pos') is not None and o.get('size') is not None]
            if not matches:continue
            compared+=1
            agreement &= any(int(o.get('pos','-1'))==f['start'] and int(o.get('size','-1'))==f['length'] for o in matches)
        check(label+': tshark byte-range oracle',agreement,f'{compared} fields compared; PDML provides no mask occupancy oracle')
rows=[]
for expected in json.loads((ROOT/'tests/fixtures/ground_truth.json').read_text()):
    m=models[expected['fixture']][expected['frame']-1]
    candidates=[f for f in m['fields'] if f['abbr']==expected['field'] and f['start']==expected['byte']]
    f=candidates[0] if candidates else {}
    passed=f.get('start')==expected['byte'] and f.get('length')==expected['length'] and f.get('ranges')==expected['ranges'] and f.get('source')==expected['source']
    check('ground truth: '+expected['fixture']+'/'+expected['field'],passed,str(f) if not passed else '')
    rows.append([expected['fixture'],expected['frame'],f.get('protocol','MISSING'),expected['field'],expected['byte'],expected['length'],expected['ranges'],f.get('start','MISSING'),f.get('length','MISSING'),f.get('ranges','MISSING'),f.get('source','MISSING'),'PASS' if passed else 'FAIL'])
for fixture,abbr in [('tcp_reassembly','mbtcp.trans_id'),('ip_reassembly','udp.srcport')]:
    fields=[f for f in models[fixture][-1]['fields'] if f['abbr']==abbr]
    check(fixture+': explicit reassembly',bool(fields) and all(f['derived'] and not f['wire'] and f['source']>0 for f in fields))
(a.output/'results.json').write_text(json.dumps(results,indent=2)+'\n')
headers=['Fixture','Frame','Protocol','Field','Expected byte','Expected length','Expected bit [start,length]','Extracted byte','Extracted length','Extracted bits','Source','Result']
(a.output/'ground-truth.md').write_text('| '+' | '.join(headers)+' |\n|'+'|'.join(['---']*len(headers))+'|\n'+''.join('| '+' | '.join(str(v) for v in row)+' |\n' for row in rows))
failed=[r for r in results if not r['pass_']]
print(f'{len(results)-len(failed)} passed, {len(failed)} failed')
for r in failed:print(r)
raise SystemExit(bool(failed))
