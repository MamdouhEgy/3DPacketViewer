#!/usr/bin/env python3
"""Integration oracle plus independently specified fixture locations; fails on disagreements."""
import argparse, json, pathlib, subprocess, math, time, csv
ROOT=pathlib.Path(__file__).resolve().parents[3]
p=argparse.ArgumentParser();p.add_argument('--analyzer',type=pathlib.Path,required=True);p.add_argument('--tshark',type=pathlib.Path,required=True);p.add_argument('--fixtures',type=pathlib.Path,required=True);p.add_argument('--output',type=pathlib.Path,required=True);a=p.parse_args();a.output.mkdir(parents=True,exist_ok=True)
checks=[];reports={};bench=[]
def check(name,condition):checks.append(dict(test=name,passed=bool(condition)))
for path in sorted(a.fixtures.glob('*.pcap')):
    dest=a.output/(path.stem+'.json');start=time.perf_counter();r=subprocess.run([str(a.analyzer),str(path),str(dest)],capture_output=True);elapsed=(time.perf_counter()-start)*1000
    check(path.stem+' capture analysis process',r.returncode==0)
    if r.returncode:continue
    d=json.loads(dest.read_text());reports[path.stem]=d;check(path.stem+' decoded events',bool(d['events']));check(path.stem+' no malformed decoded fixture',not any(e['malformed'] for e in d['events']))
    check(path.stem+' every semantic value has field provenance',all(v['provenance'] for e in d['events'] for v in e['values'].values()))
    check(path.stem+' no raw packet data in outbound context',all(s not in json.dumps(d['semantic_context']) for s in ('192.0.2.', 'raw_bytes', 'payload','SYNTHETIC/','SYNTHETIC-MU')))
    bench.append(dict(fixture=path.stem,frames=d['capture_frames'],events=len(d['events']),total_process_ms=round(elapsed,3)))
def rules(name):return [f['rule'] for f in reports[name]['findings']]
n=reports['iec104_normal_temporal'];control=[t for t in n['transactions'] if t['state']=='COMMAND_TERMINATED'];check('IEC104 control frames / latency',len(control)==1 and control[0]['frames']==[6,7,8] and control[0]['latency_ms']==42)
check('IEC104 normal has no findings',not n['findings']);measurements=[e for e in n['events'] if e['event_type']=='MEASUREMENT'];check('four IEC104 measurement values',len(measurements)==4 and all(math.isclose(e['values']['value']['value'],v,abs_tol=.0001) for e,v in zip(measurements,[101.2,102.1,150.4,151.])))
check('IEC104 capture end is boundary limited',reports['iec104_boundary']['transactions'][0]['completion']=='INCOMPLETE_CAPTURE_BOUNDARY' and not rules('iec104_boundary'))
check('IEC104 missing confirmation', 'IEC104_TERMINATION_WITHOUT_CONFIRMATION' in rules('iec104_missing_confirmation') and reports['iec104_missing_confirmation']['transactions'][0]['completion']=='INCOMPLETE_UNKNOWN')
check('IEC104 missing termination deadline', 'IEC104_MISSING_ACTIVATION_TERMINATION' in rules('iec104_missing_termination'))
check('IEC104 sequence discontinuity','IEC104_TX_SEQUENCE_DISCONTINUITY' in rules('iec104_sequence'));check('IEC104 modulo wrap',not rules('iec104_wrap'))

for fixture in ['iec104_multi_pdu','iec104_sequence_objects']:
    measurements=[e for e in reports[fixture]['events'] if e['event_type']=='MEASUREMENT']
    check(fixture+' preserves two IOAs and values',[(e['values']['ioa']['value'],e['values']['value']['value']) for e in measurements]==[(1007,101),(1008,202)])
check('Wireshark-generated second IOA retains provenance',any(v['generated'] for e in reports['iec104_sequence_objects']['events'] if e.get('values',{}).get('ioa',{}).get('value')==1008 for v in e['values']['ioa']['provenance']))
check('IEC104 segmentation','COMMAND_TERMINATED' in [t['state'] for t in reports['iec104_segmented']['transactions']]);check('IEC104 retransmission not duplicated',len(reports['iec104_retransmission']['transactions'])==1)
check('GOOSE normal progression',not rules('goose_normal'));check('GOOSE regression','GOOSE_STNUM_REGRESSION' in rules('goose_regression'));check('GOOSE publisher identity change','GOOSE_PUBLISHER_IDENTITY_CHANGE' in rules('goose_duplicate_publisher'));check('SV missing sample counter','SV_SAMPLE_COUNTER_DISCONTINUITY' in rules('sv_gap'))
for name in ['mms_identify','modbus_write','modbus_read','dnp3_read']:check(name+' request-response correlation',len(reports[name]['transactions'])==1 and reports[name]['transactions'][0]['completion']=='COMPLETE')
for name in ['sv_wrap','iec104_normal_temporal','modbus_write']:
    dest=a.output/(name+'-policy.json');r=subprocess.run([str(a.analyzer),str(a.fixtures/(name+'.pcap')),str(dest),str(ROOT/'semantic/tests/fixtures/policy.json')],capture_output=True);check(name+' policy process',r.returncode==0)
    if r.returncode:continue
    d=json.loads(dest.read_text());rs=[f['rule'] for f in d['findings']]
    check(name+' configured policy',not rs if name=='sv_wrap' else any('SOURCE' in x for x in rs))
# Manually derived from Ethernet14 + IPv4 20 + TCP20 + APCI6 + ASDU fixed6.
truth=[('iec104_normal_temporal',6,'IEC104','iec60870_asdu.typeid',60,1,45),('iec104_normal_temporal',6,'IEC104','iec60870_asdu.causetx',62,1,6),('iec104_normal_temporal',6,'IEC104','iec60870_asdu.addr',64,2,2),('iec104_normal_temporal',6,'IEC104','iec60870_asdu.ioa',66,3,1007),('iec104_normal_temporal',9,'IEC104','iec60870_asdu.float',69,4,101.2),('modbus_write',4,'MODBUS','mbtcp.trans_id',54,2,4660),('modbus_write',4,'MODBUS','modbus.func_code',61,1,6)]
rows=[]
for fixture,frame,protocol,field,start,length,value in truth:
    found=[(e,v,ref) for e in reports[fixture]['events'] if e['frame']==frame for v in e['values'].values() for ref in v['provenance'] if ref['field']==field]
    ok=bool(found) and all(ref['byte_offset']==start and ref['byte_length']==length and math.isclose(v['value'],value,abs_tol=.0001) for e,v,ref in found if isinstance(v['value'],(int,float)) and ref['field']==field and v['value'] not in (False,True))
    # Locate actual field's native value, excluding classifications derived from the same provenance.
    ok=ok and any(isinstance(v['value'],(int,float)) and math.isclose(v['value'],value,abs_tol=.0001) for e,v,ref in found)
    check(f'{fixture}:{frame}:{field} independent wire location',ok)
    ref=found[0][2] if found else {};rows.append(dict(fixture=fixture,frame=frame,protocol=protocol,field=field,expected_start=start,expected_length=length,extracted_start=ref.get('byte_offset'),extracted_length=ref.get('byte_length'),data_source=ref.get('source'),result='PASS' if ok else 'FAIL'))
    r=subprocess.run([str(a.tshark),'-r',str(a.fixtures/(fixture+'.pcap')),'-Y',f'frame.number == {frame}','-T','fields','-e',field],capture_output=True,text=True)
    try:oracle=float(r.stdout.strip().split(',')[0]);agree=math.isclose(oracle,value,abs_tol=.001)
    except ValueError:agree=False
    check(f'{fixture}:{frame}:{field} tshark agreement',r.returncode==0 and agree)
with (a.output/'wire-validation.csv').open('w') as f:w=csv.DictWriter(f,fieldnames=rows[0].keys(),lineterminator="\n");w.writeheader();w.writerows(rows)
(a.output/'results.json').write_text(json.dumps(checks,indent=2)+'\n');(a.output/'benchmark.json').write_text(json.dumps(bench,indent=2)+'\n')
print('Integration:',sum(c['passed'] for c in checks),'passed,',sum(not c['passed'] for c in checks),'failed')
for c in checks:
    if not c['passed']:print('FAIL:',c['test'])
raise SystemExit(any(not c['passed'] for c in checks))
