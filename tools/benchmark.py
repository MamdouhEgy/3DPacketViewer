#!/usr/bin/env python3
"""Summarize actual extraction and geometry timings, excluding process startup."""
import argparse,json,pathlib,statistics
p=argparse.ArgumentParser();p.add_argument('models',type=pathlib.Path);a=p.parse_args()
frames=[]
for path in a.models.glob('*.json'):
    data=json.loads(path.read_text())
    if isinstance(data,list):frames += [f for f in data if isinstance(f,dict) and 'extraction_ms' in f]
if not frames:raise SystemExit('No extracted frame measurements')
print('Frames:',len(frames))
for key in ['extraction_ms','geometry_ms']:
    values=sorted(f[key] for f in frames)
    print(key,'median',round(statistics.median(values),3),'max',round(max(values),3),'ms')
print('Fields: maximum',max(len(f['fields']) for f in frames))
print('Tiles: maximum',max(len(f['tiles']) for f in frames))
