#!/usr/bin/env python3
import json,pathlib,sys
p=pathlib.Path(sys.argv[1]);data=json.loads(p.read_text())
failed=[r for r in data if not r['pass']]
print(f'{len(data)-len(failed)} GUI checks passed, {len(failed)} failed')
for row in failed:print(row['test'])
raise SystemExit(bool(failed))
