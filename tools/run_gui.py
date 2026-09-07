#!/usr/bin/env python3
"""Run the opt-in GUI driver against synthetic fixtures; enforce process and test results."""
import argparse,json,os,pathlib,subprocess
p=argparse.ArgumentParser()
p.add_argument('--wireshark',type=pathlib.Path,required=True)
p.add_argument('--fixtures',type=pathlib.Path,required=True)
p.add_argument('--output',type=pathlib.Path,required=True)
p.add_argument('--no-session-bus',action='store_true',help='Isolate desktop DBus services; does not suppress sanitizer diagnostics')
a=p.parse_args();a.output.mkdir(parents=True,exist_ok=True)
config=a.output/'config';config.mkdir(exist_ok=True)
fixture=a.fixtures.resolve();results=fixture/'gui-results.json';results.unlink(missing_ok=True)
env={**os.environ,'QT_QPA_PLATFORM':'xcb','WIRESHARK_CONFIG_DIR':str(config.resolve()),'PACKETVIEWER_TEST_DIR':str(fixture),
     'ASAN_OPTIONS':'detect_leaks=1','UBSAN_OPTIONS':'halt_on_error=1'}
if a.no_session_bus:
    env['DBUS_SESSION_BUS_ADDRESS']='unix:path='+str((a.output/'no-session-bus').resolve())
    env['QT_QPA_PLATFORMTHEME']='generic'
    env['QT_STYLE_OVERRIDE']='Fusion'
    env['NO_AT_BRIDGE']='1'
with (a.output/'gui.log').open('w') as log:
    process=subprocess.run([str(a.wireshark.resolve())],env=env,stdout=log,stderr=subprocess.STDOUT,timeout=90)
data=json.loads(results.read_text()) if results.exists() else []
(a.output/'gui-results.json').write_text(json.dumps(data,indent=2)+'\n')
(a.output/'gui-process.json').write_text(json.dumps({'exit_code':process.returncode,'checks':len(data),'failed':sum(not r['pass'] for r in data)},indent=2)+'\n')
if (fixture/'viewer.png').exists():(a.output/'viewer.png').write_bytes((fixture/'viewer.png').read_bytes())
print('Exit:',process.returncode,'GUI checks:',len(data),'failed:',sum(not r['pass'] for r in data))
for row in data:
    if not row['pass']:print(row['test'])
raise SystemExit(process.returncode!=0 or not data or any(not row['pass'] for row in data))
