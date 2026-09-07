#!/usr/bin/env python3
"""Run opt-in synthetic GUI checks with a private profile and desktop-service isolation."""
import argparse
import json
import os
import pathlib
import subprocess
import sys

parser = argparse.ArgumentParser()
parser.add_argument('--wireshark', type=pathlib.Path, required=True)
parser.add_argument('--fixtures', type=pathlib.Path, required=True)
parser.add_argument('--output', type=pathlib.Path, required=True)
parser.add_argument('--live-ai', action='store_true')
args = parser.parse_args()
args.output.mkdir(parents=True, exist_ok=True)
config = args.output / 'profile'
config.mkdir(exist_ok=True)
env = {**os.environ, 'QT_QPA_PLATFORM': 'xcb', 'WIRESHARK_CONFIG_DIR': str(config.resolve()),
       'SSPA_TEST_DIR': str(args.fixtures.resolve()),
       'DBUS_SESSION_BUS_ADDRESS': 'unix:path=' + str((args.output / 'no-bus').resolve()),
       'QT_QPA_PLATFORMTHEME': 'generic', 'QT_STYLE_OVERRIDE': 'Fusion', 'NO_AT_BRIDGE': '1',
       'ASAN_OPTIONS': 'detect_leaks=1', 'UBSAN_OPTIONS': 'halt_on_error=1'}
for key in ('PACKETVIEWER_TEST_DIR', 'OPENCODE_API_KEY', 'SSPA_AI_TEST'):
    env.pop(key, None)
settings = None
if args.live_ai:
    import termios
    settings = termios.tcgetattr(sys.stdin.fileno())
    hidden = settings.copy()
    hidden[3] &= ~termios.ECHO
    termios.tcsetattr(sys.stdin.fileno(), termios.TCSANOW, hidden)
    env['SSPA_AI_TEST'] = '1'
    print('Session credential input ready (echo disabled).', flush=True)
result = args.fixtures / 'gui-results.json'
result.unlink(missing_ok=True)
try:
    with (args.output / 'gui.log').open('w') as log:
        process = subprocess.run([str(args.wireshark.resolve())], env=env, stdout=log,
                                 stderr=subprocess.STDOUT, timeout=180 if args.live_ai else 90)
finally:
    if settings is not None:
        termios.tcsetattr(sys.stdin.fileno(), termios.TCSANOW, settings)
data = json.loads(result.read_text()) if result.exists() else []
report = dict(exit_code=process.returncode, checks=len(data), failed=sum(not x['pass'] for x in data))
(args.output / 'process.json').write_text(json.dumps(report, indent=2) + '\n')
(args.output / 'gui-results.json').write_text(json.dumps(data, indent=2) + '\n')
print(report)
for check in data:
    if not check['pass']:
        print('FAIL:', check['test'])
raise SystemExit(process.returncode != 0 or not data or any(not x['pass'] for x in data))
