#!/usr/bin/env python3
"""Install into the existing pinned Linux user bundle; never overwrite distribution Wireshark."""
import argparse
import hashlib
import os
import pathlib
import re
import shutil
import subprocess
import tempfile

parser = argparse.ArgumentParser()
parser.add_argument('--prefix', type=pathlib.Path, required=True)
parser.add_argument('--module', type=pathlib.Path, required=True)
parser.add_argument('--fixtures', type=pathlib.Path, required=True)
args = parser.parse_args()
root = pathlib.Path(__file__).resolve().parents[2]
revision = (root / 'cmake/wireshark-revision.txt').read_text().strip()
marker = args.prefix / '3DPACKETVIEWER-INSTALLATION.txt'
if not marker.exists() or revision not in marker.read_text():
    raise SystemExit('This installer requires the existing verified 4.7.4 user bundle')
destination = args.prefix / 'lib/wireshark/plugins/4.7/ui/semantic_analyzer.so'
staged = destination.with_name('.semantic_analyzer.so.new')
shutil.copy2(args.module, staged)
subprocess.run(['strip', '--strip-unneeded', str(staged)], check=True)
info = subprocess.check_output(['readelf', '-d', str(staged)], text=True)
match = re.search(r'\((?:RUNPATH|RPATH)\).*?\[(.*?)\]', info)
if not match:
    raise SystemExit('Expected relocatable development module RPATH')
def cmake_quote(value):
    delimiter = '='
    while ']' + delimiter + ']' in value:
        delimiter += '='
    return '[' + delimiter + '[' + value + ']' + delimiter + ']'
with tempfile.TemporaryDirectory(prefix='sspa-install-') as temporary:
    script = pathlib.Path(temporary) / 'relocate.cmake'
    script.write_text('file(RPATH_CHANGE FILE ' + cmake_quote(str(staged)) + ' OLD_RPATH '
                      + cmake_quote(match[1]) + ' NEW_RPATH ' + cmake_quote('$ORIGIN/../../../..') + ')\n')
    subprocess.run(['cmake', '-P', str(script)], check=True)
linked = subprocess.check_output(['ldd', str(staged)], text=True)
if 'not found' in linked or '/tmp/' in linked:
    raise SystemExit('Installed dependency closure is incomplete or refers to a temporary build')
os.replace(staged, destination)
share = args.prefix / 'share/semantic-analyzer'
(share / 'examples').mkdir(parents=True, exist_ok=True)
for fixture in args.fixtures.glob('*.pcap'):
    shutil.copy2(fixture, share / 'examples' / fixture.name)
shutil.copytree(root / 'semantic/docs', share / 'docs', dirs_exist_ok=True)
shutil.copy2(root / 'semantic/README.md', share / 'README.md')
shutil.copy2(root / 'LICENSE', share / 'LICENSE')
commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip()
(args.prefix / 'SEMANTIC-ANALYZER-INSTALLATION.txt').write_text(
    'Stateful Semantic Protocol Analyzer 0.1.0\nWireshark 4.7.4 / ' + revision + '\n'
    + 'Project HEAD: ' + commit + '\nModule SHA256: ' + hashlib.sha256(destination.read_bytes()).hexdigest()
    + '\nOpen: Tools > Stateful Semantic Protocol Analyzer > Protocol Transactions\n'
    + 'AI disabled by default. Keys are session-only or OPENCODE_API_KEY.\n')
print('Installed:', destination)
print('Runtime dependencies resolved without temporary paths.')
