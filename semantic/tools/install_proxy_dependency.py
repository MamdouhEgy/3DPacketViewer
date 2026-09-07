#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Install the validated libproxy dependency only into the existing Linux user bundle."""
import argparse
import pathlib
import re
import shlex
import shutil
import subprocess
import tempfile

REVISION = '99da01926b1b1e303a4d2331bbd74bed424863e7'
parser = argparse.ArgumentParser()
parser.add_argument('--source', type=pathlib.Path, required=True)
parser.add_argument('--stage', type=pathlib.Path, required=True)
parser.add_argument('--prefix', type=pathlib.Path, required=True)
parser.add_argument('--launcher', type=pathlib.Path, required=True)
args = parser.parse_args()
revision = subprocess.check_output(['git', '-C', str(args.source), 'rev-parse', 'HEAD'], text=True).strip()
changed = subprocess.check_output(['git', '-C', str(args.source), 'status', '--porcelain', '--untracked-files=no'], text=True)
if revision != REVISION or changed:
    raise SystemExit('An unmodified pinned libproxy 0.5.12 checkout is required')
if not (args.prefix / 'SEMANTIC-ANALYZER-INSTALLATION.txt').exists():
    raise SystemExit('Existing semantic analyzer user bundle required')
launcher = args.launcher.read_text()
original_launcher = launcher
if str(args.prefix / 'bin/wireshark') not in launcher:
    raise SystemExit('Launcher does not belong to the selected bundle')


def cmake_quote(value):
    delimiter = '='
    while ']' + delimiter + ']' in value:
        delimiter += '='
    return '[' + delimiter + '[' + value + ']' + delimiter + ']'


for relative, rpath in [('lib/libproxy.so.1', '$ORIGIN/libproxy'),
                        ('lib/libproxy/libpxbackend-1.0.so', '$ORIGIN')]:
    destination = args.prefix / relative
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name('.' + destination.name + '.new')
    shutil.copy2(args.stage / relative, temporary)
    info = subprocess.check_output(['readelf', '-d', str(temporary)], text=True)
    old = re.search(r'\((?:RUNPATH|RPATH)\).*?\[(.*?)\]', info)
    if not old:
        raise SystemExit('Expected staged library RPATH')
    with tempfile.TemporaryDirectory(prefix='sspa-proxy-install-') as directory:
        script = pathlib.Path(directory) / 'relocate.cmake'
        script.write_text('file(RPATH_CHANGE FILE ' + cmake_quote(str(temporary))
                          + ' OLD_RPATH ' + cmake_quote(old[1]) + ' NEW_RPATH '
                          + cmake_quote(rpath) + ')\n')
        subprocess.run(['cmake', '-P', str(script)], check=True)
    temporary.replace(destination)

# The system Qt Network library must find the bundle's proxy dependency transitively.
# Do not change system libraries or bypass the configured proxy.
line = 'export LD_LIBRARY_PATH=' + shlex.quote(str(args.prefix / 'lib')) + '${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}'
if line not in launcher:
    launcher = launcher.replace('\nexec ', '\n' + line + '\nexec ', 1)
# Preserve explicitly supplied isolated profiles used by the GUI validation runner.
if 'if [ -z "${WIRESHARK_CONFIG_DIR:-}" ]' not in launcher:
    launcher = re.sub(r'(?m)^export WIRESHARK_CONFIG_DIR=.*$',
                      lambda match: 'if [ -z "${WIRESHARK_CONFIG_DIR:-}" ]; then\n' + match[0] + '\nfi', launcher)
if launcher != original_launcher:
    temporary = args.launcher.with_name('.' + args.launcher.name + '.new')
    temporary.write_text(launcher)
    temporary.chmod(args.launcher.stat().st_mode)
    temporary.replace(args.launcher)
share = args.prefix / 'share/semantic-analyzer/dependencies/libproxy'
share.mkdir(parents=True, exist_ok=True)
shutil.copy2(args.source / 'COPYING', share / 'COPYING')
(share / 'SOURCE.txt').write_text('libproxy 0.5.12\nhttps://github.com/libproxy/libproxy\n'
                               + REVISION + '\nUnmodified upstream source; LGPL-2.1-or-later.\n')
print('Installed libproxy 0.5.12 in user bundle; system libraries unchanged.')
