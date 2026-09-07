#!/usr/bin/env python3
"""Link this independent repository through Wireshark's custom plugin extension."""
import argparse
import pathlib
import subprocess
p = argparse.ArgumentParser()
p.add_argument('wireshark', type=pathlib.Path)
a = p.parse_args()
root = pathlib.Path(__file__).resolve().parents[1]
ws = a.wireshark.resolve()
expected = (root/'cmake/wireshark-revision.txt').read_text().strip()
actual = subprocess.check_output(['git', '-C', str(ws), 'rev-parse', 'HEAD'], text=True).strip()
if actual != expected:
    raise SystemExit(f'Revision mismatch: expected {expected}, detected {actual}')
link = ws/'plugins/ui/3dpacketviewer'
if link.is_symlink():
    if link.resolve() != root:
        raise SystemExit(f'Refusing to replace unrelated link: {link}')
elif link.exists():
    raise SystemExit(f'Refusing to replace existing directory: {link}')
else:
    link.symlink_to(root, target_is_directory=True)
print('Configure Wireshark with -DCUSTOM_PLUGIN_SRC_DIR=ui/3dpacketviewer')
