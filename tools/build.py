#!/usr/bin/env python3
"""Prepare the pinned upstream checkout, integrate, configure, and build."""
import argparse
import pathlib
import subprocess
ROOT=pathlib.Path(__file__).resolve().parents[1]
p=argparse.ArgumentParser()
p.add_argument('--wireshark',type=pathlib.Path,required=True)
p.add_argument('--build',type=pathlib.Path,required=True)
p.add_argument('--jobs',type=int,default=4)
p.add_argument('--debug',action='store_true')
p.add_argument('--sanitizers',action='store_true')
p.add_argument('--gui-tests',action='store_true')
p.add_argument('--configure-only',action='store_true')
p.add_argument('cmake_args',nargs='*')
a=p.parse_args()
revision=(ROOT/'cmake/wireshark-revision.txt').read_text().strip()
ws=a.wireshark.resolve()
def run(*args):subprocess.run([str(x) for x in args],check=True)
if not ws.exists():
    run('git','init',ws)
    run('git','-C',ws,'fetch','--depth=1','https://gitlab.com/wireshark/wireshark.git',revision)
    run('git','-C',ws,'checkout','--detach','FETCH_HEAD')
run('python3',ROOT/'tools/integrate.py',ws)
options=['-DCUSTOM_PLUGIN_SRC_DIR=ui/3dpacketviewer','-DCMAKE_BUILD_TYPE='+('Debug' if a.debug or a.sanitizers else 'RelWithDebInfo'),'-DBUILD_stratoshark=OFF']
if a.sanitizers:options+=['-DENABLE_ASAN=ON','-DENABLE_UBSAN=ON']
if a.gui_tests:options+=['-DPACKETVIEWER_GUI_TESTS=ON','-DSSPA_GUI_TESTS=ON']
run('cmake','-S',ws,'-B',a.build.resolve(),'-G','Ninja',*options,*a.cmake_args)
if not a.configure_only:run('cmake','--build',a.build.resolve(),'--parallel',a.jobs)
