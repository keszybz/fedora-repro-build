#!/usr/bin/python
# SPDX-License-Identifier: LGPL-2.1-or-later

import dataclasses
import functools
import json
import re
import sys
from pathlib import Path
from pprint import pprint

@dataclasses.dataclass
class State:
    rpmname: str

    src_metadata: int = 0
    static_library: int = 0
    jar_library: int = 0
    mingw_binary: int = 0
    debuginfo_metadata: int = 0
    debuginfo_hash: int = 0
    javadoc_html: int = 0
    doc_pdf: int = 0

    rpm_metadata: list[str] = dataclasses.field(default_factory=list)
    payload_paths: list[str] = dataclasses.field(default_factory=list)
    payload_mods: list[str] = dataclasses.field(default_factory=list)

    unknown: list[str] = dataclasses.field(default_factory=list)

    def report(self):
        print(f'    {self.rpmname}')
        for attr in ('src_metadata',
                     'static_library',
                     'jar_library',
                     'mingw_binary',
                     'debuginfo_metadata',
                     'debuginfo_hash',
                     'javadoc_html',
                     'doc_pdf'):
            val = getattr(self, attr)
            if val > 0:
                print(f"        {attr}{'×' if val > 1 else ''}{val if val > 1 else ''}")

        for attr in ('rpm_metadata',
                     'payload_paths',
                     'payload_mods',
                     'unknown'):
            items = getattr(self, attr)
            for item in items:
                print(f"        {' '.join(item)}")

def parse_rpmdiff(rpmname, diff):
    state = State(rpmname)

    for line in filter(None, diff.split('\n')):
        words = line.split()
        arch = rpmname.split('.')[-1]
        debuginfo_rpm = '-debuginfo-' in rpmname
        mingw_rpm = rpmname.startswith(('mingw32', 'mingw64')) and arch == 'noarch'

        match words:
            # added REQUIRES openmpi-devel
            # added PROVIDES valgrind-openmpi = 1:3.22.0-6.fc40
            # S.5..... DESCRIPTION
            case 'added'|'removed', 'PROVIDES'|'REQUIRES', *rest:
                if arch == 'src':
                    state.src_metadata += 1
                elif rest[0] == 'debuginfo(build-id)':
                    state.debuginfo_metadata += 1
                else:
                    state.rpm_metadata += [words]

            case 'added'|'removed', path if path.startswith('/'):
                # removed /usr/lib/debug/.build-id/0a
                # removed /usr/lib/debug/.build-id/0a/6ad914018fdfc80d9779ecf4eab3831b3d46e3
                # removed /usr/lib/debug/.build-id/0a/6ad914018fdfc80d9779ecf4eab3831b3d46e3.debug
                if arch != 'noarch' and path.startswith('/usr/lib/debug/.build-id/'):
                    state.debuginfo_hash += 1
                # added   /usr/lib/.build-id/16
                # added   /usr/lib/.build-id/16/c477e990217761a5944eab433215c8462dba57
                # removed /usr/lib/.build-id/e5
                # removed /usr/lib/.build-id/e5/1adc1cdedcb75b7874c3dbae1fae14c11dc9f8
                elif arch != 'noarch' and not debuginfo_rpm and path.startswith('/usr/lib/.build-id/'):
                    state.debuginfo_hash += 1
                else:
                    state.payload_paths += [(words[0], path)]

            case word, path if set(word) < set('SM5DNLVUGFT.') and path.startswith('/'):
                size_mod = 'S' in word[0]
                hash_mod = '5' in word[2]
                other_mod = set(word) > set('S5.')

                if other_mod:
                    state.payload_mods += [(f'modified-{word}', path)]

                # S.5........ /usr/lib64/ghc-9.4.5/lib/Agda-2.6.4.1/libHSAgda-2.6.4.1-AfpHgXgK1wA2nVrbniet8k.a
                elif path.endswith('.a'):
                    state.static_library += 1
                elif path.endswith(('.jar', '.war')):
                    state.jar_library += 1
                # S.5........ /usr/share/maven-metadata/xmlunit-xmlunit-matchers.xml
                # ..5........ /usr/share/maven-metadata/xmvn-connector-ivy.xml
                # If the jar differs, the manifest will also differ, but not in size.
                elif not size_mod and re.match(r'/usr/share/maven-metadata/.*\.xml', path):
                    state.jar_library += 1
                elif re.match(r'/usr/share/javadoc/.*\.html', path):
                    state.javadoc_html += 1
                elif re.match(r'/usr/share/doc/.*\.pdf', path):
                    state.doc_pdf += 1
                # ..5........ /usr/lib/debug/usr/lib64/.../algos.cpython-312-x86_64-linux-gnu.so-2.2.1-1.fc41.x86_64.debug
                elif (debuginfo_rpm and
                      (path.endswith('.debug') or
                       path.startswith('/usr/lib/debug/.dwz/'))):
                    state.debuginfo_hash += 1
                elif (mingw_rpm and
                      path.endswith(('.exe', '.dll'))):
                    state.mingw_binary += 1
                else:
                    state.payload_mods += [(f'modified-{word}', path)]

            case _:
                state.unknown += [words]

    return state

def read_input(filename):
    f = filename.open('r')
    data = json.load(f)

    data2 = {k:parse_rpmdiff(k, v) for k,v in data.items()}
    return data2

if __name__ == '__main__':
    for filename in sys.argv[1:]:
        p = Path(filename)
        data = read_input(p)

        print(f'#################### {filename} ####################')

        for diff in data.values():
            diff.report()
