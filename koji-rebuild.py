# https://kojipkgs.fedoraproject.org//packages/systemd/254/1.fc39/data/logs/x86_64/root.log

import argparse
import dataclasses
import functools
import platform
import re
import shlex
import subprocess
import sys
import textwrap
import tempfile
import types
from pathlib import Path

import requests
import koji

CACHE_DIR = Path('./cache')
KOJI_URL = 'https://kojipkgs.fedoraproject.org/'

def listify(func):
    def wrapper(*args, **kwargs):
        return list(func(*args, **kwargs))
    return functools.update_wrapper(wrapper, func)

KOJI, SESSION = None, None
def init_koji_session(opts):
    global KOJI, SESSION
    if not SESSION:
        KOJI = koji.get_profile_module(opts.koji_profile)
        session_opts = KOJI.grab_session_options(KOJI.config)
        SESSION = KOJI.ClientSession(KOJI.config.server, session_opts)

def do_opts():
    parser = argparse.ArgumentParser()
    parser.add_argument('--koji-profile', default='koji')

    opts = parser.parse_args()
    return opts

@listify
def extract_log_installed_rpms(file):
    if isinstance(file, Path):
        file = file.open('rt')

    in_installed = False
    for line in file:
        # if 'Installed' in line:
        #    breakpoint()
        line = line.rstrip()
        if re.match(r'DEBUG util.py:\d+:\s+Installed:', line):
            in_installed = True
            continue
        if not in_installed:
            continue
        if re.match(r'DEBUG util.py:\d+:\s+Complete!', line):
            in_installed = False
            continue
        if not (m := re.match(r'DEBUG util.py:\d+:(\s+([-a-zA-Z0-9:._^~+]+))+$', line)):
            print(f'Failed to match: {line!r}')
            raise ValueError

        for s in m.group(1).split():
            rpm = RPM.from_string(s)
            yield rpm

@dataclasses.dataclass(frozen=True)
class RPM:
    name: str
    version: str
    release: str
    arch: str = None
    epoch: int = None
    build_id: int = None

    @classmethod
    @functools.lru_cache(maxsize=None)
    def from_string(cls, s):
        # 'valgrind-1:3.21.0-8.fc39.x86_64'
        parts = s.split('-')
        *nn, version, suffix = parts
        name = '-'.join(nn)

        if m := re.match(r'(\d+):(.*)', version):
            epoch, version = m.groups()
            epoch = int(epoch)
        else:
            epoch = None

        if '.' in suffix:
            release, arch = suffix.rsplit('.', maxsplit=1)
        else:
            release, arch = suffix, None

        return cls(name=name, version=version, release=release, arch=arch, epoch=epoch)

    @functools.cached_property
    def koji_id(self):
        dd = dict(name=self.name, version=self.version, release=self.release)
        if self.arch:
            dd['arch'] = self.arch
        return dd

    @functools.cached_property
    def canonical(self):
        return (f'{self.name}-{self.version}-{self.release}' +
                (f'.{self.arch}' if self.arch else ''))

    @functools.cached_property
    def without_arch(self):
        # like self, but with arch stripped
        if not self.arch:
            return self
        return self.__class__(name=self.name,
                              version=self.version,
                              release=self.release,
                              epoch=self.epoch)

@functools.lru_cache(maxsize=None)
def rpm_info(rpm):
    # It seems koji has no notion of epoch :(
    # Let's hope nobody ever builds the same n-v-r with different e

    # https://koji.fedoraproject.org/koji/api says:
    # - a map containing 'name', 'version', 'release', and 'arch'
    #   (and optionally 'location')
    # I have no idea what 'location' is.
    return SESSION.getRPM(rpm.koji_id, strict=True)

@functools.lru_cache(maxsize=None)
def build_info(ident):
    if not isinstance(ident, int):
        ident = ident.koji_id
    return SESSION.getBuild(ident, strict=True)
    
def koji_rpm_url(package):
    # 'valgrind-devel-1:3.21.0-8.fc39.x86_64'
    # https://kojipkgs.fedoraproject.org//packages/valgrind/3.21.0/8.fc39/x86_64/valgrind-3.21.0-8.fc39.x86_64.rpm
    # https://kojipkgs.fedoraproject.org//packages/valgrind/3.21.0/8.fc39/src/valgrind-3.21.0-8.fc39.src.rpm
    if not (build_id := package.build_id):
        rpm = rpm_info(package)
        build_id = rpm['build_id']

    build = build_info(build_id)

    return '/'.join((KOJI_URL,
                     'packages',
                     build['name'],
                     build['version'],
                     build['release'],
                     rpm['arch'],
                     f"{package.canonical}.rpm"))

def koji_log_url(package, name, arch):
    build = build_info(package)
    logs = SESSION.getBuildLogs(build['build_id'])
    for entry in logs:
        if entry['name'] == name and entry['dir'] == arch:
            return '/'.join((KOJI_URL, entry['path']))

def get_local_package_filename(package, fname, url_generator, *details):
    path = CACHE_DIR / 'rpms' / package.without_arch.canonical / fname

    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        url = url_generator(package, *details)
        print(f'Downloading {url} to {path}')
        req = requests.get(url, allow_redirects=True)
        req.raise_for_status()
        path.write_bytes(req.content)

    return path

def get_koji_log(package, name, arch):
    assert name.endswith('.log')
    return get_local_package_filename(package, f'{arch}-{name}', koji_log_url, name, arch)

def get_buildroot_listing(package, arch):
    build = build_info(package)
    list = SESSION.getBuildrootListing(build['build_id'])
    # [ {'arch': 'x86_64',
    #    'build_id': 553384,
    #    'epoch': None,
    #    'external_repo_id': 0,
    #    'external_repo_name': 'INTERNAL',
    #    'is_update': False,
    #    'name': 'binutils',
    #    'release': '18.fc22',
    #    'rpm_id': 5360316,
    #    'version': '2.24'},
    #    ...
    #  ]

    return [RPM(name=e['name'], version=e['version'], release=e['release'], arch=e['arch'],
                epoch=e['epoch'], build_id=e['build_id'])
            for e in list]

def get_installed_rpms_from_log(package, arch):
    log = get_koji_log(package, 'root.log', arch)
    return extract_log_installed_rpms(log)

def get_local_rpm_filename(rpm):
    return get_local_package_filename(rpm, f'{rpm.canonical}.rpm', koji_rpm_url)

def get_local_installed_rpms(rpms):
    return [get_local_rpm_filename(rpm) for rpm in rpms]

main_config = '''\
        [main]
        keepcache=1
        debuglevel=2
        reposdir=/dev/null
        logfile=/var/log/yum.log
        retries=20
        obsoletes=1
        gpgcheck=0
        assumeyes=1
        syslog_ident=mock
        syslog_device=
        install_weak_deps=0
        metadata_expire=0
        best=0
        module_platform_id=platform:f{{ releasever }}
        protected_packages=
        user_agent={{ user_agent }}

        {%- macro rawhide_gpg_keys() -%}
        file:///usr/share/distribution-gpg-keys/fedora/RPM-GPG-KEY-fedora-$releasever-primary
        {%- for version in [releasever|int, releasever|int - 1]
        %} file:///usr/share/distribution-gpg-keys/fedora/RPM-GPG-KEY-fedora-{{ version }}-primary
        {%- endfor %}
        {%- endmacro %}
        '''

def mock_config(arch, package_dir):
    if arch == 'noarch':
        arch = platform.machine()

    return textwrap.dedent(
        f'''\
        include('fedora-rawhide-{arch}.cfg')

        config_opts['use_bootstrap'] = False

        config_opts['dnf.conf'] = """
        {main_config}

        [local]
        reposdir=/dev/null
        name=local
        baseurl=file://{package_dir.absolute()}
        enabled=True
        skip_if_unavailable=False
        """
        ''')

def comps_config(rpms):
    pkgs = '\n              '.join(
        f'<packagereq type="default">{rpm.name}</packagereq>'
        for rpm in rpms)
    return textwrap.dedent(
        f'''\
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE comps
          PUBLIC '-//Red Hat, Inc.//DTD Comps info//EN'
          'comps.dtd'>
        <comps>
          <group>
            <id>buildsys-build</id>
            <name>build-sys</name>
            <description>Smallest possible installation v2</description>
            <default>true</default>
            <uservisible>true</uservisible>
            <packagelist>
              {pkgs}
            </packagelist>
          </group>
        </comps>
        ''')
        
def setup_buildroot(package, arch):
    # build_rpms = get_buildroot_listing(package, arch)
    build_rpms = get_installed_rpms_from_log(package, arch)

    rpms = get_local_installed_rpms(build_rpms)

    build_dir = CACHE_DIR / 'build' / package.without_arch.canonical

    repo_dir = build_dir / 'repo'
    repo_dir.mkdir(parents=True, exist_ok=True)
    for rpm in rpms:
        # Is there a way to make this less horrible in python?
        try:
            (repo_dir / rpm.name).symlink_to('../../../..' / rpm)
        except FileExistsError:
            pass

    comps = comps_config(build_rpms)
    compsfile = repo_dir / 'comps.xml'
    compsfile.write_text(comps)

    cmdline = [
        'createrepo_c',
        '-v',
        '-g', 'comps.xml',
        repo_dir,
    ]

    print(f"+ {' '.join(shlex.quote(str(s)) for s in cmdline)}")
    subprocess.check_call(cmdline)

    config = mock_config(arch, repo_dir)
    configfile = build_dir / 'mock.cfg'
    configfile.write_text(config)

    return configfile

def extract_header_field(filename, name):
    cmd = [
        'rpm',
        '-qp',
        '--qf', f'%{{{name}}}',
        filename,
    ]
    return subprocess.check_output(cmd, text=True)

def extract_config(filename):
    config = {name: extract_header_field(filename, name)
              for name in ('BUILDHOST',
                           'BUILDTIME',
                           'BUGURL',
                           'DISTRIBUTION',
                           'PACKAGER',
                           'VENDOR',
                           )}
    return config

def extract_srpm_name(rpm):
    field = extract_header_field(rpm, 'SOURCERPM')
    assert field.endswith('.src.rpm')
    return RPM.from_string(field[:-4])

def build_package(package, arch, *mock_opts):
    rpm = get_local_rpm_filename(package)
    config = extract_config(rpm)
    _srpm = extract_srpm_name(rpm)
    srpm = get_local_rpm_filename(_srpm)

    configfile = setup_buildroot(_srpm, arch)
    uniqueext = package.without_arch.canonical

    cmdline = [
        'mock',
        '-r', configfile,
        f'--uniqueext={uniqueext}',
        f"--define=_buildhost {config['BUILDHOST']}",
        f"--define=distribution {config['DISTRIBUTION']}",
        f"--define=packager {config['PACKAGER']}",
        f"--define=vendor {config['VENDOR']}",
        f"--define=bugurl {config['BUGURL']}",
        f"--without=tests",
        *mock_opts,
        srpm,
    ]

    print(f"+ {' '.join(shlex.quote(str(s)) for s in cmdline)}")
    subprocess.check_call(cmdline)

if __name__ == '__main__':
    opts = do_opts()
    init_koji_session(opts)

    package = RPM.from_string(sys.argv[1])
    build_package(package, package.arch)
