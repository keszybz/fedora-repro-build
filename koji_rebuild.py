# https://kojipkgs.fedoraproject.org//packages/systemd/254/1.fc39/data/logs/x86_64/root.log

# pylint: disable=missing-docstring,invalid-name,consider-using-with,unspecified-encoding

import argparse
import dataclasses
import functools
import platform
import re
import shlex
import subprocess
import sys
import textwrap
from pathlib import Path

import requests
import koji

CACHE_DIR = Path('./cache')
KOJI_URL = 'https://kojipkgs.fedoraproject.org/'

def listify(func):
    def wrapper(*args, **kwargs):
        return list(func(*args, **kwargs))
    return functools.update_wrapper(wrapper, func)

def const(func):
    def wrapper(self):
        attrname = f'_{func.__name__}'
        if not (m := getattr(self, attrname)):
            m = func(self)
            setattr(self, attrname, m)
        return m
    return functools.update_wrapper(wrapper, func)

KOJI, SESSION = None, None
def init_koji_session(opts):
    # pylint: disable=global-statement
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

@functools.cache
@listify
def rpm_arch_list():
    for line in open('/usr/lib/rpm/rpmrc'):
        if m := re.match(r'arch_canon:\s+(\w+):.*', line.rstrip()):
            yield m.group(1)
    yield 'noarch'
    yield 'src'

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

@dataclasses.dataclass
class RPM:
    name: str
    version: str
    release: str
    epoch: int = None
    arch: str = None

    package: object = None
    build_id: int = None
    rpms: dict = dataclasses.field(default_factory=list)
    srpm: object = None

    @classmethod
    @functools.lru_cache(maxsize=None)
    def from_string(cls, s, epoch=None):
        # 'valgrind-1:3.21.0-8.fc39.x86_64'
        parts = s.split('-')
        *nn, version, suffix = parts
        name = '-'.join(nn)

        if m := re.match(r'(\d+):(.*)', version):
            ep, version = m.groups()
            ep = int(ep)
        else:
            ep = None

        if epoch is not None and ep is not None:
            raise ValueError('Epoch is specified twice')
        if ep is None:
            ep = epoch

        if '.' in suffix:
            release, arch = suffix.rsplit('.', maxsplit=1)

            # I don't think there's a reliable way to figure out if
            # arch is present without having a list of possible arches.
            if arch not in rpm_arch_list():
                release, arch = suffix, None
        else:
            release, arch = suffix, None

        return cls(name=name, version=version, release=release, arch=arch, epoch=ep)

    @functools.cached_property
    def koji_id(self):
        # pylint: disable=use-dict-literal
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

    def rpm_info(self):
        assert self.arch
        # It seems koji has no notion of epoch :(
        # Let's hope nobody ever builds the same n-v-r with different e

        # https://koji.fedoraproject.org/koji/api says:
        # - a map containing 'name', 'version', 'release', and 'arch'
        #   (and optionally 'location')
        # I have no idea what 'location' is.
        print(f'call: getRPM({self.koji_id}')
        return SESSION.getRPM(self.koji_id, strict=True)

    def build_info(self):
        return koji_build_info(self)

    def add_output(self, rpm, build_id=None):
        assert self.package is None
        assert self.arch is None
        assert rpm.package is None

        if rpm.arch == 'src':
            assert self.srpm is None
            self.srpm = rpm
        else:
            self.rpms += [rpm]
        rpm.package = self
        return rpm

    def add_output_from_string(self, name, build_id=None):
        rpm = self.from_string(name)
        assert rpm.arch
        return self.add_output(rpm)

    def some_rpm(self):
        assert self.package is None
        # Return first archful output, if any, otherwise first output
        for rpm in self.rpms:
            if rpm.arch != 'noarch':
                return rpm
        return self.rpms[0]

    def fill_in_package(self):
        assert not self.package

        rinfo = self.rpm_info()
        bid = rinfo['build_id']
        binfo = koji_build_info(bid)
        package = self.from_string(binfo['nvr'], epoch=binfo['epoch'])
        package.add_output(self)

    def local_filename(self):
        if not self.package:
            self.fill_in_package()
        return get_local_package_filename(self.package, f'{self.canonical}.rpm', self.koji_url)

    def koji_url(self):
        assert self.package
        # 'valgrind-devel-1:3.21.0-8.fc39.x86_64'
        # https://kojipkgs.fedoraproject.org//packages/valgrind/3.21.0/8.fc39/x86_64/valgrind-3.21.0-8.fc39.x86_64.rpm
        # https://kojipkgs.fedoraproject.org//packages/valgrind/3.21.0/8.fc39/src/valgrind-3.21.0-8.fc39.src.rpm
        return '/'.join((KOJI_URL,
                         'packages',
                         self.package.name,
                         self.package.version,
                         self.package.release,
                         self.arch,
                         f"{self.canonical}.rpm"))

_BUILD_INFO_CACHE = {}

def koji_build_info(ident):
    if isinstance(ident, int):
        key = ident
    else:
        key = ident.canonical
        ident = ident.koji_id
    if not (binfo := _BUILD_INFO_CACHE.get(key, None)):
        print(f'call: getBuild({ident}')
        binfo = SESSION.getBuild(ident, strict=True)
        _BUILD_INFO_CACHE[binfo['id']] = _BUILD_INFO_CACHE[binfo['nvr']] = binfo
    return binfo
    # XXX: nvr vs. nevr

def koji_log_url(package, name, arch):
    build = package.build_info()
    bid = build['build_id']
    print(f'call: getBuildLogs({bid})')
    logs = SESSION.getBuildLogs(bid)
    # pylint: disable=useless-else-on-loop
    for entry in logs:
        if entry['name'] == name and entry['dir'] == arch:
            return '/'.join((KOJI_URL, entry['path']))
    else:
        raise ValueError(f'{package}: build log {name}/{arch} not found')

def get_local_package_filename(package, fname, url_generator, *details):
    path = CACHE_DIR / 'rpms' / package.without_arch.canonical / fname

    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        url = url_generator(*details)
        print(f'Downloading {url} to {path}')
        req = requests.get(url, allow_redirects=True, timeout=60)
        req.raise_for_status()
        path.write_bytes(req.content)

    return path

def get_koji_log(package, name, arch):
    assert name.endswith('.log')
    return get_local_package_filename(package, f'{arch}-{name}', koji_log_url, package, name, arch)

def get_buildroot_listing(package, arch):
    build = package.build_info()
    bid = build['build_id']
    print(f'call: getBuildrootListing({bid})')
    lst = SESSION.getBuildrootListing(bid)
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
            for e in lst]

def get_installed_rpms_from_log(package, arch):
    log = get_koji_log(package, 'root.log', arch)
    return extract_log_installed_rpms(log)

def get_local_rpms(rpms):
    return [rpm.local_filename() for rpm in rpms]

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

    rpms = get_local_rpms(build_rpms)

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

def build_package(package, *mock_opts):
    rpm = package.some_rpm()   # we don't care which one is used
    rpm_file = rpm.local_filename()
    config = extract_config(rpm_file)
    srpm_file = package.srpm.local_filename()

    configfile = setup_buildroot(package, rpm.arch)
    uniqueext = package.canonical

    cmdline = [
        'mock',
        '-r', configfile,
        f"--uniqueext={uniqueext}",
        f"--define=_buildhost {config['BUILDHOST']}",
        f"--define=distribution {config['DISTRIBUTION']}",
        f"--define=packager {config['PACKAGER']}",
        f"--define=vendor {config['VENDOR']}",
        f"--define=bugurl {config['BUGURL']}",
        '--without=tests',
        *mock_opts,
        srpm_file,
    ]

    print(f"+ {' '.join(shlex.quote(str(s)) for s in cmdline)}")
    subprocess.check_call(cmdline)

def rebuild_package(package, *mock_opts, arch=None):
    arch_possibles = [arch] if arch else ['noarch', platform.machine()]

    build = package.build_info()

    tasks = SESSION.getTaskChildren(build['task_id'])
    for subtask in tasks:
        # find task with the right arch
        if (subtask['method'] == 'buildArch' and
            subtask['arch'] in arch_possibles):
            break
    else:
        raise ValueError(f"Cannot find buildArch task with arch={' or '.join(arch_possibles)}")

    # tags = SESSION.listTags(build['build_id'])

    # get a list of outputs:
    # ['mock_output.log', 'root.log', …,
    #  'python3-referencing-0.30.2-1.fc40.noarch.rpm',
    #  'python-referencing-0.30.2-1.fc40.src.rpm']
    outputs = SESSION.listTaskOutput(subtask['id'])

    have_rpm = False
    for output in outputs:
        if output.endswith('.rpm'):
            rpm = package.add_output_from_string(output[:-4], build_id=subtask['id'])
            if rpm.arch in arch_possibles:
                have_rpm = True
            if package.srpm and have_rpm:
                break
    else:
        raise ValueError(f'srpm and rpm output not found in {outputs!r}')

    return build_package(package)


def main(argv):
    opts = do_opts()
    init_koji_session(opts)

    package = RPM.from_string(argv[1])
    if package.arch:
        sys.exit('Sorry, specify build name, not rpm name')

    rebuild_package(package)

if __name__ == '__main__':
    main(sys.argv)
