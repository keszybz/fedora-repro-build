# https://kojipkgs.fedoraproject.org//packages/systemd/254/1.fc39/data/logs/x86_64/root.log

# pylint: disable=missing-docstring,invalid-name,consider-using-with,unspecified-encoding

import argparse
import collections
import dataclasses
import json
import functools
import platform
import pprint
import re
import shlex
import shutil
import subprocess
import sys
import textwrap
import typing
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

try:
    KOJI, SESSION  # pylint: disable=used-before-assignment
except NameError:
    KOJI, SESSION = None, None

def init_koji_session(opts):
    # pylint: disable=global-statement
    global KOJI, SESSION
    if not SESSION:
        KOJI = koji.get_profile_module(opts.koji_profile)
        session_opts = KOJI.grab_session_options(KOJI.config)
        SESSION = KOJI.ClientSession(KOJI.config.server, session_opts)

def do_opts(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('--koji-profile', default='koji')

    parser.add_argument('rpm')

    opts = parser.parse_args(argv)
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

    package: 'RPM' = None
    build_id: int = None
    rpms: dict = dataclasses.field(default_factory=list)
    srpm: 'RPM' = None

    @classmethod
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

    def with_arch(self, arch):
        if self.arch == arch:
            return self
        return self.__class__(name=self.name,
                              version=self.version,
                              release=self.release,
                              epoch=self.epoch,
                              arch=arch)

    @functools.cached_property
    def without_arch(self):
        # like self, but with arch stripped
        return self.with_arch(None)

    def build_dir(self):
        assert not self.package
        return CACHE_DIR / 'build' / self.canonical

    def rpm_info(self):
        assert self.arch
        return KojiRPMInfo.get(self)

    def build_info(self):
        return KojiBuildInfo.get(self)

    def add_output(self, rpm, build_id=None):
        assert self.package is None
        assert self.arch is None
        assert rpm.package is None

        if rpm.arch == 'src':
            # assert self.srpm is None
            # In noarch builds, srpm is created and listed in build outputs twice.
            self.srpm = rpm
        else:
            self.rpms += [rpm]
        rpm.package = self

        if rpm.build_id and build_id and rpm.build_id != build_id:
            raise ValueError(f'Differing build ids: {rpm.build_id=} {build_id=}')
        rpm.build_id = build_id

        return rpm

    def add_output_from_string(self, name, build_id=None):
        rpm = self.from_string(name)
        assert rpm.arch
        print(rpm)
        return self.add_output(rpm, build_id=build_id)

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
        binfo = KojiBuildInfo.get(rinfo['build_id'])
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

class DiskCache:
    name = None

    @classmethod
    def get(cls, ident):
        key = cls.identifier(ident)

        path = cls.path(key)
        try:
            f = path.open('r')
            return json.load(f)
        except FileNotFoundError:
            pass

        value = cls._get(key)

        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open('w') as f:
            json.dump(value, f)
        return value

    @staticmethod
    def identifier(key):
        if isinstance(key, RPM):
            return key.canonical
        return key

    @classmethod
    def path(cls, key) -> Path:
        return Path(f'cache/info/{cls.name}-{key}.txt')

    @classmethod
    def _get(cls, key):
        raise NotImplementedError

class KojiBuildInfo(DiskCache):
    name = 'build-info'

    @classmethod
    def _get(cls, key):
        print(f'call: getBuild({key})')
        ans = SESSION.getBuild(key, strict=True)
        return ans

class KojiTaskChildren(DiskCache):
    name = 'task-children'

    @classmethod
    def _get(cls, key):
        print(f"call: getTaskChildren({key})")
        tasks = SESSION.getTaskChildren(key)
        return tasks

class KojiTaskOutput(DiskCache):
    name = 'task-output'

    @classmethod
    def _get(cls, key):
        print(f"call: listTaskOutput({key})")
        output = SESSION.listTaskOutput(key)
        return output

class KojiRPMInfo(DiskCache):
    name = 'rpm-info'

    # It seems koji has no notion of epoch :(
    # Let's hope nobody ever builds the same n-v-r with different e

    # https://koji.fedoraproject.org/koji/api says:
    # - a map containing 'name', 'version', 'release', and 'arch'
    #   (and optionally 'location')
    # I have no idea what 'location' is.
    @classmethod
    def _get(cls, key):
        print(f'call: getRPM({key!r})')
        rinfo = SESSION.getRPM(key, strict=True)
        return rinfo


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
        print(logs)
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

def get_buildroot_listing(buildroot_id):
    print(f'call: getBuildrootListing({buildroot_id})')
    lst = SESSION.getBuildrootListing(buildroot_id)
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

    rpms = [RPM(name=e['name'],
                version=e['version'],
                release=e['release'],
                arch=e['arch'],
                epoch=e['epoch'],
                build_id=e['build_id'])
            for e in lst]
    print(f'build root {buildroot_id} contains {len(rpms)} rpms')
    return rpms

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
    assert arch != 'src'
    if arch in {'noarch', None}:
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

@listify
def override_rpm_architecture(buildroot_arch, rpms):
    # noarch rpms are built on a "random" architecture. If the
    # buildroot arch doesn't match our own, let's override the arch to install
    # rpms that make we can run locally. There is no gurantee that the same
    # set of rpms is available on every arch. But noarch packages should not
    # depend on the build architecture. It'd be a bug if that were the case.
    our_arch = platform.machine()  # XXX: this doesn't handle i386/i686 correctly
    if buildroot_arch == our_arch:
        yield from rpms
    else:
        print(f"Overriding build arch of rpms from {buildroot_arch} to {our_arch}")

        for rpm in rpms:
            if rpm.arch not in ('noarch', our_arch):
                yield rpm.with_arch(our_arch)
            else:
                yield rpm

def setup_buildroot(package, buildroot_info):
    # XXX: buildroot_info['arch'] might be a foreign arch for a noarch build

    # build_rpms = get_installed_rpms_from_log(package, arch)

    build_rpms = get_buildroot_listing(buildroot_info['id'])

    build_rpms = override_rpm_architecture(buildroot_info['arch'], build_rpms)

    rpms = get_local_rpms(build_rpms)

    repo_dir = package.build_dir() / 'repo'
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

    cmd = [
        'createrepo_c',
        '-v',
        '-g', 'comps.xml',
        repo_dir,
    ]

    print(f"+ {' '.join(shlex.quote(str(s)) for s in cmd)}")
    subprocess.check_call(cmd)

    config = mock_config(None, repo_dir)
    configfile = package.build_dir() / 'mock.cfg'
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

def mock_uniqueext_arg(package):
    return '--uniqueext=repro'
    # return f'--uniqueext={package.canonical}'

def build_package(package, mock_configfile, *mock_opts):
    rpm = package.some_rpm()   # we don't care which one is used
    rpm_file = rpm.local_filename()
    config = extract_config(rpm_file)
    srpm_file = package.srpm.local_filename()

    cmd = [
        'mock',
        '-r', mock_configfile,
        mock_uniqueext_arg(package),
        f"--define=_buildhost {config['BUILDHOST']}",
        f"--define=distribution {config['DISTRIBUTION']}",
        f"--define=packager {config['PACKAGER']}",
        f"--define=vendor {config['VENDOR']}",
        f"--define=bugurl {config['BUGURL']}",
        '--without=tests',
        '--nocheck',
        *mock_opts,
        srpm_file,
    ]

    print(f"+ {' '.join(shlex.quote(str(s)) for s in cmd)}")
    subprocess.check_call(cmd)

def mock_collect_output(package, mock_configfile):
    cmd = [
        'mock',
        '-r', mock_configfile,
        mock_uniqueext_arg(package),
        '--print-root-path',
    ]

    print(f"+ {' '.join(shlex.quote(str(s)) for s in cmd)}")
    root = Path(subprocess.check_output(cmd, text=True).strip())
    assert root.exists()

    result = root / '../result'
    assert result.exists()

    outdir = package.build_dir() / 'rebuild'
    if outdir.exists():
        shutil.rmtree(outdir)
    outdir.mkdir()

    outputs = []
    for file in result.glob('*'):
        print(f'Squirelling mock output {file.name}')
        shutil.copyfile(file, outdir / file.name, follow_symlinks=False)
        outputs += [outdir / file.name]

    return outputs

def compare_output(rpm1, rpm2, file=None):
    # Let's first compare with rpmdiff. If rpmdiff is happy, the rpms
    # are substantially the same: the contents and important metadata
    # is the same.
    #
    # diffoscope will pretty much always find differences because of
    # BUILDTIME and other metadata that we don't override in the
    # rebuild. Let's do this comparison only if the first finds some
    # differences.

    cmd = ['rpmdiff', rpm1.local_filename(), rpm2]
    print(f"+ {' '.join(shlex.quote(str(s)) for s in cmd)}")
    c = subprocess.getstatusoutput(cmd)
    if c == 0:
        return

    # TBD

def compare_outputs(package, outputs):
    srpm = None
    rpms = []

    for output in outputs:
        if output.name.endswith('.src.rpm'):
            if srpm is not None:
                raise ValueError('Duplicate srpm')
            srpm = output
        elif output.name.endswith('.rpm'):
            rpms += [output]

    if not srpm:
        raise ValueError('No srpm found')
    if not rpms:
        raise ValueError('No rpms found')

    if len(rpms) != len(package.rpms):
        raise ValueError(f'Mismatch in rpm count ({len(rpms)} != {len(package.rpms)})')

    compare_output(package.srpm, srpm)

    rpms_new = sorted(rpms)
    rpms_old = sorted(package.rpms, key=lambda r: r.canonical)

    for rpm_old, rpm_new in zip(rpms_old, rpms_new):
        compare_output(rpm_old, rpm_new)


def rebuild_package(package, *mock_opts, arch=None):
    arch_possibles = [arch] if arch else ['noarch', platform.machine()]

    build = package.build_info()
    tasks = KojiTaskChildren.get(build['task_id'])

    # get a list of outputs:
    # for a noarch build:
    # ['mock_output.log', 'root.log', …,
    #  'python3-referencing-0.30.2-1.fc40.noarch.rpm',
    #  'python-referencing-0.30.2-1.fc40.src.rpm']
    #
    # for an archful build:
    # ['mock_output.log', 'hw_info.log', 'state.log', 'build.log', 'root.log', 'checkout.log',
    # 'systemd-254.1-2.fc40.src.rpm']
    # ['mock_output.log', 'hw_info.log', 'state.log', 'build.log', 'root.log',
    # 'systemd-debugsource-254.1-2.fc40.x86_64.rpm',
    # 'systemd-debuginfo-254.1-2.fc40.x86_64.rpm',
    # 'systemd-254.1-2.fc40.x86_64.rpm',
    # 'systemd-tests-debuginfo-254.1-2.fc40.x86_64.rpm',
    # 'systemd-tests-254.1-2.fc40.x86_64.rpm',
    # 'systemd-udev-254.1-2.fc40.x86_64.rpm',
    # 'systemd-libs-debuginfo-254.1-2.fc40.x86_64.rpm',
    # 'systemd-udev-debuginfo-254.1-2.fc40.x86_64.rpm',
    # 'systemd-networkd-debuginfo-254.1-2.fc40.x86_64.rpm',
    # 'systemd-pam-debuginfo-254.1-2.fc40.x86_64.rpm',
    # 'systemd-container-debuginfo-254.1-2.fc40.x86_64.rpm',
    # 'systemd-standalone-repart-debuginfo-254.1-2.fc40.x86_64.rpm',
    # 'systemd-resolved-debuginfo-254.1-2.fc40.x86_64.rpm',
    # 'systemd-standalone-tmpfiles-debuginfo-254.1-2.fc40.x86_64.rpm',
    # 'systemd-standalone-shutdown-debuginfo-254.1-2.fc40.x86_64.rpm',
    # 'systemd-networkd-254.1-2.fc40.x86_64.rpm',
    # 'systemd-libs-254.1-2.fc40.x86_64.rpm',
    # 'systemd-standalone-sysusers-debuginfo-254.1-2.fc40.x86_64.rpm',
    # 'systemd-container-254.1-2.fc40.x86_64.rpm',
    # 'systemd-pam-254.1-2.fc40.x86_64.rpm',
    # 'systemd-standalone-repart-254.1-2.fc40.x86_64.rpm',
    # 'systemd-resolved-254.1-2.fc40.x86_64.rpm',
    # 'systemd-devel-254.1-2.fc40.x86_64.rpm',
    # 'systemd-journal-remote-debuginfo-254.1-2.fc40.x86_64.rpm',
    # 'systemd-standalone-tmpfiles-254.1-2.fc40.x86_64.rpm',
    # 'systemd-standalone-shutdown-254.1-2.fc40.x86_64.rpm',
    # 'systemd-standalone-sysusers-254.1-2.fc40.x86_64.rpm',
    # 'systemd-journal-remote-254.1-2.fc40.x86_64.rpm',
    # 'systemd-boot-unsigned-254.1-2.fc40.x86_64.rpm',
    # 'systemd-ukify-254.1-2.fc40.noarch.rpm',
    # 'systemd-rpm-macros-254.1-2.fc40.noarch.rpm',
    # 'systemd-oomd-defaults-254.1-2.fc40.noarch.rpm',
    # 'noarch_rpmdiff.json']

    arch_task = None

    for subtask in tasks:
        # find task with the right arch
        if (subtask['method'] == 'buildSRPMFromSCM' or
            (subtask['method'] == 'buildArch' and
             subtask['arch'] in arch_possibles)):

            outputs = KojiTaskOutput.get(subtask['id'])
            print(f'{outputs=}')

            for output in outputs:
                if output.endswith('.rpm'):
                    package.add_output_from_string(output[:-4], build_id=subtask['id'])

            if subtask['method'] == 'buildArch':
                arch_task = subtask

    if not arch_task:
        raise ValueError(f"Cannot find buildArch task with arch={' or '.join(arch_possibles)}")

    # tags = SESSION.listTags(build['build_id'])
    if not package.srpm or not package.rpms:
        pprint.pprint(tasks)
        raise ValueError(f'srpm and rpm output not found in {outputs!r}')

    buildroots = SESSION.listBuildroots(taskID=arch_task['id'])
    # I have no idea how to distinguish different buildroots.
    # If there's just one, there's no issue.
    assert len(buildroots) == 1
    buildroot_info = buildroots[0]

    mock_configfile = setup_buildroot(package, buildroot_info)

    build_package(package, mock_configfile, *mock_opts)

    outputs = mock_collect_output(package, mock_configfile)
    compare_outputs(package, outputs)


def main(argv):
    opts = do_opts(argv)
    init_koji_session(opts)

    package = RPM.from_string(opts.rpm)
    if package.arch:
        sys.exit('Sorry, specify build name, not rpm name')

    rebuild_package(package)

if __name__ == '__main__':
    main(sys.argv[1:])
