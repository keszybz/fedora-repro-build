#!/usr/bin/python
# SPDX-License-Identifier: LGPL-2.1-or-later

# https://kojipkgs.fedoraproject.org//packages/systemd/254/1.fc39/data/logs/x86_64/root.log
# pylint: disable=missing-docstring,invalid-name,consider-using-with,unspecified-encoding

import argparse
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
import time
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
        session_opts['debug'] = opts.debug
        session_opts['debug_xmlrpc'] = opts.debug_xmlrpc
        # pprint.pprint(session_opts)
        SESSION = KOJI.ClientSession(KOJI.config.server, session_opts)

def do_opts(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('--koji-profile', default='koji')
    parser.add_argument('--mock-uniqueext', default='repro',
                        help="Mock build identifier, e.g. 'builder1' or '{p.canonical}'")
    parser.add_argument('--debug',
                        action='store_true')
    parser.add_argument('--debug-xmlrpc',
                        action='store_true')
    parser.add_argument('-d', '--diff',
                        action='store_true')

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
    arch_override: bool = False

    package: 'RPM' = None
    build_id: int = None
    buildroot_id: int = None
    rpms: dict = dataclasses.field(default_factory=list)
    srpm: 'RPM' = None

    def __repr__(self):
        return f"RPM({self.name}-{self.version}-{self.release}{'.' if self.arch else ''}{self.arch or ''})"

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

        return cls(name=name, version=version, release=release, epoch=ep, arch=arch)

    @classmethod
    def from_koji_rpm_listing(cls, listing: dict):
        rpms = [cls(name=info['name'],
                    version=info['version'],
                    release=info['release'],
                    epoch=info['epoch'],
                    arch=info['arch'],
                    build_id=info['build_id'],
                    buildroot_id=info['buildroot_id'])
                for info in listing]

        for rpm in rpms:
            if rpm.arch == 'src':
                srpm = rpm
                break
        else:
            raise ValueError(f'srpm not found in {rpms=}')

        package = srpm.without_arch
        for rpm in rpms:
            package.add_output(rpm)
        return package

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

    def with_arch(self, arch, tag=False):
        if self.arch == arch:
            return self
        return self.__class__(name=self.name,
                              version=self.version,
                              release=self.release,
                              epoch=self.epoch,
                              arch=arch,
                              arch_override=tag)

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

    def add_output(self, rpm):
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

    def add_output_from_string(self, name, build_id=None):
        rpm = self.from_string(name)
        assert rpm.arch
        rpm.build_id = build_id
        print(rpm)
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

    @property
    def fedora_version(self):
        # Guess the Fedora version from the package release tag.
        # This of course only works if the release tag is present and in a fairly
        # standard form (e.g. shim doesn't have it). Maybe there's a better way…
        if not (m := re.search(r'\.fc(\d\d)(?!\d)', self.release)):
            raise ValueError(f'No see .fcNN in {self.release!r}')
        return int(m.group(1))


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
        # print(f'-> {tasks}')
        return tasks

class KojiTaskDescendents(DiskCache):
    name = 'task-descendents'

    @classmethod
    def _get(cls, key):
        print(f"call: getTaskDescendents({key})")
        tasks = SESSION.getTaskDescendents(key)
        # print(f'-> {tasks}')
        return tasks

class KojiTaskInfo(DiskCache):
    name = 'task-info'

    @classmethod
    def _get(cls, key):
        print(f"call: getTaskInfo({key})")
        tasks = SESSION.getTaskInfo(key)
        # print(f'-> {tasks}')
        return tasks

class KojiTaskOutput(DiskCache):
    name = 'task-output'

    @classmethod
    def _get(cls, key):
        print(f"call: listTaskOutput({key})")
        output = SESSION.listTaskOutput(key)
        return output

class KojiBuildRPMs(DiskCache):
    name = 'build-rpms'

    # [{'arch': 'src',
    #   'build_id': 2390461,
    #   'buildroot_id': 48532084,
    #   'buildtime': 1706340863,
    #   'draft': False,
    #   'epoch': 1,
    #   'external_repo_id': 0,
    #   'external_repo_name': 'INTERNAL',
    #   'extra': None,
    #   'id': 37502802,
    #   'metadata_only': False,
    #   'name': 'valgrind',
    #   'nvr': 'valgrind-3.22.0-6.fc40',
    #   'payloadhash': '5fa31d65362f9bbc790707b30bfa2b2d',
    #   'release': '6.fc40',
    #   'size': 16343447,
    #   'version': '3.22.0'},
    #  {'arch': 'i686',
    #   'build_id': 2390461,
    #   'buildroot_id': 48532084,
    #   'buildtime': 1706340882,
    #   'draft': False,
    #   'epoch': 1,
    #   'external_repo_id': 0,
    #   'external_repo_name': 'INTERNAL',
    #   'extra': None,
    #   'id': 37502803,
    #   'metadata_only': False,
    #   'name': 'valgrind',
    #   'nvr': 'valgrind-3.22.0-6.fc40',
    #   'payloadhash': 'b46d3f7cce0df0806a4e712a83d69219',
    #   'release': '6.fc40',
    #   'size': 4704425,
    #   'version': '3.22.0'},
    #  ...]

    @classmethod
    def _get(cls, key):
        for attempt in range(3):
            print(f"call: listBuildRPMs({key})")
            output = SESSION.listBuildRPMs(key)

            # Sometimes we get an empty list. Let's try again.
            if output:
                return output

            print('Got empty output, retrying!!!')
            time.sleep(1)
        else:
            raise IOError("Getting empty reply for listBuildRPMs({key})")


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

@listify
def get_local_rpms(rpms):
    for rpm in rpms:
        try:
            yield rpm.local_filename()
        # there's apparently koji.GenericError and __koji__koji.GenericError, wtf?
        except Exception as e:
            print('Failed to acquire local rpm:', e)
            if rpm.arch_override and 'No such rpm' in str(e):
                print(f'Skipping {rpm.canonical} after arch override')
            else:
                raise


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

def mock_config(fedora_version, arch, package_dir):
    assert arch != 'src'
    if arch in {'noarch', None}:
        arch = platform.machine()

    return textwrap.dedent(
        f'''\
        include('fedora-{fedora_version}-{arch}.cfg')

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
def override_rpm_architecture(rpms):
    # noarch rpms are built on a "random" architecture. If the
    # buildroot arch doesn't match our own, let's override the arch to install
    # rpms that make we can run locally. There is no gurantee that the same
    # set of rpms is available on every arch. But noarch packages should not
    # depend on the build architecture. It'd be a bug if that were the case.
    our_arch = platform.machine()  # XXX: this doesn't handle i386/i686 correctly

    warned = False
    for rpm in rpms:
        if rpm.arch not in ('noarch', our_arch):
            if not warned:
                print(f"Overriding build arch of rpms from {rpm.arch} to {our_arch}")
                warned = True
            yield rpm.with_arch(our_arch, tag=True)
        else:
            yield rpm


def setup_buildroot(task_rpm):
    # XXX: buildroot_info['arch'] might be a foreign arch for a noarch build

    build_rpms = get_buildroot_listing(task_rpm.buildroot_id)
    build_rpms = override_rpm_architecture(build_rpms)

    rpms = get_local_rpms(build_rpms)

    repo_dir = task_rpm.package.build_dir() / 'repo'
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

    config = mock_config(task_rpm.package.fedora_version, None, repo_dir)
    configfile = task_rpm.package.build_dir() / 'mock.cfg'
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

def format_string(string: str, **environ: dict):
    try:
        return string.format(**environ)
    except (KeyError, AttributeError) as e:
        msg = f'string formatting failed: {e}\n[{string}]\n[{pprint.pformat(environ)}]'
        raise ValueError(msg)

def mock_uniqueext_arg(opts, package) -> list[str]:
    ext = format_string(opts.mock_uniqueext, p=package)
    return [f'--uniqueext={ext}'] if ext else []

def build_package(opts, rpm, mock_configfile, *mock_opts):
    rpm_file = rpm.local_filename()
    config = extract_config(rpm_file)
    srpm_file = rpm.package.srpm.local_filename()

    cmd = [
        'mock',
        '-r', mock_configfile,
        *mock_uniqueext_arg(opts, rpm.package),
        f"--define=_buildhost {config['BUILDHOST']}",
        f"--define=distribution {config['DISTRIBUTION']}",
        f"--define=packager {config['PACKAGER']}",
        f"--define=vendor {config['VENDOR']}",
        f"--define=bugurl {config['BUGURL']}",
        '--config-opts=yum_cache_enable=False',
        '--without=tests',
        '--nocheck',
        *mock_opts,
        srpm_file,
    ]

    print(f"+ {' '.join(shlex.quote(str(s)) for s in cmd)}")
    c = subprocess.run(cmd)
    return c.returncode

def create_empty_outdir(package):
    outdir = package.build_dir() / 'rebuild'
    if outdir.exists():
        shutil.rmtree(outdir)
    outdir.mkdir(parents=True)
    return outdir

def mock_collect_output(opts, package, mock_configfile, mock_result):
    cmd = [
        'mock',
        '-r', mock_configfile,
        *mock_uniqueext_arg(opts, package),
        '--print-root-path',
    ]

    print(f"+ {' '.join(shlex.quote(str(s)) for s in cmd)}")
    root = Path(subprocess.check_output(cmd, text=True).strip())
    assert root.exists()

    result = root / '../result'
    assert result.exists()

    outdir = create_empty_outdir(package)

    for file in result.glob('*'):
        print(f'Squirelling mock output {file.name}')
        shutil.copyfile(file, outdir / file.name, follow_symlinks=False)

    return outdir

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
    status = subprocess.run(cmd, capture_output=True, text=True)
    if status == 0:
        return None

    print(status.stdout)
    return status.stdout
    # TBD

def compare_outputs(package, save=False):
    outdir = package.build_dir() / 'rebuild'
    print(f'Looking for {outdir}/*.rpm…')
    outputs = outdir.glob('*.rpm')

    srpm = None
    rpms = []

    for output in outputs:
        if output.name.endswith('.src.rpm'):
            if srpm is not None:
                raise ValueError('Duplicate srpm')
            srpm = output
        else:
            rpms += [output]

    if not srpm:
        raise ValueError('No srpm found')
    if not rpms:
        raise ValueError('No rpms found')

    relevant_rpms = [rpm for rpm in package.rpms
                     if rpm.arch in ('src', 'noarch', platform.machine())]

    if len(rpms) != len(relevant_rpms):
        print(f'Mismatch in rpm count ({len(rpms)} != {len(relevant_rpms)})')

    rpms_new = sorted(rpms)
    rpms_old = {r.canonical:r for r in relevant_rpms}

    rpm_diffs = {}
    rpm_diffs[package.srpm.canonical] = compare_output(package.srpm, srpm)

    for rpm_new in rpms_new:
        rpmname = rpm_new.name.removesuffix('.rpm')
        if rpm_old := rpms_old.pop(rpmname, None):
            res = compare_output(rpm_old, rpm_new)
        else:
            res = 'only found in rebuild'
            print(f'{rpmname}: {res}')

        rpm_diffs[rpmname] = res

    # Some packages build noarch packages with archful code to allow
    # foreign-arch code to be installed. For example, glibc builds
    #   sysroot-x86_64-fc41-glibc.noarch
    #   sysroot-i386-fc41-glibc.noarch
    #   sysroot-aarch64-fc41-glibc.noarch
    #   sysroot-ppc64le-fc41-glibc.noarch
    #   sysroot-s390x-fc41-glibc.noarch
    # and also
    #   glibc-headers-s390.noarch
    #   glibc-headers-x86.noarch
    # Builds from different architectures in koji are combined.
    # Our build will only recreate one variant, so we need to ignore
    # the others. Unfortunately, there is just a naming convention,
    # no obvious way to figure out which rpms are not expected.
    known_foreignarch = (
        # glibc:
        'sysroot-',
        'glibc-headers-',
        # s390utils
        's390utils-',
        # kernel
        'kernel-uki-',   # those are only built for some architectures
        'kernel-debug-uki-',
    )

    for rpmname in rpms_old:
        good = rpmname.startswith(known_foreignarch)
        if good:
            res = 'foreign-arch build only found in koji, ignoring'
        else:
            res = 'only found in koji build'

        print(f'{rpmname}: {res}')
        if not good:
            rpm_diffs[rpmname] = res

    if save:
        savepath = package.build_dir() / 'rebuild/comparison.json'
        print(f'Saving comparison to {savepath}')
        with savepath.open('w') as f:
            json.dump(rpm_diffs, f)

    return rpm_diffs

class NoBuildForArch(ValueError):
    pass

def rebuild_package(opts, package, *mock_opts, arch=None):
    arch_possibles = [arch] if arch else [platform.machine(), 'noarch']

    build = package.build_info()
    rpm_list = KojiBuildRPMs.get(build['build_id'])
    package = RPM.from_koji_rpm_listing(rpm_list)

    arch_rpms = [rpm for rpm in package.rpms if rpm.arch in arch_possibles[:1]]
    if not arch_rpms:
        arch_rpms = [rpm for rpm in package.rpms if rpm.arch in arch_possibles[1:]]
    if arch_rpms:
        arch_rpm = arch_rpms[0]

        mock_configfile = setup_buildroot(arch_rpm)

        mock_result = build_package(opts, arch_rpm, mock_configfile, *mock_opts)
        outdir = mock_collect_output(opts, package, mock_configfile, mock_result)

        if mock_result == 0:
            compare_outputs(package, save=True)

        result = f"Mock result {mock_result}"
    else:
        outdir = create_empty_outdir(package)
        mock_result = None
        result = f"Cannot find rpm with arch={' or '.join(arch_possibles)}"

    if mock_result != 0:
        print(f'{package.canonical}: marking rebuild as failed: {result}')
        (outdir / 'FAILED').write_text(result + '\n')

    return mock_result

def compare_package(opts, package):
    build = package.build_info()
    rpm_list = KojiBuildRPMs.get(build['build_id'])
    package = RPM.from_koji_rpm_listing(rpm_list)
    compare_outputs(package, save=True)

def main(argv):
    opts = do_opts(argv)
    rpm = RPM.from_string(opts.rpm)

    init_koji_session(opts)

    if opts.diff:
        return compare_package(opts, rpm)

    if rpm.arch:
        sys.exit('Sorry, specify build name, not rpm name')
    sys.exit(rebuild_package(opts, rpm))

if __name__ == '__main__':
    main(sys.argv[1:])
