#!/usr/bin/python
# SPDX-License-Identifier: LGPL-2.1-or-later

# pylint: disable=missing-docstring,invalid-name,consider-using-with,unspecified-encoding

import argparse
import dataclasses
import random
import sys

import koji
from ipcqueue import posixmq

import koji_rebuild

def do_opts(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('--koji-profile', default='koji')
    parser.add_argument('--mock-uniqueext', default='repro',
                        help="Mock build identifier, e.g. 'builder1' or '{p.canonical}'")
    parser.add_argument('--debug',
                        action='store_true')
    parser.add_argument('--debug-xmlrpc',
                        action='store_true')

    parser.add_argument('--worker',
                        action='store_true')
    parser.add_argument('--drain',
                        action='store_true')
    parser.add_argument('--queue',
                        default='rebuild')
    parser.add_argument('--after',
                        default=None)
    parser.add_argument('--pattern',
                        default='*.fc41*')
    parser.add_argument('builds',
                        nargs='*')

    opts = parser.parse_args(argv)
    return opts

@dataclasses.dataclass
class Queues:
    jobs: posixmq.Queue
    results: posixmq.Queue

    @classmethod
    def open(cls, opts):
        print(f'Opening /{opts.queue}/{{jobs,results}}...')
        j = posixmq.Queue(f'/{opts.queue}.jobs')
        r = posixmq.Queue(f'/{opts.queue}.results')
        return cls(j, r)

def queue_pop(queue):
    try:
        return queue.get(timeout=0)
    except Exception:  # no public type?
        return None

def rebuild_exists(package):
    return (package.build_dir() / 'rebuild').exists()

def main(argv):
    opts = do_opts(argv)

    koji_rebuild.init_koji_session(opts)

    queues = Queues.open(opts)

    if opts.drain:
        while res := queue_pop(queues.jobs):
            print(f'Got job {res}')
        queues.jobs.unlink()
        while res := queue_pop(queues.results):
            print(f'Got result {res}')
        queues.results.unlink()

    elif opts.worker:
        while True:
            print('Getting job...', end=' ')
            package = queues.jobs.get()
            print(f'{package}')

            assert not package.arch
            if rebuild_exists(package):
                print(f'{package.canonical} already built')
                queues.results.put(f'FAILURE {package}: found on disk')
                continue

            print(f'Will rebuild {package}')

            mock_result = koji_rebuild.rebuild_package(opts, package)
            if mock_result == 0:
                queues.results.put(f'SUCCESS {package}')
            else:
                queues.results.put(f'FAILURE {package}: {mock_result=}')

    elif opts.after:
        builds = koji_rebuild.SESSION.listBuilds(
            state=koji.BUILD_STATES['COMPLETE'],
            createdAfter=opts.after,
            pattern=opts.pattern)

        packages = [
            koji_rebuild.RPM(name=build['name'],
                             version=build['version'],
                             release=build['release'])
            for build in builds]

        todo = []
        for package in packages:
            if rebuild_exists(package):
                print(f'{package.canonical} already rebuilt, ignoring')
            else:
                todo += [package]

        # Randomize the list in case the list consists of a long repetition
        # of builds of the same type, which makes load type distribution bad.
        todo.sort(key=lambda x: random.random())
        print(f'Have {len(todo)} builds to do ({len(packages)-len(todo)} already done)')

        for package in todo:
            print(f'{package.canonical} into the queue')
            queues.jobs.put(package)

            while ret := queue_pop(queues.results):
                print(f'Got {ret}')

        while ret := queues.results.get():
            print(f'Got {ret}')

    else:
        packages = [koji_rebuild.RPM.from_string(arg, is_package=True)
                    for arg in opts.builds]
        for package in packages:
            print(f'{package.canonical} into the queue')
            queues.jobs.put(package)


if __name__ == '__main__':
    main(sys.argv[1:])
