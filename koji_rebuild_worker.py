#!/usr/bin/python
# SPDX-License-Identifier: LGPL-2.1-or-later

# pylint: disable=missing-docstring,invalid-name,consider-using-with,unspecified-encoding

import argparse
import dataclasses
import subprocess
import random
import time
import sys
from pathlib import Path

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
                        default='*.fc41')

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
                # I don't understand what's going on here.
                # Did I forget to drain the queue before a restart?
                print(f'WARNING: {package.canonical} already built')
                queues.results.put(f'FAILURE {package}: found on disk')
                continue

            print(f'Will rebuild {package}')

            try:
                koji_rebuild.rebuild_package(opts, package)
            except subprocess.CalledProcessError as e:
                queues.results.put(f'FAILURE {package}: {e}')
            else:
                queues.results.put(f'SUCCESS {package}')

    else:
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

if __name__ == '__main__':
    main(sys.argv[1:])
