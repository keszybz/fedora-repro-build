#!/usr/bin/python
# SPDX-License-Identifier: LGPL-2.1-or-later

# pylint: disable=missing-docstring,invalid-name,consider-using-with,unspecified-encoding

import argparse
import fnmatch
import os
import sys
from pathlib import Path

CONF_FILENAME = 'fm_client.toml'
# can this happen later?
os.environ['FEDORA_MESSAGING_CONF'] = Path(sys.argv[0]).with_name(CONF_FILENAME).as_posix()

from fedora_messaging import api, config

import koji_rebuild
import koji_rebuild_worker

# Id: b1cb6938-bab8-4597-b278-dd45f5491ce8
# Topic: org.fedoraproject.prod.buildsys.rpm.sign
# Headers: {
#     "fedora_messaging_rpm_glibc": true,
#     "fedora_messaging_schema": "koji_fedoramessaging.rpm.SignV1",
#     "fedora_messaging_severity": 10,
#     "fedora_messaging_user_fweimer": true,
#     "priority": 0,
#     "sent-at": "2024-06-21T12:52:29+00:00",
#     "x-received-from": [
#         {
#             "cluster-name": "rabbit@rabbitmq02.iad2.fedoraproject.org",
#             "exchange": "amq.topic",
#             "redelivered": false,
#             "uri": "amqps://rabbitmq01.iad2.fedoraproject.org/%2Fpubsub"
#         }
#     ]
# }
# Body: {
#     "base_url": "https://koji.fedoraproject.org",
#     "build": {
#         "build_id": 2477334,
#         "cg_id": null,
#         "cg_name": null,
#         "completion_time": 1718974114.0,
#         "creation_event_id": 132897878,
#         "creation_time": 1718969311.0,
#         "creation_ts": 1718969311.67259,
#         "draft": false,
#         "epoch": null,
#         "extra": {
#             "source": {
#                 "original_url": "git+https://src.fedoraproject.org/rpms/glibc.git#b5cf50002ff11b750020c0a8fa2324bc28ba4ed1"
#             }
#         },
#         "id": 2477334,
#         "name": "glibc",
#         "nvr": "glibc-2.39.9000-27.fc41",
#         "owner_id": 3362,
#         "owner_name": "fweimer",
#         "package_id": 57,
#         "package_name": "glibc",
#         "promoter_id": null,
#         "promoter_name": null,
#         "promotion_time": null,
#         "promotion_ts": null,
#         "release": "27.fc41",
#         "source": "git+https://src.fedoraproject.org/rpms/glibc.git#b5cf50002ff11b750020c0a8fa2324bc28ba4ed1",
#         "start_time": 1718969311.0,
#         "state": 1,
#         "task_id": 119384399,
#         "version": "2.39.9000",
#         "volume_id": 0,
#         "volume_name": "DEFAULT"
#     },
#     "instance": "primary",
#     "rpm": {
#         "arch": "aarch64",
#         "build_id": 2477334,
#         "buildroot_id": 51718777,
#         "buildtime": 1718969452,
#         "draft": false,
#         "epoch": null,
#         "external_repo_id": 0,
#         "external_repo_name": "INTERNAL",
#         "extra": null,
#         "id": 38990978,
#         "metadata_only": false,
#         "name": "glibc-langpack-sv",
#         "payloadhash": "d823146150dc533bb93797773fb05540",
#         "release": "27.fc41",
#         "size": 597192,
#         "version": "2.39.9000"
#     },
#     "sighash": "661ce647fe3ba91c50e9d3b6295d1ffb",
#     "sigkey": "e99d6ad1"
# }

SEEN = set()
QUEUES = None
OPTS = None

def do_opts(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('--queue',
                        default='rebuild')
    parser.add_argument('--pattern',
                        default='*.fc41*')

    opts = parser.parse_args(argv)
    return opts

def consumer(message):
    print('message:\n:', message)

    build = message.body['build']
    build = koji_rebuild.RPM(name=build['name'],
                             version=build['version'],
                             release=build['release'],
                             epoch=build['epoch'])

    if build.canonical in SEEN:
        return

    print(f'Build signed: {build.canonical}')
    SEEN.add(build.canonical)

    if not fnmatch.fnmatch(build.canonical, OPTS.pattern):
        print(f'Build {build.canonical} does not match {OPTS.pattern}')
        return

    if koji_rebuild_worker.rebuild_exists(build):
        print(f'{build.canonical} already rebuilt, ignoring')
    else:
        print(f'{build.canonical} into the queue')
        QUEUES.jobs.put(build)

def main(argv):
    config.conf.setup_logging()

    global OPTS, QUEUES
    OPTS = do_opts(argv)
    QUEUES = koji_rebuild_worker.Queues.open(OPTS)

    api.consume(consumer)

if __name__ == '__main__':
    main(sys.argv[1:])
