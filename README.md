🚧🚧🚧 WARNING: WIP 🚧🚧🚧

Usage:
```
$ python koji_rebuild.py NEVR
```

This will establish a koji session,
download information about the build,
get the output package list,
pick a subpackage with a matching architecture or "noarch",
download the list of packages in the build of the subpackage,
download those packages,
create a "repository" using `createrepo_c`,
create a mock config using that repository and no other sources of packages,
download the srpm,
launch `mock` rebuild of the srpm,
locate the output packages,
and do a one-by-one comparison of the first package list and the mock output packages.

The comparison is done using `rpmdiff`,
because that suppresses differences that are not interesting.
`diffoscope` should be used for in-depth comparisons.

At least the following fields will always or almost always vary:
* `HEADERIMMUTABLE`,
* `SIGSIZE`,
* `SIGMD5`,
* `SHA1HEADER`,
* `SHA256HEADER`
* `BUILDTIME`
* `BUILDHOST` (we override this based on the first archful package, but srpm and noarch packages will often have different values)
* `OPTFLAGS` (this depends on the architecture, also for the srpm and noarch packages)
* `PLATFORM` (same)

If `rpmdiff` shows a difference, or if `diffoscope` shows a difference in `FILEMD5S` or `PAYLOADDIGEST`, then the builds was not reproducible.

For list of known issues, see https://pagure.io/fedora-reproducible-builds/project/issues?tags=irreproducibility.

Information that is queried from koji is saved under `cache/info/`,
and packages that are downloaded are saved under `cache/rpms/`.
Build outputs and logs are saved under `cache/build/`.

🚧🚧🚧 WARNING: WIP 🚧🚧🚧
