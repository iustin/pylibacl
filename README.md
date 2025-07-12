# pylibacl

This is a Python 3.7+ extension module allows you to manipulate the
POSIX.1e Access Control Lists present in some OS/file-systems
combinations.

Downloads: go to <https://pylibacl.k1024.org/downloads>. Latest
version is 0.7.3. The source repository is either at
<https://git.k1024.org/pylibacl.git> or at
<https://github.com/iustin/pylibacl>.

For any issues, please file bugs at
<https://github.com/iustin/pylibacl/issues>.

See the `CONTRIBUTING.md` file for details on how to contribute, or
support me on [ko-fi](https://ko-fi.com/iustin).

[![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/iustin/pylibacl/ci.yml?branch=main)](https://github.com/iustin/pylibacl/actions/workflows/ci.yml)
[![Codecov](https://img.shields.io/codecov/c/github/iustin/pylibacl)](https://codecov.io/gh/iustin/pylibacl)
[![Read the Docs](https://img.shields.io/readthedocs/pylibacl)](http://pylibacl.readthedocs.io/en/latest/?badge=latest)
[![GitHub issues](https://img.shields.io/github/issues/iustin/pylibacl)](https://github.com/iustin/pylibacl/issues)
![GitHub tag (latest by date)](https://img.shields.io/github/v/tag/iustin/pylibacl)
[![GitHub release (latest by date)](https://img.shields.io/github/v/release/iustin/pylibacl)](https://github.com/iustin/pylibacl/releases)
[![PyPI](https://img.shields.io/pypi/v/pylibacl)](https://pypi.org/project/pylibacl/)
![Debian package](https://img.shields.io/debian/v/python-pylibacl)
![Ubuntu package](https://img.shields.io/ubuntu/v/python-pylibacl)
![GitHub Release Date](https://img.shields.io/github/release-date/iustin/pylibacl)
![GitHub commits since latest release](https://img.shields.io/github/commits-since/iustin/pylibacl/latest)
![GitHub last commit](https://img.shields.io/github/last-commit/iustin/pylibacl)

## Requirements

pylibacl has been written and tested on Linux, kernel v2.4 or newer,
with XFS filesystems; ext2/ext3 should also work. Since release 0.4.0,
FreeBSD 7 also has quite good support. If any other platform
implements the POSIX.1e draft, pylibacl can be used. I heard that
Solaris does, but I can't test it.

- Python 3.7 or newer. Python 2.4+ was supported in the 0.5.x branch,
  Python 3.4+ in the 0.6 branch.
- Operating system:
    - Linux, kernel v2.4 or newer, and the libacl library and
      development packages (all modern distributions should have this,
      under various names); also the file-systems you use must have
      ACLs turned on, either as a compile or mount option.
    - FreeBSD 7.0 or newer.
- The sphinx python module, for your python version, if building the
  documentation.

## FreeBSD

Note that on FreeBSD, ACLs are not enabled by default (at least on UFS
file systems). To enable them, run `tunefs -a enabled` on the file
system in question (after mounting it read-only). Then install:

- `pkg install py36-setuptools py36-sphinx`

or:

- `pkg install py37-setuptools`

## Security

For reporting security vulnerabilities, please see `SECURITY.md`.

## License

pylibacl is Copyright (C) 2002-2009, 2012, 2014, 2015 Iustin Pop.

pylibacl is free software; you can redistribute it and/or modify it under the
terms of the GNU Lesser General Public License as published by the Free
Software Foundation; either version 2.1 of the License, or (at your option) any
later version. See the COPYING file for the full license terms.
