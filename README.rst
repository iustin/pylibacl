pylibacl
========

This is a Python 3.4+ extension module allows you to manipulate the
POSIX.1e Access Control Lists present in some OS/file-systems
combinations.

Downloads: go to http://pylibacl.k1024.org/downloads. Latest version
is 0.5.4. The source repository is either at
https://git.k1024.org/pylibacl.git or at
https://github.com/iustin/pylibacl.

For any issues, please file bugs at
https://github.com/iustin/pylibacl/issues.

.. image:: https://img.shields.io/travis/iustin/pylibacl
    :alt: Travis CI
    :target: https://travis-ci.org/iustin/pylibacl
.. image:: https://img.shields.io/coveralls/github/iustin/pylibacl
    :alt: Coveralls coverage
    :target: https://coveralls.io/github/iustin/pylibacl?branch=master
.. image:: https://img.shields.io/github/release-date/iustin/pylibacl
    :alt: GitHub Release Date
.. image:: https://img.shields.io/pypi/v/pylibacl
    :alt: PyPI
    :target: https://pypi.org/project/pylibacl/
.. image:: https://img.shields.io/pypi/implementation/pylibacl
    :alt: PyPI - Implementation
.. image:: https://img.shields.io/pypi/dm/pylibacl
    :alt: PyPI - Downloads

Requirements
------------

pylibacl has been written and tested on Linux, kernel v2.4 or newer,
with XFS filesystems; ext2/ext3 should also work. Since release 0.4.0,
FreeBSD 7 also has quite good support. If any other platform
implements the POSIX.1e draft, pylibacl can be used. I heard that
Solaris does, but I can't test it.

- Python 3.4 or newer. Python 2.4+ was supported in the 0.5.x branch.
- Operating system:
    - Linux, kernel v2.4 or newer, and the libacl library and
      development packages (all modern distributions should have this,
      under various names); also the file-systems you use must have
      ACLs turned on, either as a compile or mount option.
    - FreeBSD 7.0 or newer.
- The sphinx python module, for your python version, if building the
  documentation.

FreeBSD
+++++++

Note that on FreeBSD, ACLs are not enabled by default (at least on UFS
file systems). To enable them, run `tunefs -a enabled` on the file
system in question (after mounting it read-only). Then install:

- `pkg install py36-setuptools py36-sphinx`

or:

- `pkg install py37-setuptools`


License
-------

pylibacl is Copyright (C) 2002-2009, 2012, 2014, 2015 Iustin Pop.

pylibacl is free software; you can redistribute it and/or modify it under the
terms of the GNU Lesser General Public License as published by the Free
Software Foundation; either version 2.1 of the License, or (at your option) any
later version. See the COPYING file for the full license terms.
