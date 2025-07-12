#!/usr/bin/env python3

import os
from setuptools import setup, Extension

(u_sysname, u_nodename, u_release, u_version, u_machine) = os.uname()

macros = []
libs = []
if u_sysname == "Linux":
    macros.append(("HAVE_LINUX", None))
    macros.append(("HAVE_LEVEL2", None))
    macros.append(("HAVE_ACL_COPY_EXT", None))
    libs.append("acl")
elif u_sysname == "GNU/kFreeBSD":
    macros.append(("HAVE_LINUX", None))
    macros.append(("HAVE_LEVEL2", None))
    macros.append(("HAVE_ACL_COPY_EXT", None))
    libs.append("acl")
elif u_sysname == "FreeBSD":
    macros.append(("HAVE_FREEBSD", None))
    if int(u_release.split(".", 1)[0]) >= 7:
        macros.append(("HAVE_LEVEL2", None))
elif u_sysname == "Darwin":
    libs.append("pthread")
else:
    raise ValueError("I don't know your system '%s'."
                     " Please contact the author" % u_sysname)

long_desc = """This is a C extension module for Python which
implements POSIX ACLs manipulation. It is a wrapper on top
of the systems's acl C library - see acl(5)."""

version = "0.7.3"

setup(name="pylibacl",
      version=version,
      description="POSIX.1e ACLs for python",
      long_description=long_desc,
      author="Iustin Pop",
      author_email="iustin@k1024.org",
      url="https://pylibacl.k1024.org/",
      license="LGPL",
      ext_modules=[Extension("posix1e", ["acl.c"],
                             libraries=libs,
                             define_macros=macros,
                             )],
      python_requires = ">=3.7",
      # Note: doesn't work since it's not a package. Sigh.
      package_data = {
          '': ['py.typed', 'posix1e.pyi'],
      },
      zip_safe=False,
      project_urls={
        "Bug Tracker": "https://github.com/iustin/pylibacl/issues",
      },
      classifiers = [
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: GNU Lesser General Public License v2 or later (LGPLv2+)",
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: Python :: Implementation :: CPython",
        "Programming Language :: Python :: Implementation :: PyPy",
        "Operating System :: POSIX :: BSD :: FreeBSD",
        "Operating System :: POSIX :: Linux",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: System :: Filesystems",
      ]
      )
