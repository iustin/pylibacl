#!/usr/bin/env python3

import os
from setuptools import setup, Extension

(u_sysname, u_nodename, u_release, u_version, u_machine) = os.uname()

macros = []
libs = []
if u_sysname == "Linux":
    macros.append(("HAVE_LINUX", None))
    macros.append(("HAVE_LEVEL2", None))
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

version = "0.5.4"

setup(name="pylibacl",
      version=version,
      description="POSIX.1e ACLs for python",
      long_description=long_desc,
      author="Iustin Pop",
      author_email="iustin@k1024.org",
      url="http://pylibacl.k1024.org/",
      license="LGPL",
      ext_modules=[Extension("posix1e", ["acl.c"],
                             libraries=libs,
                             define_macros=macros,
                             )],
      test_suite="test",
      )
