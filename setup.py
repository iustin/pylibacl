#!/usr/bin/env python2

import distutils, os
from distutils.core import setup, Extension

(u_sysname, u_nodename, u_release, u_version, u_machine) = os.uname()

macros = []
libs = []
if u_sysname == "Linux":
    macros.append(("HAVE_LINUX", None))
    macros.append(("HAVE_LEVEL2", None))
    libs.append("acl")
elif u_sysname == "FreeBSD":
    macros.append(("HAVE_FREEBSD", None))
    libs.append("posix1e")
else:
    raise ValueError("I don't know your system. Please contact the author")

setup(name="pyacl",
      version="0.1",
      description="POSIX ACLs for python",
      long_description="""This is a C extension module for Python which
      implements POSIX ACLs manipulation. It is a wrapper on top
      of the acl C library - see acl(5).""",
      author="Iustin Pop",
      author_email="iusty@k1024.org",
      ext_modules=[Extension("acl", ["acl.c"],
                             libraries=libs,
                             define_macros=macros,
                             )],
      )
