# News

## Version 0.7.3

*released Sun, 13 Jul 2025*

This is a test-only changes release, removing some very old testing for
reference counts, introduced in 2012, but which stopped working with Python
3.14 as it changed reference counting by introducing optimizations in some
cases. No need to upgrade unless you want to make sure the test suite passes on
3.14, and no real failures are hidden by the broken reference testing.

Additionally, the release enables CI on Python 3.14, thanks Marcin
Zajączkowski!

## Version 0.7.2

*released Sun, 23 Feb 2025*

Single-bugfix release: fixed the typing stub module. Nothing exercised
it, and having been generated with pre-3.6 stubgen, it failed to work
on modern versions. No tests failed (should add some), but the doc
build by Sphinx failed accidentally since the failure to import (which
was ignored) led to a missing title for the module, which Sphinx
complained about. Quite funny :)

## Version 0.7.1

*released Fri, 14 Feb 2025*

Minor version, with a few test improvements, and updated documentation
building dependencies. No user-visible changes otherwise.

Tested with CPython versions 3.7-3.13, and PyPy 3.7-3.10.

## Version 0.7.0

*released Sun, 23 Apr 2023*

Important: Python 3.7 is the minimum supported version, due to
difficulty of testing old releases, and the fact that everything older
has been deprecated a long time ago (e.g. 3.6 at the end of 2021).

Otherwise, a minor release:

- Improve error handling in some corner cases (not expected to have
  any real-life impact, but who knows).
- Improved testing coverage and test infrastructure.
- Modernise parts of the C code based on recent Python version
  guidelines.
- Add a simple security policy and contribution guidelines.

## Version 0.6.0

*released Sun, 29 Nov 2020*

Major release removing Python 2 support. This allow both code cleanup
and new features, such as:

- Support for pathlib objects in `apply_to` and `has_extended`
  functions when running with Python 3.6 and newer.
- Use of built-in C API functions for bytes/unicode/pathlib conversion
  when dealing with file names, removing custom code (with the
  associated benefits).

Important API changes/bug fixes:

- Initialisation protocol has been changed, to disallow uninitialised
  objects; this means that `__new__` will always create valid objects,
  to prevent the need for checking initialisation status in all code
  paths; this also (implicitly) fixes memory leaks on re-initialisation
  (calling `__init__(…)` on an existing object) and segfaults (!) on
  non-initialised object attribute access. Note ACL re-initialisation is
  tricky and (still) leads to undefined behaviour of existing Entry
  objects pointing to it.
- Fix another bug in ACL re-initialisation where failures would result
  in invalid objects; now failed re-initialisation does not touch the
  original object.
- Restore `__setstate__`/`__getstate__` support on Linux; this was
  inadvertently removed due a typo(!) when adding support for it in
  FreeBSD. Pickle should work again for ACL instances, although not sure
  how stable this serialisation format actually is.
- Additionally, slightly change `__setstate__()` input to not allow
  Unicode, since the serialisation format is an opaque binary format.
- Fix (and change) entry qualifier (which is a user/group ID) behaviour:
  assume/require that uid_t/gid_t are unsigned types (they are with
  glibc, MacOS and FreeBSD at least; the standard doesn't document the
  signedness), and convert parsing and returning the qualifier to behave
  accordingly. The breakage was most apparent on 32-bit architectures,
  in which context the problem was originally reported (see issue #13).

Minor improvements:

- Added a `data` keyword argument to `ACL()`, which allows restoring an
  ACL directly from a serialised form (as given by `__getstate__()`),
  which should simplify some uses cases (`a = ACL(); a.__set
  state__(…)`).
- When available, add the file path to I/O error messages, which should
  lead to easier debugging.
- The test suite has changed to `pytest`, which allows increased
  coverage via parameterisation.

## Version 0.5.4

*released Thu, 14 Nov 2019*

Maintenance release:

- Switch build system to Python 3 by default (can be overridden if
  needed).
- Internal improvements for better cpychecker support.
- Fix compatibility with PyPy.
- Test improvements (both local and on Travis), testing more variations
  (debug, PyPy).
- Improve test coverage, and allow gathering test coverage results.
- Drop support (well, drop testing) for Python lower than 2.7.
- Minor documentation improvements (closes #9, #12).

## Version 0.5.3

*released Thu, 30 Apr 2015*

FreeBSD fixes:

- Enable all FreeBSD versions after 7.x at level 2 (thanks to Garrett
  Cooper).
- Make test suite pass under FreeBSD, which has a stricter behaviour
  with regards to invalid ACLs (which we do exercise in the test suite),
  thanks again to Garret for the bug reports.

## Version 0.5.2

*released Sat, 24 May 2014*

No visible changes release: just fix tests when running under pypy.

## Version 0.5.1

*released Sun, 13 May 2012*

A bug-fix only release. Critical bugs (memory leaks and possible
segmentation faults) have been fixed thanks to Dave Malcolm and his
``cpychecker`` tool. Additionally, some compatibility issues with Python
3.x have been fixed (str() methods returning bytes).

The documentation has been improved and changed from epydoc to sphinx;
note however that the documentation is still auto-generated from the
docstrings.

Project reorganisation: the project home page has been moved from
SourceForge to GitHub.

## Version 0.5

*released Sun, 27 Dec 2009*

Added support for Python 3.x and improved support for Unicode filenames.

## Version 0.4

*released Sat, 28 Jun 2008*

### License


Starting with this version, pylibacl is licensed under LGPL 2.1,
Febryary 1999 or any later versions (see README.rst and COPYING).

### Linux support

A few more Linux-specific functions:

- add the ACL.equiv_mode() method, which will return the equivalent
  octal mode if this is a basic ACL and raise an IOError exception
  otherwise

- add the acl_extended(...) function, which will check if an fd or path
  has an extended ACL

### FreeBSD support

FreeBSD 7.x will have almost all the acl manipulation functions that
Linux has, with the exception of __getstate__/__setstate__. As a
workaround, use the str() and ACL(text=...) methods to pass around
textual representations.

### Interface

At module level there are now a few constants exported for easy-checking
at runtime what features have been compiled in:

- `HAS_ACL_FROM_MODE`, denoting whether the ACL constructor supports
  the `mode=0xxx` parameter

- `HAS_ACL_CHECK`, denoting whether ACL instances support the
  `check()` method

- `HAS_ACL_ENTRY`, denoting whether ACL manipulation is possible and
  the Entry and Permset classes are available

- `HAS_EXTENEDED_CHECK`, denoting whether the `acl_extended()`
  function is supported

- `HAS_EQUIV_MODE`, denoting whether ACL instances support the
  `equiv_mode()` method

### Internals

Many functions have now unittests, which is a good thing.


## Version 0.3

*released Sun, 21 Oct 2007*

### Linux support

Under Linux, implement more functions from libacl:

- add `ACL(mode=...)`, implementing `acl_from_mode`.
- add `ACL.to_any_text()`, implementing `acl_to_any_text`.
- add ACL comparison, using `acl_cmp`.
- add `ACL.check()`, which is a more descriptive function than
  validate.
