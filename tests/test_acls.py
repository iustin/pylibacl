#
#

"""Unittests for the posix1e module"""

#  Copyright (C) 2002-2009, 2012, 2014, 2015 Iustin Pop <iustin@k1024.org>
#
#  This library is free software; you can redistribute it and/or
#  modify it under the terms of the GNU Lesser General Public
#  License as published by the Free Software Foundation; either
#  version 2.1 of the License, or (at your option) any later version.
#
#  This library is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#  Lesser General Public License for more details.
#
#  You should have received a copy of the GNU Lesser General Public
#  License along with this library; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
#  02110-1301  USA


import unittest
import os
import tempfile
import sys
import platform
import re
import errno
import operator
import pytest  # type: ignore
import contextlib
import pathlib
import io

import posix1e
from posix1e import *

TEST_DIR = os.environ.get("TEST_DIR", ".")

BASIC_ACL_TEXT = "u::rw,g::r,o::-"
TEXT_0755 = "u::rwx,g::rx,o::rx"

# Permset permission information
PERMSETS = [
    (ACL_READ, "read", Permset.read),
    (ACL_WRITE, "write", Permset.write),
    (ACL_EXECUTE, "execute", Permset.execute),
]

PERMSETS_IDS = [p[1] for p in PERMSETS]

ALL_TAGS = [
  (posix1e.ACL_USER, "user"),
  (posix1e.ACL_GROUP, "group"),
  (posix1e.ACL_USER_OBJ, "user object"),
  (posix1e.ACL_GROUP_OBJ, "group object"),
  (posix1e.ACL_MASK, "mask"),
  (posix1e.ACL_OTHER, "other"),
]

ALL_TAG_VALUES = [i[0] for i in ALL_TAGS]
ALL_TAG_DESCS = [i[1] for i in ALL_TAGS]

# Fixtures and helpers

def ignore_ioerror(errnum, fn, *args, **kwargs):
    """Call a function while ignoring some IOErrors.

    This is needed as some OSes (e.g. FreeBSD) return failure (EINVAL)
    when doing certain operations on an invalid ACL.

    """
    try:
        fn(*args, **kwargs)
    except IOError as err:
        if err.errno == errnum:
            return
        raise

def assert_acl_eq(a, b):
    if HAS_ACL_CHECK:
        assert a == b
    assert str(a) == str(b)

@pytest.fixture
def testdir():
    """per-test temp dir based in TEST_DIR"""
    with tempfile.TemporaryDirectory(dir=TEST_DIR) as dname:
        yield dname

def get_file(path):
    fh, fname = tempfile.mkstemp(".test", "xattr-", path)
    return fh, fname

@contextlib.contextmanager
def get_file_name(path):
    fh, fname = get_file(path)
    os.close(fh)
    yield fname

@contextlib.contextmanager
def get_file_fd(path):
    fd = get_file(path)[0]
    yield fd
    os.close(fd)

@contextlib.contextmanager
def get_file_object(path):
    fd = get_file(path)[0]
    with os.fdopen(fd) as f:
        yield f

@contextlib.contextmanager
def get_dir(path):
    yield tempfile.mkdtemp(".test", "xattr-", path)

def get_symlink(path, dangling=True):
    """create a symlink"""
    fh, fname = get_file(path)
    os.close(fh)
    if dangling:
        os.unlink(fname)
    sname = fname + ".symlink"
    os.symlink(fname, sname)
    return fname, sname

@contextlib.contextmanager
def get_valid_symlink(path):
    yield get_symlink(path, dangling=False)[1]

@contextlib.contextmanager
def get_dangling_symlink(path):
    yield get_symlink(path, dangling=True)[1]

@contextlib.contextmanager
def get_file_and_symlink(path):
    yield get_symlink(path, dangling=False)

@contextlib.contextmanager
def get_file_and_fobject(path):
    fh, fname = get_file(path)
    with os.fdopen(fh) as fo:
        yield fname, fo

# Wrappers that build upon existing values

def as_wrapper(call, fn, closer=None):
    @contextlib.contextmanager
    def f(path):
        with call(path) as r:
            val = fn(r)
            yield val
            if closer is not None:
                closer(val)
    return f

def as_bytes(call):
    return as_wrapper(call, lambda r: r.encode())

def as_fspath(call):
    return as_wrapper(call, pathlib.PurePath)

def as_iostream(call):
    opener = lambda f: io.open(f, "r")
    closer = lambda r: r.close()
    return as_wrapper(call, opener, closer)

NOT_BEFORE_36 = pytest.mark.xfail(condition="sys.version_info < (3,6)",
                                  strict=True)
NOT_PYPY = pytest.mark.xfail(condition="platform.python_implementation() == 'PyPy'",
                                  strict=False)

require_acl_from_mode = pytest.mark.skipif("not HAS_ACL_FROM_MODE")
require_acl_check = pytest.mark.skipif("not HAS_ACL_CHECK")
require_acl_entry = pytest.mark.skipif("not HAS_ACL_ENTRY")
require_extended_check = pytest.mark.skipif("not HAS_EXTENDED_CHECK")
require_equiv_mode = pytest.mark.skipif("not HAS_EQUIV_MODE")
require_copy_ext = pytest.mark.skipif("not HAS_COPY_EXT")

# Note: ACLs are valid only for files/directories, not symbolic links
# themselves, so we only create valid symlinks.
FILE_P = [
    get_file_name,
    as_bytes(get_file_name),
    pytest.param(as_fspath(get_file_name),
                 marks=[NOT_BEFORE_36, NOT_PYPY]),
    get_dir,
    as_bytes(get_dir),
    pytest.param(as_fspath(get_dir),
                 marks=[NOT_BEFORE_36, NOT_PYPY]),
    get_valid_symlink,
    as_bytes(get_valid_symlink),
    pytest.param(as_fspath(get_valid_symlink),
                 marks=[NOT_BEFORE_36, NOT_PYPY]),
]

FILE_D = [
    "file name",
    "file name (bytes)",
    "file name (path)",
    "directory",
    "directory (bytes)",
    "directory (path)",
    "file via symlink",
    "file via symlink (bytes)",
    "file via symlink (path)",
]

FD_P = [
    get_file_fd,
    get_file_object,
    as_iostream(get_file_name),
]

FD_D = [
    "file FD",
    "file object",
    "file io stream",
]

DIR_D = [
    "directory",
    "directory (bytes)",
    "directory (path object)",
]

DIR_P = [
    get_dir,
    as_bytes(get_dir),
    pytest.param(as_fspath(get_dir),
                 marks=[NOT_BEFORE_36, NOT_PYPY]),
]

ALL_P = FILE_P + FD_P
ALL_D = FILE_D + FD_D

@pytest.fixture(params=FILE_P, ids=FILE_D)
def file_subject(testdir, request):
    with request.param(testdir) as value:
        yield value

@pytest.fixture(params=FD_P, ids=FD_D)
def fd_subject(testdir, request):
    with request.param(testdir) as value:
        yield value

@pytest.fixture(params=DIR_P, ids=DIR_D)
def dir_subject(testdir, request):
    with request.param(testdir) as value:
        yield value

@pytest.fixture(params=ALL_P, ids=ALL_D)
def subject(testdir, request):
    with request.param(testdir) as value:
        yield value


class TestLoad:
    """Load/create tests"""
    def test_from_file(self, file_subject):
        """Test loading ACLs from a file/directory"""
        acl = posix1e.ACL(file=file_subject)
        assert acl.valid()

    def test_from_dir(self, dir_subject):
        """Test loading ACLs from a directory"""
        acl2 = posix1e.ACL(filedef=dir_subject)
        # default ACLs might or might not be valid; missing ones are
        # not valid, so we don't test acl2 for validity

    def test_from_fd(self, fd_subject):
        """Test loading ACLs from a file descriptor"""
        acl = posix1e.ACL(fd=fd_subject)
        assert acl.valid()

    def test_from_nonexisting(self, testdir):
        _, fname = get_file(testdir)
        with pytest.raises(IOError):
            posix1e.ACL(file="fname"+".no-such-file")
        with pytest.raises(IOError):
            posix1e.ACL(filedef="fname"+".no-such-file")

    def test_from_invalid_fd(self, testdir):
        fd, _ = get_file(testdir)
        os.close(fd)
        with pytest.raises(IOError):
            posix1e.ACL(fd=fd)

    def test_from_empty_invalid(self):
        """Test creating an empty ACL"""
        acl1 = posix1e.ACL()
        assert not acl1.valid()

    def test_from_text(self):
        """Test creating an ACL from text"""
        acl1 = posix1e.ACL(text=BASIC_ACL_TEXT)
        assert acl1.valid()

    # This is acl_check, but should actually be have_linux...
    @require_acl_check
    def test_from_acl(self):
        """Test creating an ACL from an existing ACL"""
        acl1 = posix1e.ACL(text=BASIC_ACL_TEXT)
        acl2 = posix1e.ACL(acl=acl1)
        assert acl1 == acl2

    def test_from_acl_via_str(self):
        # This is needed for not HAVE_LINUX cases.
        acl1 = posix1e.ACL(text=BASIC_ACL_TEXT)
        acl2 = posix1e.ACL(acl=acl1)
        assert str(acl1) == str(acl2)

    def test_invalid_creation_params(self, testdir):
        """Test that creating an ACL from multiple objects fails"""
        fd, _ = get_file(testdir)
        with pytest.raises(ValueError):
          posix1e.ACL(text=BASIC_ACL_TEXT, fd=fd)

    def test_invalid_value_creation(self):
        """Test that creating an ACL from wrong specification fails"""
        with pytest.raises(EnvironmentError):
          posix1e.ACL(text="foobar")
        with pytest.raises(TypeError):
          posix1e.ACL(foo="bar")

    def test_uninit(self):
        """Checks that uninit is actually empty init"""
        acl = posix1e.ACL.__new__(posix1e.ACL)
        assert not acl.valid()
        e = acl.append()
        e.permset
        acl.delete_entry(e)

    def test_double_init(self):
        acl1 = posix1e.ACL(text=BASIC_ACL_TEXT)
        assert acl1.valid()
        acl1.__init__(text=BASIC_ACL_TEXT) # type: ignore
        assert acl1.valid()
        acl2 = ACL(text=TEXT_0755)
        assert acl1 != acl2
        acl1.__init__(acl=acl2)  # type: ignore
        assert_acl_eq(acl1, acl2)

    def test_reinit_failure_noop(self):
        a = posix1e.ACL(text=TEXT_0755)
        b = posix1e.ACL(acl=a)
        assert_acl_eq(a, b)
        with pytest.raises(IOError):
            a.__init__(text='foobar')
        assert_acl_eq(a, b)

    @pytest.mark.xfail(reason="Unreliable test, re-init doesn't always invalidate children")
    def test_double_init_breaks_children(self):
        acl = posix1e.ACL()
        e = acl.append()
        e.permset.write = True
        acl.__init__() # type: ignore
        with pytest.raises(EnvironmentError):
            e.permset.write = False


class TestAclExtensions:
    """ACL extensions checks"""

    @require_acl_from_mode
    def test_from_mode(self):
        """Test loading ACLs from an octal mode"""
        acl1 = posix1e.ACL(mode=0o644)
        assert acl1.valid()

    @require_acl_check
    def test_acl_check(self):
        """Test the acl_check method"""
        acl1 = posix1e.ACL(text=BASIC_ACL_TEXT)
        assert not acl1.check()
        acl2 = posix1e.ACL()
        c = acl2.check()
        assert c == (ACL_MISS_ERROR, 0)
        assert isinstance(c, tuple)
        assert c[0] == ACL_MISS_ERROR
        e = acl2.append()
        c = acl2.check()
        assert c == (ACL_ENTRY_ERROR, 0)

    def test_applyto(self, subject):
        """Test the apply_to function"""
        # TODO: add read/compare with before, once ACL can be init'ed
        # from any source.
        basic_acl = posix1e.ACL(text=BASIC_ACL_TEXT)
        basic_acl.applyto(subject)
        enhanced_acl = posix1e.ACL(text="u::rw,g::-,o::-,u:root:rw,mask::r")
        assert enhanced_acl.valid()
        enhanced_acl.applyto(subject)

    def test_apply_to_with_wrong_object(self):
        acl1 = posix1e.ACL(text=BASIC_ACL_TEXT)
        assert acl1.valid()
        with pytest.raises(TypeError):
          acl1.applyto(object())
        with pytest.raises(TypeError):
          acl1.applyto(object(), object()) # type: ignore

    def test_apply_to_fail(self, testdir):
        acl1 = posix1e.ACL(text=BASIC_ACL_TEXT)
        assert acl1.valid()
        fd, fname = get_file(testdir)
        os.close(fd)
        with pytest.raises(IOError):
          acl1.applyto(fd)
        with pytest.raises(IOError, match="no-such-file"):
          acl1.applyto(fname+".no-such-file")

    @require_extended_check
    def test_applyto_extended(self, subject):
        """Test the acl_extended function"""
        basic_acl = posix1e.ACL(text=BASIC_ACL_TEXT)
        basic_acl.applyto(subject)
        assert not has_extended(subject)
        enhanced_acl = posix1e.ACL(text="u::rw,g::-,o::-,u:root:rw,mask::r")
        assert enhanced_acl.valid()
        enhanced_acl.applyto(subject)
        assert has_extended(subject)

    @require_extended_check
    @pytest.mark.parametrize(
        "gen", [ get_file_and_symlink, get_file_and_fobject ])
    def test_applyto_extended_mixed(self, testdir, gen):
        """Test the acl_extended function"""
        with gen(testdir) as (a, b):
            basic_acl = posix1e.ACL(text=BASIC_ACL_TEXT)
            basic_acl.applyto(a)
            for item in a, b:
                assert not has_extended(item)
            enhanced_acl = posix1e.ACL(text="u::rw,g::-,o::-,u:root:rw,mask::r")
            assert enhanced_acl.valid()
            enhanced_acl.applyto(b)
            for item in a, b:
                assert has_extended(item)

    @require_extended_check
    def test_extended_fail(self, testdir):
        fd, fname = get_file(testdir)
        os.close(fd)
        with pytest.raises(IOError):
          has_extended(fd)
        with pytest.raises(IOError, match="no-such-file"):
          has_extended(fname+".no-such-file")

    @require_extended_check
    def test_extended_arg_handling(self):
      with pytest.raises(TypeError):
        has_extended() # type: ignore
      with pytest.raises(TypeError):
        has_extended(object()) # type: ignore

    @require_equiv_mode
    def test_equiv_mode(self):
        """Test the equiv_mode function"""
        if HAS_ACL_FROM_MODE:
            for mode in 0o644, 0o755:
                acl = posix1e.ACL(mode=mode)
                assert acl.equiv_mode() == mode
        acl = posix1e.ACL(text="u::rw,g::r,o::r")
        assert acl.equiv_mode() == 0o644
        acl = posix1e.ACL(text="u::rx,g::-,o::-")
        assert acl.equiv_mode() == 0o500

    @require_equiv_mode
    @pytest.mark.xfail(reason="It seems equiv mode always passes, even for empty ACLs")
    def test_equiv_mode_invalid(self):
        """Test equiv_mode on invalid ACLs"""
        a = posix1e.ACL()
        with pytest.raises(EnvironmentError):
            a.equiv_mode()

    @require_acl_check
    def test_to_any_text(self):
        acl = posix1e.ACL(text=BASIC_ACL_TEXT)
        assert b"u::" in \
          acl.to_any_text(options=posix1e.TEXT_ABBREVIATE)
        assert b"user::" in acl.to_any_text()

    @require_acl_check
    def test_to_any_text_wrong_args(self):
        acl = posix1e.ACL(text=BASIC_ACL_TEXT)
        with pytest.raises(TypeError):
          acl.to_any_text(foo="bar") # type: ignore


    @require_acl_check
    def test_rich_compare(self):
        acl1 = posix1e.ACL(text="u::rw,g::r,o::r")
        acl2 = posix1e.ACL(acl=acl1)
        acl3 = posix1e.ACL(text="u::rw,g::rw,o::r")
        assert acl1 == acl2
        assert acl1 != acl3
        with pytest.raises(TypeError):
          acl1 < acl2 # type: ignore
        with pytest.raises(TypeError):
          acl1 >= acl3 # type: ignore
        assert acl1 != True # type: ignore
        assert not (acl1 == 1) # type: ignore
        with pytest.raises(TypeError):
          acl1 > True # type: ignore

    @require_acl_entry
    def test_acl_iterator(self):
        acl = posix1e.ACL(text=BASIC_ACL_TEXT)
        for entry in acl:
            assert entry.parent is acl

    @require_copy_ext
    def test_acl_copy_ext(self):
        a = posix1e.ACL(text=BASIC_ACL_TEXT)
        b = posix1e.ACL()
        c = posix1e.ACL(acl=b)
        assert a != b
        assert b == c
        state = a.__getstate__()
        b.__setstate__(state)
        assert a == b
        assert b != c

    @staticmethod
    def get_nulled_state(src=None):
        """Generate a mostly-valid external serialization

        Passing arbitrary state into acl_copy_int() is dangerous. That
        C function gets a void * buffer, and then casts that to an ACL
        structure, irrespective of buffer length; this can lead to
        segfaults (via unallocated memory indexing). Depending on the
        exact buffer, the same code might segfault on all
        architectures, some architectures, all C compiler versions, or
        some C compilers, or any combination of the above :(

        To mitigate this, pass a much larger buffer size as returned
        from the state, just nulled out - in the Linux version of the
        library, the first byte is the structure size and is tested
        for correct size, and a null byte will cause failure.

        """
        if src is None:
            src = posix1e.ACL()
        state = src.__getstate__()
        nulled = b'\x00' * (10 * len(state))
        return nulled

    @require_copy_ext
    def test_acl_copy_int_failure(self):
        a = posix1e.ACL()
        nulled = self.get_nulled_state(a)
        with pytest.raises(IOError):
            a.__setstate__(nulled)

    @require_copy_ext
    def test_acl_copy_int_failure_is_noop(self):
        a = posix1e.ACL(text=BASIC_ACL_TEXT)
        b = posix1e.ACL()
        c = posix1e.ACL(acl=a)
        assert a == c
        assert a != b
        nulled = self.get_nulled_state(b)
        with pytest.raises(IOError):
            a.__setstate__(nulled)
        # Assert that 'a' didn't change in the attempt to restore
        # invalid state.
        assert a == c

    @require_copy_ext
    def test_acl_copy_int_args(self):
        a = posix1e.ACL()
        with pytest.raises(TypeError):
            a.__setstate__(None)

    @require_copy_ext
    def test_acl_init_copy_int(self):
        a = posix1e.ACL(text=BASIC_ACL_TEXT)
        b = posix1e.ACL()
        c = posix1e.ACL(data=a.__getstate__())
        assert c != b
        assert c == a

    @require_copy_ext
    def test_acl_init_copy_int_invalid(self):
        with pytest.raises(IOError):
            posix1e.ACL(data=self.get_nulled_state())


class TestWrite:
    """Write tests"""

    def test_delete_default(self, testdir):
        """Test removing the default ACL"""
        with get_dir(testdir) as dname:
          posix1e.delete_default(dname)

    def test_delete_default_fail(self, testdir):
        """Test removing the default ACL"""
        with get_file_name(testdir) as fname:
            with pytest.raises(IOError, match="no-such-file"):
                posix1e.delete_default(fname+".no-such-file")

    @NOT_PYPY
    def test_delete_default_wrong_arg(self):
        with pytest.raises(TypeError):
          posix1e.delete_default(object()) # type: ignore

    def test_reapply(self, testdir):
        """Test re-applying an ACL"""
        fd, fname = get_file(testdir)
        acl1 = posix1e.ACL(fd=fd)
        acl1.applyto(fd)
        acl1.applyto(fname)
        with get_dir(testdir) as dname:
          acl2 = posix1e.ACL(file=fname)
          acl2.applyto(dname)



@require_acl_entry
class TestModification:
    """ACL modification tests"""

    def test_str(self):
        """Test str() of an ACL."""
        acl = posix1e.ACL(text=BASIC_ACL_TEXT)
        str_acl = str(acl)

    def test_append(self):
        """Test append a new Entry to the ACL"""
        acl = posix1e.ACL()
        e = acl.append()
        e.tag_type = posix1e.ACL_OTHER
        ignore_ioerror(errno.EINVAL, acl.calc_mask)
        str_format = str(e)
        e2 = acl.append(e)
        ignore_ioerror(errno.EINVAL, acl.calc_mask)
        assert not acl.valid()

    def test_wrong_append(self):
        """Test append a new Entry to the ACL based on wrong object type"""
        acl = posix1e.ACL()
        with pytest.raises(TypeError):
          acl.append(object()) # type: ignore

    @pytest.mark.xfail(reason="Behaviour not conform to specification")
    def test_append_invalid_source(self):
        a = posix1e.ACL()
        b = posix1e.ACL()
        f = b.append()
        b.delete_entry(f)
        with pytest.raises(EnvironmentError):
            f.permset.write = True
        with pytest.raises(EnvironmentError):
            e = a.append(f)

    def test_entry_creation(self):
        acl = posix1e.ACL()
        e = posix1e.Entry(acl)
        ignore_ioerror(errno.EINVAL, acl.calc_mask)
        str_format = str(e)

    def test_entry_failed_creation(self):
        # Checks for partial initialisation and deletion on error
        # path.
        with pytest.raises(TypeError):
          posix1e.Entry(object()) # type: ignore

    def test_entry_reinitialisations(self):
        a = posix1e.ACL()
        b = posix1e.ACL()
        e = posix1e.Entry(a)
        e.__init__(a) # type: ignore
        with pytest.raises(ValueError, match="different parent"):
            e.__init__(b) # type: ignore

    @NOT_PYPY
    def test_entry_reinit_leaks_refcount(self):
        acl = posix1e.ACL()
        e = acl.append()
        ref = sys.getrefcount(acl)
        e.__init__(acl) # type: ignore
        assert ref == sys.getrefcount(acl), "Uh-oh, ref leaks..."

    def test_delete(self):
        """Test delete Entry from the ACL"""
        acl = posix1e.ACL()
        e = acl.append()
        e.tag_type = posix1e.ACL_OTHER
        ignore_ioerror(errno.EINVAL, acl.calc_mask)
        acl.delete_entry(e)
        ignore_ioerror(errno.EINVAL, acl.calc_mask)

    def test_double_delete(self):
        """Test delete Entry from the ACL"""
        # This is not entirely valid/correct, since the entry object
        # itself is invalid after the first deletion, so we're
        # actually testing deleting an invalid object, not a
        # non-existing entry...
        acl = posix1e.ACL()
        e = acl.append()
        e.tag_type = posix1e.ACL_OTHER
        ignore_ioerror(errno.EINVAL, acl.calc_mask)
        acl.delete_entry(e)
        ignore_ioerror(errno.EINVAL, acl.calc_mask)
        with pytest.raises(EnvironmentError):
          acl.delete_entry(e)

    def test_delete_unowned(self):
        """Test delete Entry from the ACL"""
        a = posix1e.ACL()
        b = posix1e.ACL()
        e = a.append()
        e.tag_type = posix1e.ACL_OTHER
        with pytest.raises(ValueError, match="un-owned entry"):
            b.delete_entry(e)

    # This currently fails as this deletion seems to be accepted :/
    @pytest.mark.xfail(reason="Entry deletion is unreliable")
    def testDeleteInvalidEntry(self):
        """Test delete foreign Entry from the ACL"""
        acl1 = posix1e.ACL()
        acl2 = posix1e.ACL()
        e = acl1.append()
        e.tag_type = posix1e.ACL_OTHER
        ignore_ioerror(errno.EINVAL, acl1.calc_mask)
        with pytest.raises(EnvironmentError):
          acl2.delete_entry(e)

    def test_delete_invalid_object(self):
        """Test delete a non-Entry from the ACL"""
        acl = posix1e.ACL()
        with pytest.raises(TypeError):
          acl.delete_entry(object()) # type: ignore

    def test_double_entries(self):
        """Test double entries"""
        acl = posix1e.ACL(text=BASIC_ACL_TEXT)
        assert acl.valid()
        for tag_type in (posix1e.ACL_USER_OBJ, posix1e.ACL_GROUP_OBJ,
                         posix1e.ACL_OTHER):
            e = acl.append()
            e.tag_type = tag_type
            e.permset.clear()
            assert not acl.valid(), ("ACL containing duplicate entries"
                                     " should not be valid")
            acl.delete_entry(e)

    def test_multiple_good_entries(self):
        """Test multiple valid entries"""
        acl = posix1e.ACL(text=BASIC_ACL_TEXT)
        assert acl.valid()
        for tag_type in (posix1e.ACL_USER,
                         posix1e.ACL_GROUP):
            for obj_id in range(5):
                e = acl.append()
                e.tag_type = tag_type
                e.qualifier = obj_id
                e.permset.clear()
                acl.calc_mask()
                assert acl.valid(), ("ACL should be able to hold multiple"
                                     " user/group entries")

    def test_multiple_bad_entries(self):
        """Test multiple invalid entries"""
        for tag_type in (posix1e.ACL_USER,
                         posix1e.ACL_GROUP):
            acl = posix1e.ACL(text=BASIC_ACL_TEXT)
            assert acl.valid()
            e1 = acl.append()
            e1.tag_type = tag_type
            e1.qualifier = 0
            e1.permset.clear()
            acl.calc_mask()
            assert acl.valid(), ("ACL should be able to add a"
                                 " user/group entry")
            e2 = acl.append()
            e2.tag_type = tag_type
            e2.qualifier = 0
            e2.permset.clear()
            ignore_ioerror(errno.EINVAL, acl.calc_mask)
            assert not acl.valid(), ("ACL should not validate when"
                                     " containing two duplicate entries")
            acl.delete_entry(e1)
            # FreeBSD trips over itself here and can't delete the
            # entry, even though it still exists.
            ignore_ioerror(errno.EINVAL, acl.delete_entry, e2)

    def test_copy(self):
        acl = ACL()
        e1 = acl.append()
        e1.tag_type = ACL_USER
        p1 = e1.permset
        p1.clear()
        p1.read = True
        p1.write = True
        e2 = acl.append()
        e2.tag_type = ACL_GROUP
        p2 = e2.permset
        p2.clear()
        p2.read = True
        assert not p2.write
        e2.copy(e1)
        assert p2.write
        assert e1.tag_type == e2.tag_type

    def test_copy_wrong_arg(self):
        acl = ACL()
        e = acl.append()
        with pytest.raises(TypeError):
          e.copy(object()) # type: ignore

    def test_set_permset(self):
        acl = ACL()
        e1 = acl.append()
        e1.tag_type = ACL_USER
        p1 = e1.permset
        p1.clear()
        p1.read = True
        p1.write = True
        e2 = acl.append()
        e2.tag_type = ACL_GROUP
        p2 = e2.permset
        p2.clear()
        p2.read = True
        assert not p2.write
        e2.permset = p1
        assert e2.permset.write
        assert e2.tag_type == ACL_GROUP

    def test_set_permset_wrong_arg(self):
        acl = ACL()
        e = acl.append()
        with pytest.raises(TypeError):
          e.permset = object() # type: ignore

    def test_permset_creation(self):
        acl = ACL()
        e = acl.append()
        p1 = e.permset
        p2 = Permset(e)
        #assert p1 == p2

    def test_permset_creation_wrong_arg(self):
        with pytest.raises(TypeError):
          Permset(object()) # type: ignore

    def test_permset_reinitialisations(self):
        a = posix1e.ACL()
        e = posix1e.Entry(a)
        f = posix1e.Entry(a)
        p = e.permset
        p.__init__(e) # type: ignore
        with pytest.raises(ValueError, match="different parent"):
            p.__init__(f) # type: ignore

    @NOT_PYPY
    def test_permset_reinit_leaks_refcount(self):
        acl = posix1e.ACL()
        e = acl.append()
        p = e.permset
        ref = sys.getrefcount(e)
        p.__init__(e) # type: ignore
        assert ref == sys.getrefcount(e), "Uh-oh, ref leaks..."

    @pytest.mark.parametrize("perm, txt, accessor",
                             PERMSETS, ids=PERMSETS_IDS)
    def test_permset(self, perm, txt, accessor):
        """Test permissions"""
        del accessor
        acl = posix1e.ACL()
        e = acl.append()
        ps = e.permset
        ps.clear()
        str_ps = str(ps)
        assert not ps.test(perm), ("Empty permission set should not"
                                   " have permission '%s'" % txt)
        ps.add(perm)
        assert ps.test(perm), ("Permission '%s' should exist"
                               " after addition" % txt)
        str_ps = str(ps)
        ps.delete(perm)
        assert not ps.test(perm), ("Permission '%s' should not exist"
                                   " after deletion" % txt)
        ps.add(perm)
        assert ps.test(perm), ("Permission '%s' should exist"
                               " after addition" % txt)
        ps.clear()
        assert not ps.test(perm), ("Permission '%s' should not exist"
                                   " after clearing" % txt)



    @pytest.mark.parametrize("perm, txt, accessor",
                             PERMSETS, ids=PERMSETS_IDS)
    def test_permset_via_accessors(self, perm, txt, accessor):
        """Test permissions"""
        acl = posix1e.ACL()
        e = acl.append()
        ps = e.permset
        ps.clear()
        def getter():
            return accessor.__get__(ps) # type: ignore
        def setter(value):
            return accessor.__set__(ps, value) # type: ignore
        str_ps = str(ps)
        assert not getter(), ("Empty permission set should not"
                              " have permission '%s'" % txt)
        setter(True)
        assert ps.test(perm), ("Permission '%s' should exist"
                               " after addition" % txt)
        assert getter(), ("Permission '%s' should exist"
                          " after addition" % txt)
        str_ps = str(ps)
        setter(False)
        assert not ps.test(perm), ("Permission '%s' should not exist"
                                   " after deletion" % txt)
        assert not getter(), ("Permission '%s' should not exist"
                                  " after deletion" % txt)
        setter(True)
        assert getter()
        ps.clear()
        assert not getter()

    def test_permset_invalid_type(self):
        acl = posix1e.ACL()
        e = acl.append()
        ps = e.permset
        ps.clear()
        with pytest.raises(TypeError):
          ps.add("foobar") # type: ignore
        with pytest.raises(TypeError):
          ps.delete("foobar") # type: ignore
        with pytest.raises(TypeError):
          ps.test("foobar") # type: ignore
        with pytest.raises(ValueError):
          ps.write = object() # type: ignore

    @pytest.mark.parametrize("tag", [ACL_USER, ACL_GROUP],
                             ids=["ACL_USER", "ACL_GROUP"])
    def test_qualifier_values(self, tag):
        """Tests qualifier correct store/retrieval"""
        acl = posix1e.ACL()
        e = acl.append()
        qualifier = 1
        e.tag_type = tag
        while True:
            regex = re.compile("(user|group) with (u|g)id %d" % qualifier)
            try:
                e.qualifier = qualifier
            except OverflowError:
                # reached overflow condition, break
                break
            assert e.qualifier == qualifier
            assert regex.search(str(e)) is not None
            qualifier *= 2

    def test_qualifier_overflow(self):
        """Tests qualifier overflow handling"""
        acl = posix1e.ACL()
        e = acl.append()
        # the uid_t/gid_t are unsigned, so they can hold slightly more
        # than sys.maxsize*2 (on Linux).
        qualifier = (sys.maxsize + 1) * 2
        for tag in [posix1e.ACL_USER, posix1e.ACL_GROUP]:
            e.tag_type = tag
            with pytest.raises(OverflowError):
                e.qualifier = qualifier

    def test_qualifier_underflow(self):
        """Tests negative qualifier handling"""
        # Note: this presumes that uid_t/gid_t in C are unsigned...
        acl = posix1e.ACL()
        e = acl.append()
        for tag in [posix1e.ACL_USER, posix1e.ACL_GROUP]:
            e.tag_type = tag
            for qualifier in [-10, -5, -1]:
                with pytest.raises(OverflowError):
                    e.qualifier = qualifier

    def test_invalid_qualifier(self):
        """Tests invalid qualifier handling"""
        acl = posix1e.ACL()
        e = acl.append()
        with pytest.raises(TypeError):
          e.qualifier = object() # type: ignore
        with pytest.raises((TypeError, AttributeError)):
          del e.qualifier

    def test_qualifier_on_wrong_tag(self):
        """Tests qualifier setting on wrong tag"""
        acl = posix1e.ACL()
        e = acl.append()
        e.tag_type = posix1e.ACL_OTHER
        with pytest.raises(TypeError):
          e.qualifier = 1
        with pytest.raises(TypeError):
          e.qualifier

    @pytest.mark.parametrize("tag", ALL_TAG_VALUES, ids=ALL_TAG_DESCS)
    def test_tag_types(self, tag):
        """Tests tag type correct set/get"""
        acl = posix1e.ACL()
        e = acl.append()
        e.tag_type = tag
        assert e.tag_type == tag
        # check we can show all tag types without breaking
        assert str(e)

    @pytest.mark.parametrize("src_tag", ALL_TAG_VALUES, ids=ALL_TAG_DESCS)
    @pytest.mark.parametrize("dst_tag", ALL_TAG_VALUES, ids=ALL_TAG_DESCS)
    def test_tag_overwrite(self, src_tag, dst_tag):
        """Tests tag type correct set/get"""
        acl = posix1e.ACL()
        e = acl.append()
        e.tag_type = src_tag
        assert e.tag_type == src_tag
        assert str(e)
        e.tag_type = dst_tag
        assert e.tag_type == dst_tag
        assert str(e)

    def test_invalid_tags(self):
        """Tests tag type incorrect set/get"""
        acl = posix1e.ACL()
        e = acl.append()
        with pytest.raises(TypeError):
          e.tag_type = object() # type: ignore
        e.tag_type = posix1e.ACL_USER_OBJ
        # For some reason, PyPy raises AttributeError. Strange...
        with pytest.raises((TypeError, AttributeError)):
          del e.tag_type

    def test_tag_wrong_overwrite(self):
        acl = posix1e.ACL()
        e = acl.append()
        e.tag_type = posix1e.ACL_USER_OBJ
        tag = max(ALL_TAG_VALUES) + 1
        with pytest.raises(EnvironmentError):
          e.tag_type = tag
        # Check tag is still valid.
        assert e.tag_type == posix1e.ACL_USER_OBJ

if __name__ == "__main__":
    unittest.main()
