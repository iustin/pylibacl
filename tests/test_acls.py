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
import pytest
import contextlib

import posix1e
from posix1e import *

TEST_DIR = os.environ.get("TEST_DIR", ".")

BASIC_ACL_TEXT = "u::rw,g::r,o::-"

# This is to workaround python 2/3 differences at syntactic level
# (which can't be worked around via if's)
M0500 = 320 # octal 0500
M0644 = 420 # octal 0644
M0755 = 493 # octal 755

# Permset permission information
PERMSETS = {
  posix1e.ACL_READ: ("read", posix1e.Permset.read),
  posix1e.ACL_WRITE: ("write", posix1e.Permset.write),
  posix1e.ACL_EXECUTE: ("execute", posix1e.Permset.execute),
  }

ALL_TAG_TYPES = [
  posix1e.ACL_USER,
  posix1e.ACL_GROUP,
  posix1e.ACL_USER_OBJ,
  posix1e.ACL_GROUP_OBJ,
  posix1e.ACL_MASK,
  posix1e.ACL_OTHER,
]

# Check if running under Python 3
IS_PY_3K = sys.hexversion >= 0x03000000

# Fixtures and helpers

def ignore_ioerror(errnum, fn, *args, **kwargs):
    """Call a function while ignoring some IOErrors.

    This is needed as some OSes (e.g. FreeBSD) return failure (EINVAL)
    when doing certain operations on an invalid ACL.

    """
    try:
        fn(*args, **kwargs)
    except IOError:
        err = sys.exc_info()[1]
        if err.errno == errnum:
            return
        raise

def encode(s):
    """Encode a string if needed (under Python 3)"""
    if IS_PY_3K:
        return s.encode()
    else:
        return s

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

class TestLoad:
    """Load/create tests"""
    def test_from_file(self, testdir):
        """Test loading ACLs from a file"""
        _, fname = get_file(testdir)
        acl1 = posix1e.ACL(file=fname)
        assert acl1.valid()

    def test_from_dir(self, testdir):
        """Test loading ACLs from a directory"""
        with get_dir(testdir) as dname:
          acl1 = posix1e.ACL(file=dname)
          acl2 = posix1e.ACL(filedef=dname)
          assert acl1.valid()
        # default ACLs might or might not be valid; missing ones are
        # not valid, so we don't test acl2 for validity

    def test_from_fd(self, testdir):
        """Test loading ACLs from a file descriptor"""
        fd, _ = get_file(testdir)
        acl1 = posix1e.ACL(fd=fd)
        assert acl1.valid()

    def test_from_empty_invalid(self):
        """Test creating an empty ACL"""
        acl1 = posix1e.ACL()
        assert not acl1.valid()

    def test_from_text(self):
        """Test creating an ACL from text"""
        acl1 = posix1e.ACL(text=BASIC_ACL_TEXT)
        assert acl1.valid()

    def test_from_acl(self):
        """Test creating an ACL from an existing ACL"""
        acl1 = posix1e.ACL()
        acl2 = posix1e.ACL(acl=acl1)
        assert acl1 == acl2

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

    def test_double_init(self):
        acl1 = posix1e.ACL(text=BASIC_ACL_TEXT)
        assert acl1.valid()
        acl1.__init__(text=BASIC_ACL_TEXT)
        assert acl1.valid()

class TestAclExtensions:
    """ACL extensions checks"""

    @require_acl_from_mode
    def test_from_mode(self):
        """Test loading ACLs from an octal mode"""
        acl1 = posix1e.ACL(mode=M0644)
        assert acl1.valid()

    @require_acl_check
    def test_acl_check(self):
        """Test the acl_check method"""
        acl1 = posix1e.ACL(text=BASIC_ACL_TEXT)
        assert not acl1.check()
        acl2 = posix1e.ACL()
        assert acl2.check()

    @require_extended_check
    def test_extended(self, testdir):
        """Test the acl_extended function"""
        fd, fname = get_file(testdir)
        basic_acl = posix1e.ACL(text=BASIC_ACL_TEXT)
        basic_acl.applyto(fd)
        for item in fd, fname:
            assert not has_extended(item)
        enhanced_acl = posix1e.ACL(text="u::rw,g::-,o::-,u:root:rw,mask::r")
        assert enhanced_acl.valid()
        enhanced_acl.applyto(fd)
        for item in fd, fname:
            assert has_extended(item)

    @require_extended_check
    def test_extended_arg_handling(self):
      with pytest.raises(TypeError):
        has_extended()
      with pytest.raises(TypeError):
        has_extended(object())

    @require_equiv_mode
    def test_equiv_mode(self):
        """Test the equiv_mode function"""
        if HAS_ACL_FROM_MODE:
            for mode in M0644, M0755:
                acl = posix1e.ACL(mode=mode)
                assert acl.equiv_mode() == mode
        acl = posix1e.ACL(text="u::rw,g::r,o::r")
        assert acl.equiv_mode() == 0o644
        acl = posix1e.ACL(text="u::rx,g::-,o::-")
        assert acl.equiv_mode() == 0o500

    @require_acl_check
    def test_to_any_text(self):
        acl = posix1e.ACL(text=BASIC_ACL_TEXT)
        assert encode("u::") in \
          acl.to_any_text(options=posix1e.TEXT_ABBREVIATE)
        assert encode("user::") in acl.to_any_text()

    @require_acl_check
    def test_to_any_text_wrong_args(self):
        acl = posix1e.ACL(text=BASIC_ACL_TEXT)
        with pytest.raises(TypeError):
          acl.to_any_text(foo="bar")


    @require_acl_check
    def test_rich_compare(self):
        acl1 = posix1e.ACL(text="u::rw,g::r,o::r")
        acl2 = posix1e.ACL(acl=acl1)
        acl3 = posix1e.ACL(text="u::rw,g::rw,o::r")
        assert acl1 == acl2
        assert acl1 != acl3
        with pytest.raises(TypeError):
          acl1 < acl2
        with pytest.raises(TypeError):
          acl1 >= acl3
        assert acl1 != True
        assert not (acl1 == 1)
        with pytest.raises(TypeError):
          acl1 > True

    @pytest.mark.skipif(not hasattr(posix1e.ACL, "__cmp__"), reason="__cmp__ is missing")
    @NOT_PYPY
    def test_cmp(self):
        acl1 = posix1e.ACL()
        with pytest.raises(TypeError):
          acl1.__cmp__(acl1)

    def test_apply_to_with_wrong_object(self):
        acl1 = posix1e.ACL(text=BASIC_ACL_TEXT)
        assert acl1.valid()
        with pytest.raises(TypeError):
          acl1.applyto(object())
        with pytest.raises(TypeError):
          acl1.applyto(object(), object())

    @require_acl_entry
    def test_acl_iterator(self):
        acl = posix1e.ACL(text=BASIC_ACL_TEXT)
        for entry in acl:
            assert entry.parent is acl


class TestWrite:
    """Write tests"""

    def test_delete_default(self, testdir):
        """Test removing the default ACL"""
        with get_dir(testdir) as dname:
          posix1e.delete_default(dname)

    @NOT_PYPY
    def test_delete_default_wrong_arg(self):
        with pytest.raises(TypeError):
          posix1e.delete_default(object())

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

    def checkRef(self, obj):
        """Checks if a given obj has a 'sane' refcount"""
        if platform.python_implementation() == "PyPy":
            return
        ref_cnt = sys.getrefcount(obj)
        # FIXME: hardcoded value for the max ref count... but I've
        # seen it overflow on bad reference counting, so it's better
        # to be safe
        if ref_cnt < 2 or ref_cnt > 1024:
            pytest.fail("Wrong reference count, expected 2-1024 and got %d" %
                        ref_cnt)

    def test_str(self):
        """Test str() of an ACL."""
        acl = posix1e.ACL(text=BASIC_ACL_TEXT)
        str_acl = str(acl)
        self.checkRef(str_acl)

    def test_append(self):
        """Test append a new Entry to the ACL"""
        acl = posix1e.ACL()
        e = acl.append()
        e.tag_type = posix1e.ACL_OTHER
        ignore_ioerror(errno.EINVAL, acl.calc_mask)
        str_format = str(e)
        self.checkRef(str_format)
        e2 = acl.append(e)
        ignore_ioerror(errno.EINVAL, acl.calc_mask)
        assert not acl.valid()

    def test_wrong_append(self):
        """Test append a new Entry to the ACL based on wrong object type"""
        acl = posix1e.ACL()
        with pytest.raises(TypeError):
          acl.append(object())

    def test_entry_creation(self):
        acl = posix1e.ACL()
        e = posix1e.Entry(acl)
        ignore_ioerror(errno.EINVAL, acl.calc_mask)
        str_format = str(e)
        self.checkRef(str_format)

    def test_entry_failed_creation(self):
        # Checks for partial initialisation and deletion on error
        # path.
        with pytest.raises(TypeError):
          posix1e.Entry(object())

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
          acl.delete_entry(object())

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
          e.copy(object())

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
          e.permset = object()

    def test_permset_creation(self):
        acl = ACL()
        e = acl.append()
        p1 = e.permset
        p2 = Permset(e)
        #self.assertEqual(p1, p2)

    def test_permset_creation_wrong_arg(self):
        with pytest.raises(TypeError):
          Permset(object())

    def test_permset(self):
        """Test permissions"""
        acl = posix1e.ACL()
        e = acl.append()
        ps = e.permset
        ps.clear()
        str_ps = str(ps)
        self.checkRef(str_ps)
        for perm in PERMSETS:
            str_ps = str(ps)
            txt = PERMSETS[perm][0]
            self.checkRef(str_ps)
            assert not ps.test(perm), ("Empty permission set should not"
                                       " have permission '%s'" % txt)
            ps.add(perm)
            assert ps.test(perm), ("Permission '%s' should exist"
                                   " after addition" % txt)
            str_ps = str(ps)
            self.checkRef(str_ps)
            ps.delete(perm)
            assert not ps.test(perm), ("Permission '%s' should not exist"
                                       " after deletion" % txt)

    def test_permset_via_accessors(self):
        """Test permissions"""
        acl = posix1e.ACL()
        e = acl.append()
        ps = e.permset
        ps.clear()
        str_ps = str(ps)
        self.checkRef(str_ps)
        def getter(perm):
            return PERMSETS[perm][1].__get__(ps)
        def setter(parm, value):
            return PERMSETS[perm][1].__set__(ps, value)
        for perm in PERMSETS:
            str_ps = str(ps)
            self.checkRef(str_ps)
            txt = PERMSETS[perm][0]
            assert not getter(perm), ("Empty permission set should not"
                                      " have permission '%s'" % txt)
            setter(perm, True)
            assert ps.test(perm), ("Permission '%s' should exist"
                                   " after addition" % txt)
            assert getter(perm), ("Permission '%s' should exist"
                                  " after addition" % txt)
            str_ps = str(ps)
            self.checkRef(str_ps)
            setter(perm, False)
            assert not ps.test(perm), ("Permission '%s' should not exist"
                                       " after deletion" % txt)
            assert not getter(perm), ("Permission '%s' should not exist"
                                      " after deletion" % txt)

    def test_permset_invalid_type(self):
        acl = posix1e.ACL()
        e = acl.append()
        ps = e.permset
        ps.clear()
        with pytest.raises(TypeError):
          ps.add("foobar")
        with pytest.raises(TypeError):
          ps.delete("foobar")
        with pytest.raises(TypeError):
          ps.test("foobar")
        with pytest.raises(ValueError):
          ps.write = object()

    def test_qualifier_values(self):
        """Tests qualifier correct store/retrieval"""
        acl = posix1e.ACL()
        e = acl.append()
        # work around deprecation warnings
        for tag in [posix1e.ACL_USER, posix1e.ACL_GROUP]:
            qualifier = 1
            e.tag_type = tag
            while True:
                if tag == posix1e.ACL_USER:
                    regex = re.compile("user with uid %d" % qualifier)
                else:
                    regex = re.compile("group with gid %d" % qualifier)
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
        qualifier = sys.maxsize * 2
        for tag in [posix1e.ACL_USER, posix1e.ACL_GROUP]:
            e.tag_type = tag
            with pytest.raises(OverflowError):
                e.qualifier = qualifier

    def test_negative_qualifier(self):
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
          e.qualifier = object()
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

    @pytest.mark.parametrize("tag", ALL_TAG_TYPES)
    def test_tag_types(self, tag):
        """Tests tag type correct set/get"""
        acl = posix1e.ACL()
        e = acl.append()
        e.tag_type = tag
        assert e.tag_type == tag
        # check we can show all tag types without breaking
        assert str(e)

    def test_invalid_tags(self):
        """Tests tag type incorrect set/get"""
        acl = posix1e.ACL()
        e = acl.append()
        with pytest.raises(TypeError):
          e.tag_type = object()
        e.tag_type = posix1e.ACL_USER_OBJ
        # For some reason, PyPy raises AttributeError. Strange...
        with pytest.raises((TypeError, AttributeError)):
          del e.tag_type

        e.tag_type = posix1e.ACL_USER_OBJ
        tag = max(ALL_TAG_TYPES) + 1
        with pytest.raises(EnvironmentError):
          e.tag_type = tag
        # Check tag is still valid.
        assert e.tag_type == posix1e.ACL_USER_OBJ

if __name__ == "__main__":
    unittest.main()
