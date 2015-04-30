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

import posix1e
from posix1e import *

TEST_DIR = os.environ.get("TEST_DIR", ".")

BASIC_ACL_TEXT = "u::rw,g::r,o::-"

# This is to workaround python 2/3 differences at syntactic level
# (which can't be worked around via if's)
M0500 = 320 # octal 0500
M0644 = 420 # octal 0644
M0755 = 493 # octal 755

# Check if running under Python 3
IS_PY_3K = sys.hexversion >= 0x03000000

def _skip_test(fn):
    """Wrapper to skip a test"""
    new_fn = lambda x: None
    new_fn.__doc__ = "SKIPPED %s" % fn.__doc__
    return new_fn


def has_ext(extension):
    """Decorator to skip tests based on platform support"""
    if not extension:
        return _skip_test
    else:
        return lambda x: x

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

class aclTest:
    """Support functions ACLs"""

    def setUp(self):
        """set up function"""
        self.rmfiles = []
        self.rmdirs = []

    def tearDown(self):
        """tear down function"""
        for fname in self.rmfiles:
            os.unlink(fname)
        for dname in self.rmdirs:
            os.rmdir(dname)

    def _getfile(self):
        """create a temp file"""
        fh, fname = tempfile.mkstemp(".test", "xattr-", TEST_DIR)
        self.rmfiles.append(fname)
        return fh, fname

    def _getdir(self):
        """create a temp dir"""
        dname = tempfile.mkdtemp(".test", "xattr-", TEST_DIR)
        self.rmdirs.append(dname)
        return dname

    def _getsymlink(self):
        """create a symlink"""
        fh, fname = self._getfile()
        os.close(fh)
        os.unlink(fname)
        os.symlink(fname + ".non-existent", fname)
        return fname


class LoadTests(aclTest, unittest.TestCase):
    """Load/create tests"""
    def testFromFile(self):
        """Test loading ACLs from a file"""
        _, fname = self._getfile()
        acl1 = posix1e.ACL(file=fname)
        self.assertTrue(acl1.valid(), "ACL read from file should be valid")

    def testFromDir(self):
        """Test loading ACLs from a directory"""
        dname = self._getdir()
        acl1 = posix1e.ACL(file=dname)
        acl2 = posix1e.ACL(filedef=dname)
        self.assertTrue(acl1.valid(),
                        "ACL read from directory should be valid")
        # default ACLs might or might not be valid; missing ones are
        # not valid, so we don't test acl2 for validity

    def testFromFd(self):
        """Test loading ACLs from a file descriptor"""
        fd, _ = self._getfile()
        acl1 = posix1e.ACL(fd=fd)
        self.assertTrue(acl1.valid(), "ACL read from fd should be valid")

    def testFromEmpty(self):
        """Test creating an empty ACL"""
        acl1 = posix1e.ACL()
        self.assertFalse(acl1.valid(), "Empty ACL should not be valid")

    def testFromText(self):
        """Test creating an ACL from text"""
        acl1 = posix1e.ACL(text=BASIC_ACL_TEXT)
        self.assertTrue(acl1.valid(),
                        "ACL based on standard description should be valid")

class AclExtensions(aclTest, unittest.TestCase):
    """ACL extensions checks"""

    @has_ext(HAS_ACL_FROM_MODE)
    def testFromMode(self):
        """Test loading ACLs from an octal mode"""
        acl1 = posix1e.ACL(mode=M0644)
        self.assertTrue(acl1.valid(),
                        "ACL created via octal mode shoule be valid")

    @has_ext(HAS_ACL_CHECK)
    def testAclCheck(self):
        """Test the acl_check method"""
        acl1 = posix1e.ACL(text=BASIC_ACL_TEXT)
        self.assertFalse(acl1.check(), "ACL is not valid")
        acl2 = posix1e.ACL()
        self.assertTrue(acl2.check(), "Empty ACL should not be valid")

    @has_ext(HAS_EXTENDED_CHECK)
    def testExtended(self):
        """Test the acl_extended function"""
        fd, fname = self._getfile()
        basic_acl = posix1e.ACL(text=BASIC_ACL_TEXT)
        basic_acl.applyto(fd)
        for item in fd, fname:
            self.assertFalse(has_extended(item),
                             "A simple ACL should not be reported as extended")
        enhanced_acl = posix1e.ACL(text="u::rw,g::-,o::-,u:root:rw,mask::r")
        self.assertTrue(enhanced_acl.valid(),
                        "Failure to build an extended ACL")
        enhanced_acl.applyto(fd)
        for item in fd, fname:
            self.assertTrue(has_extended(item),
                            "An extended ACL should be reported as such")

    @has_ext(HAS_EQUIV_MODE)
    def testEquivMode(self):
        """Test the equiv_mode function"""
        if HAS_ACL_FROM_MODE:
            for mode in M0644, M0755:
                acl = posix1e.ACL(mode=mode)
                self.assertEqual(acl.equiv_mode(), mode)
        acl = posix1e.ACL(text="u::rw,g::r,o::r")
        self.assertEqual(acl.equiv_mode(), M0644)
        acl = posix1e.ACL(text="u::rx,g::-,o::-")
        self.assertEqual(acl.equiv_mode(), M0500)


class WriteTests(aclTest, unittest.TestCase):
    """Write tests"""

    def testDeleteDefault(self):
        """Test removing the default ACL"""
        dname = self._getdir()
        posix1e.delete_default(dname)

    def testReapply(self):
        """Test re-applying an ACL"""
        fd, fname = self._getfile()
        acl1 = posix1e.ACL(fd=fd)
        acl1.applyto(fd)
        acl1.applyto(fname)
        dname = self._getdir()
        acl2 = posix1e.ACL(file=fname)
        acl2.applyto(dname)


class ModificationTests(aclTest, unittest.TestCase):
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
            self.fail("Wrong reference count, expected 2-1024 and got %d" %
                      ref_cnt)

    def testStr(self):
        """Test str() of an ACL."""
        acl = posix1e.ACL(text=BASIC_ACL_TEXT)
        str_acl = str(acl)
        self.checkRef(str_acl)

    @has_ext(HAS_ACL_ENTRY)
    def testAppend(self):
        """Test append a new Entry to the ACL"""
        acl = posix1e.ACL()
        e = acl.append()
        e.tag_type = posix1e.ACL_OTHER
        ignore_ioerror(errno.EINVAL, acl.calc_mask)
        str_format = str(e)
        self.checkRef(str_format)

    @has_ext(HAS_ACL_ENTRY)
    def testDelete(self):
        """Test delete Entry from the ACL"""
        acl = posix1e.ACL()
        e = acl.append()
        e.tag_type = posix1e.ACL_OTHER
        ignore_ioerror(errno.EINVAL, acl.calc_mask)
        acl.delete_entry(e)
        ignore_ioerror(errno.EINVAL, acl.calc_mask)

    @has_ext(HAS_ACL_ENTRY)
    def testDoubleEntries(self):
        """Test double entries"""
        acl = posix1e.ACL(text=BASIC_ACL_TEXT)
        self.assertTrue(acl.valid(), "ACL is not valid")
        for tag_type in (posix1e.ACL_USER_OBJ, posix1e.ACL_GROUP_OBJ,
                         posix1e.ACL_OTHER):
            e = acl.append()
            e.tag_type = tag_type
            e.permset.clear()
            self.assertFalse(acl.valid(),
                "ACL containing duplicate entries"
                " should not be valid")
            acl.delete_entry(e)

    @has_ext(HAS_ACL_ENTRY)
    def testMultipleGoodEntries(self):
        """Test multiple valid entries"""
        acl = posix1e.ACL(text=BASIC_ACL_TEXT)
        self.assertTrue(acl.valid(), "ACL is not valid")
        for tag_type in (posix1e.ACL_USER,
                         posix1e.ACL_GROUP):
            for obj_id in range(5):
                e = acl.append()
                e.tag_type = tag_type
                e.qualifier = obj_id
                e.permset.clear()
                acl.calc_mask()
                self.assertTrue(acl.valid(),
                    "ACL should be able to hold multiple"
                    " user/group entries")

    @has_ext(HAS_ACL_ENTRY)
    def testMultipleBadEntries(self):
        """Test multiple invalid entries"""
        for tag_type in (posix1e.ACL_USER,
                         posix1e.ACL_GROUP):
            acl = posix1e.ACL(text=BASIC_ACL_TEXT)
            self.assertTrue(acl.valid(), "ACL built from standard description"
                                         " should be valid")
            e1 = acl.append()
            e1.tag_type = tag_type
            e1.qualifier = 0
            e1.permset.clear()
            acl.calc_mask()
            self.assertTrue(acl.valid(), "ACL should be able to add a"
                " user/group entry")
            e2 = acl.append()
            e2.tag_type = tag_type
            e2.qualifier = 0
            e2.permset.clear()
            ignore_ioerror(errno.EINVAL, acl.calc_mask)
            self.assertFalse(acl.valid(), "ACL should not validate when"
                " containing two duplicate entries")
            acl.delete_entry(e1)
            # FreeBSD trips over itself here and can't delete the
            # entry, even though it still exists.
            ignore_ioerror(errno.EINVAL, acl.delete_entry, e2)

    @has_ext(HAS_ACL_ENTRY)
    def testPermset(self):
        """Test permissions"""
        acl = posix1e.ACL()
        e = acl.append()
        ps = e.permset
        ps.clear()
        str_ps = str(ps)
        self.checkRef(str_ps)
        pmap = {
            posix1e.ACL_READ: "read",
            posix1e.ACL_WRITE: "write",
            posix1e.ACL_EXECUTE: "execute",
            }
        for perm in pmap:
            str_ps = str(ps)
            self.checkRef(str_ps)
            self.assertFalse(ps.test(perm), "Empty permission set should not"
                " have permission '%s'" % pmap[perm])
            ps.add(perm)
            self.assertTrue(ps.test(perm), "Permission '%s' should exist"
                " after addition" % pmap[perm])
            str_ps = str(ps)
            self.checkRef(str_ps)
            ps.delete(perm)
            self.assertFalse(ps.test(perm), "Permission '%s' should not exist"
                " after deletion" % pmap[perm])


    @has_ext(HAS_ACL_ENTRY and IS_PY_3K)
    def testQualifierValues(self):
        """Tests qualifier correct store/retrieval"""
        acl = posix1e.ACL()
        e = acl.append()
        # work around deprecation warnings
        if hasattr(self, 'assertRegex'):
            fn = self.assertRegex
        else:
            fn = self.assertRegexpMatches
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
                self.assertEqual(e.qualifier, qualifier)
                fn(str(e), regex)
                qualifier *= 2

    @has_ext(HAS_ACL_ENTRY and IS_PY_3K)
    def testQualifierOverflow(self):
        """Tests qualifier overflow handling"""
        acl = posix1e.ACL()
        e = acl.append()
        qualifier = sys.maxsize * 2
        for tag in [posix1e.ACL_USER, posix1e.ACL_GROUP]:
            e.tag_type = tag
            with self.assertRaises(OverflowError):
                e.qualifier = qualifier

    @has_ext(HAS_ACL_ENTRY and IS_PY_3K)
    def testNegativeQualifier(self):
        """Tests negative qualifier handling"""
        # Note: this presumes that uid_t/gid_t in C are unsigned...
        acl = posix1e.ACL()
        e = acl.append()
        for tag in [posix1e.ACL_USER, posix1e.ACL_GROUP]:
            e.tag_type = tag
            for qualifier in [-10, -5, -1]:
                with self.assertRaises(OverflowError):
                    e.qualifier = qualifier


if __name__ == "__main__":
    unittest.main()
