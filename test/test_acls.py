#
#

import unittest
import os
import tempfile

import posix1e

TEST_DIR=os.environ.get("TESTDIR", ".")

class aclTest(unittest.TestCase):
    """Unittests for ACLs"""

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

    def testFromFile(self):
        """Test loading ACLs from a file"""
        _, fname = self._getfile()
        acl1 = posix1e.ACL(file=fname)
        self.failUnless(acl1.valid(), "ACL is not valid")

    def testFromDir(self):
        """Test loading ACLs from a directory"""
        dname = self._getdir()
        acl1 = posix1e.ACL(file=dname)
        acl2 = posix1e.ACL(filedef=dname)
        self.failUnless(acl1.valid(), "ACL is not valid")
        # default ACLs might or might not be valid; missing ones are
        # not valid, so we don't test acl2 for validity

    def testFromFd(self):
        """Test loading ACLs from a file descriptor"""
        fd, _ = self._getfile()
        acl1 = posix1e.ACL(fd=fd)
        self.failUnless(acl1.valid(), "ACL is not valid")

    if posix1e.HAS_ACL_FROM_MODE:
        def testFromMode(self):
            """Test loading ACLs from an octal mode"""
            acl1 = posix1e.ACL(mode=0644)
            self.failUnless(acl1.valid(), "ACL is not valid")
    else:
        def testFromMode(self):
            """Test loading ACLs from an octal mode (SKIPPED)"""

    def testFromEmpty(self):
        """Test creating an empty ACL"""
        acl1 = posix1e.ACL()


if __name__ == "__main__":
    unittest.main()
