"""Linux root-only regression tests for the stdin-only unit writer."""
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest

HELPER = Path(__file__).with_name("privileged_unit_write.py")

@unittest.skipUnless(os.name == "posix" and hasattr(os, "geteuid") and os.geteuid() == 0, "requires Linux root")
class WriterTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(dir="/root", prefix="feldjaeger-test-")
        self.root = Path(self.directory.name)
        self.target = self.root / "xray.service"
    def tearDown(self):
        self.directory.cleanup()
    def write(self, target=None, body=b"[Service]\nExecStart=/bin/true\n", cached=False):
        data = (b"password\n" if cached else b"") + b"marker\n" + body
        return subprocess.run([sys.executable, "-I", str(HELPER), str(target or self.target),
            "marker", str(len(body))], input=data, capture_output=True, timeout=5)
    def test_create_replace_and_cached_frame(self):
        self.assertEqual(self.write().returncode, 0)
        self.assertEqual(self.write(body=b"new", cached=True).returncode, 0)
        self.assertEqual(self.target.read_bytes(), b"new")
        self.assertEqual(stat.S_IMODE(self.target.stat().st_mode), 0o644)
        self.assertEqual(self.target.stat().st_uid, 0)
        self.assertEqual(list(self.root.iterdir()), [self.target])
    def test_symlink_does_not_touch_victim(self):
        victim = self.root / "victim"
        victim.write_bytes(b"old")
        self.target.symlink_to(victim)
        self.assertNotEqual(self.write().returncode, 0)
        self.assertEqual(victim.read_bytes(), b"old")
        self.assertTrue(self.target.is_symlink())
        self.assertEqual(len(list(self.root.iterdir())), 2)
    def test_fifo_refused(self):
        os.mkfifo(self.target)
        self.assertNotEqual(self.write().returncode, 0)
        self.assertTrue(stat.S_ISFIFO(self.target.lstat().st_mode))
    def test_shared_foreign_and_symlink_parent_refused(self):
        for mode, owner in [(0o777, 0), (0o700, 12345)]:
            parent = self.root / str(owner)
            parent.mkdir()
            parent.chmod(mode)
            os.chown(parent, owner, owner)
            self.assertNotEqual(self.write(parent / "x.service").returncode, 0)
            self.assertEqual(list(parent.iterdir()), [])
        link = self.root / "alias"
        link.symlink_to(self.root, target_is_directory=True)
        self.assertNotEqual(self.write(link / "x.service").returncode, 0)
    def test_bad_frame_keeps_existing_file(self):
        self.target.write_bytes(b"old")
        result = subprocess.run([sys.executable, "-I", str(HELPER), str(self.target), "marker", "3"],
            input=b"bad\nframe\nsecret", capture_output=True, timeout=5)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn(b"secret", result.stderr)
        self.assertEqual(self.target.read_bytes(), b"old")

if __name__ == "__main__":
    unittest.main()
