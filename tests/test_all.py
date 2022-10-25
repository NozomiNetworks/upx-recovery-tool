import tempfile
import unittest

from upxrecoverytool import UpxRecoveryTool, UnsupportedFileError


class TestInitialChecks(unittest.TestCase):

    def test_check_file_type(self):

        with tempfile.NamedTemporaryFile() as fd1:
            with tempfile.NamedTemporaryFile() as fd2:
                with self.assertRaises(UnsupportedFileError):
                    UpxRecoveryTool(fd1.name, fd2.name, False)

    def test_is_upx(self):

        # UPX file
        with tempfile.NamedTemporaryFile() as fd:
            urt = UpxRecoveryTool("tests/samples/overlay_8", fd.name, False)
            self.assertTrue(urt.is_upx(), "File not detected as UPX compressed")

        # Non-UPX file
        with tempfile.NamedTemporaryFile() as fd:
            urt = UpxRecoveryTool("tests/samples/no_upx", fd.name, True)
            self.assertFalse(urt.is_upx(), "File detected as UPX compressed")

        # UPX with hidden real EP
        with tempfile.NamedTemporaryFile() as fd:
            urt = UpxRecoveryTool("tests/samples/hidden_ep", fd.name, False)
            self.assertTrue(urt.is_upx(), "Hidden UPX EP was not detected")

    def test_get_overlay_size(self):

        with tempfile.NamedTemporaryFile() as fd:
            urt = UpxRecoveryTool("tests/samples/overlay_8", fd.name, False)
            urt.init_tmp_buffers()
            overlay_size = urt.get_overlay_size()
            self.assertEqual(overlay_size, 8, f"Wrong detected overlay size {overlay_size} (8 was expected)")


class TestFixes(unittest.TestCase):

    def test_fix_l_info(self):
        pass

    def test_fix_p_info_filesize(self):
        pass

    def test_fix_p_info_blocksize(self):
        pass

    def test_fix_p_info_filesize_and_blocksize(self):
        pass

    def test_fix_overlay(self):
        pass
