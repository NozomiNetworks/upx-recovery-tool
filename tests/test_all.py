import os
import tempfile
import unittest

from upxrecoverytool import UpxRecoveryTool, UnsupportedFileError, p_info_s


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
            urt.close()

        # Non-UPX file
        with tempfile.NamedTemporaryFile() as fd:
            urt = UpxRecoveryTool("tests/samples/no_upx", fd.name, True)
            self.assertFalse(urt.is_upx(), "File detected as UPX compressed")
            urt.close()

        # UPX with hidden real EP
        with tempfile.NamedTemporaryFile() as fd:
            urt = UpxRecoveryTool("tests/samples/hidden_ep", fd.name, False)
            self.assertTrue(urt.is_upx(), "Hidden UPX EP was not detected")
            urt.close()

    def test_get_overlay_size(self):

        with tempfile.NamedTemporaryFile() as fd:
            urt = UpxRecoveryTool("tests/samples/overlay_8", fd.name, False)
            urt.init_tmp_buffers()

            overlay_size = urt.get_overlay_size()
            self.assertEqual(overlay_size, 8, f"Wrong detected overlay size {overlay_size} (8 was expected)")

            urt.close()


class TestFixes(unittest.TestCase):

    def test_fix_l_info(self):
        with tempfile.NamedTemporaryFile() as fd:
            urt = UpxRecoveryTool("tests/samples/l_info", fd.name, False)
            urt.fix()

            for upx_sig_off in [0xEC, 0x1C1B, 0x2403, 0x240C]:
                fd.seek(upx_sig_off, os.SEEK_SET)
                sig = fd.read(4)
                self.assertEqual(sig, b"UPX!", f"UPX! sig at 0x{upx_sig_off:X} wasn't fixed")

            urt.close()

    def test_fix_p_info_filesize_and_blocksize(self):

        with tempfile.NamedTemporaryFile() as fd:
            urt = UpxRecoveryTool("tests/samples/p_info_0", fd.name, False)
            urt.fix()

            fd.seek(0xf4, os.SEEK_SET)
            fixed_p_info = p_info_s(fd.read(12))
            self.assertEqual(fixed_p_info.p_blocksize, b"\x38\x49\x00\x00", f"Error fixing p_info.p_blocksize. \
                                38490000 expected but {fixed_p_info.p_blocksize.hex()} was read")
            self.assertEqual(fixed_p_info.p_filesize, b"\x38\x49\x00\x00", f"Error fixing p_info.p_blocksize. \
                                38490000 expected but {fixed_p_info.p_filesize.hex()} was read")

            urt.close()

    def test_fix_overlay(self):
        with tempfile.NamedTemporaryFile() as fd:
            urt = UpxRecoveryTool("tests/samples/overlay_8", fd.name, False)
            urt.fix()

            pre_size = os.path.getsize("tests/samples/overlay_8")
            post_size = os.path.getsize(fd.name)
            size_diff = pre_size - post_size
            self.assertEqual(size_diff, 8, f"Overlay fix error. {size_diff} bytes were removed instead of 8")

            urt.close()
