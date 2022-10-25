#! /usr/bin/python3

import os
import lief
import mmap
import yara
import magic
import shutil
import struct
import argparse
import tempfile


class UnsupportedFileError(Exception):
    pass


class NonUpxError(Exception):
    pass


class CorruptedFileError(Exception):
    pass


class l_info_s:
    l_checksum: bytes  # checksum
    l_magic: bytes  # UPX! magic[55 50 58 21]
    l_lsize: bytes  # loader size
    l_version: bytes  # version info
    l_format: bytes  # UPX format

    def __init__(self, buff):
        self.l_checksum = buff[0:4]
        self.l_magic = buff[4:8]
        self.l_lsize = buff[8:10]
        self.l_version = buff[10:11]
        self.l_version = buff[11:12]


class p_info_s:
    p_progid: bytes
    p_filesize: bytes  # Size of the unpacked file
    p_blocksize: bytes  # Size of the unpacked file

    def __init__(self, buff):
        self.p_progid = buff[0:4]
        self.p_filesize = buff[4:8]
        self.p_blocksize = buff[8:12]


class PackHeader:
    u_file_size: bytes

    def __init__(self, file_mmap):
        ph_offset = file_mmap.rfind(b"UPX!")

        if ph_offset > file_mmap.size() - 36:
            raise CorruptedFileError("Parsing PackHeader")

        elif ph_offset < file_mmap.size() - 36:
            overlay_count = file_mmap.size() - 36 - ph_offset
            print("[!] Possible error parsing PackHeader:")
            print("    - Maybe not all UPX! magic bytes could be found")
            print(f"    - Or input file may contain {overlay_count} bytes of overlay")

        size_offset = ph_offset + 24
        self.u_file_size = file_mmap[size_offset: size_offset + 4]


class UpxRecoveryTool:

    upx_sigs = {
        "Intel 80386": "intel_80386.yar",
        "x86-64": "x86-64.yar",
        "MIPS": "mips.yar",
        "ARM": "arm.yar",
        "PowerPC or cisco 4500": "powerpc.yar",
    }

    def __init__(self, in_file, out_file, assume_upx):
        """ Initialization method. Receives the path to the file to be fixed and the output path for the result """

        self.in_fd = None
        self.tmp_fd = None
        self.buff = None
        self.in_file = in_file
        self.out_file = out_file
        self.tmp_file = None
        self.tmp_folder = None

        # Check that the file type is ELF and that the arch is supported
        self.check_file_type()

        # File is ELF, so it can be parsed
        self.in_fd = open(self.in_file, "rb")
        self.elf = lief.parse(self.in_file)

        # Get file size for boudaries checks
        self.file_size = os.fstat(self.in_fd.fileno()).st_size

        if not assume_upx:
            # Check if it is packed with UPX
            if not self.is_upx():
                raise NonUpxError
        else:
            print("[i] Assuming file is UPX")

        # Get UPX version. p_info fix doesn't work with UPX 4
        self.detect_version()

    def check_file_type(self):
        """ Method to check if the class will be able to analyze this file """

        if not os.path.isfile(self.in_file):
            raise UnsupportedFileError("No input file provided")

        # Check magic filetype
        magic_str = magic.from_file(self.in_file)

        if magic_str.startswith("ELF "):
            self.exe_type = "ELF"
            magic_arch = magic_str.split(',')[1].strip()

            if magic_arch in self.upx_sigs.keys():
                self.arch = magic_arch
                return

        raise UnsupportedFileError(f"Unsupported file type '{magic_str}'")

    def is_upx(self):
        """ Method that looks for ASM signatures to identify a UPX executable """

        rules_path = os.path.join("rules", self.upx_sigs[self.arch])
        rules = yara.compile(rules_path)
        matches = rules.match(self.in_file)

        if matches:
            print("[i] File is UPX")

            if len(matches) == 1:
                if matches[0].rule == "upx_init_code_not_ep":
                    print(
                        "[!] UPX entry point signature is in an address different from the entry point")

            # 2 matches. EP code found in EP and other address
            else:
                print("[!] Multiple UPX entrypoint code found in the same file")

            return True

        return False

    def detect_version(self):
        """ Method to identify the UPX version used to pack the executable """
        # TODO: The current detection method is very naive and can be easily tricked

        # Load file in memory to look for a string with a version
        self.in_fd.seek(0)
        in_buff = self.in_fd.read()

        # Detect UPX version
        version_off = in_buff.find(b"$Id: UPX ")
        if version_off == -1:
            print("[!] UPX version could not be detected")
            self.version = None
        else:
            self.version = int(in_buff[version_off + 9: version_off + 10])
            # TODO: Use 're' to get major and minor version

    def load_structs(self):

        eh = self.elf.header

        # l_info
        self.l_info_off = eh.program_header_offset + eh.numberof_segments * eh.program_header_size

        if self.l_info_off + 12 > self.file_size:
            raise CorruptedFileError("Parsing l_info structure")

        l_info_mem = self.buff[self.l_info_off: self.l_info_off + 12]
        self.l_info = l_info_s(l_info_mem)

        # p_info
        self.p_info_off = self.l_info_off + 12

        if self.p_info_off + 12 > self.file_size:
            raise CorruptedFileError("Parsing p_info structure")

        p_info_mem = self.buff[self.p_info_off: self.p_info_off + 12]
        self.p_info = p_info_s(p_info_mem)

    def patch(self, patch_bytes, offset):
        """ Method to patch bytes in the output binary """

        if offset + len(patch_bytes) > self.file_size:
            raise CorruptedFileError("Patching bytes")

        self.buff[offset: offset + len(patch_bytes)] = patch_bytes

    def get_ep_bytes(self, num_bytes):
        """ Method to get the first 'num_bytes' of the executable's Entry Point. Used to apply UPX signatures """

        ep_bytes_list = self.elf.get_content_from_virtual_address(self.elf.entrypoint, num_bytes)
        ep_bytes = bytearray(ep_bytes_list)

        return ep_bytes

    def get_overlay_size(self):
        """ Method to check if it seems that the file contains overlay data after a proper PackHeader """

        overlay_size = 0
        upx_count = 0

        upx_offset = self.buff.find(b"UPX!", 0)

        while upx_offset != -1:
            upx_count += 1
            last_upx_offset = upx_offset
            upx_offset = self.buff.find(b"UPX!", upx_offset + 4)

        # If there are less than 3 UPX! sigs, we can't be sure the PackHeader can be easily found
        if upx_count >= 3:
            if last_upx_offset < self.buff.size() - 36:
                overlay_size = self.buff.size() - 36 - last_upx_offset

        return overlay_size

    def init_tmp_buffers(self):
        """ Method to initialize internal temporary buffers """

        self.tmp_folder = tempfile.TemporaryDirectory()
        self.tmp_file = os.path.join(self.tmp_folder.name, os.path.basename(self.out_file))
        shutil.copy(self.in_file, self.tmp_file)

        self.tmp_fd = open(self.tmp_file, "r+b")
        self.buff = mmap.mmap(self.tmp_fd.fileno(), 0)

    def fix(self):
        """ Method to fix all the (supported) modifications of UPX """

        fixed = False

        self.init_tmp_buffers()
        self.load_structs()

        fixed |= self.fix_l_info()

        # Now that UPX! magic bytes are restored, PackHeader can be properly loaded
        self.pack_hdr = PackHeader(self.buff)

        fixed |= self.fix_overlay()

        if self.version != 4:
            fixed |= self.fix_p_info()

        if fixed:
            shutil.copy(self.tmp_file, self.out_file)

    def fix_l_info(self):
        """ Method to check and fix modifications of l_info structure """

        fixed = False

        print("[i] Checking l_info structure...")

        # Check and fix l_magic (UPX!) modification
        if self.l_info.l_magic != b"UPX!":
            fixed = True
            print(f'[!] l_info.l_magic mismatch: "{self.l_info.l_magic}" found instead')

            # Replace all modified l_magic bytes
            magic_offset = self.buff.find(self.l_info.l_magic)

            while magic_offset != -1:
                self.patch(b"UPX!", magic_offset)
                print(f"  [i] UPX! magic bytes patched @ 0x{magic_offset:x}")
                magic_offset = self.buff.find(self.l_info.l_magic, magic_offset + 4)

        if not fixed:
            print("  [i] No l_info fixes required")

        return fixed

        # Worst case: Different l_magic used along the file
        # It is also possible to check the magic value at the end of the file
        # last_magic_offset = len(self.buff)-36
        # mod_upx_magic = self.buff[last_magic_offset:last_magic_offset+4]

    def fix_p_info(self):
        """ Method to check and fix modifications of p_info structure """

        # “p_info” is the size of the unpacked file. “p_info” and “p_filesize” contain the same value.
        # p_filesize is @ last UPX! sig offset + 24

        fixed = False

        print("[i] Checking p_info structure...")

        # Zeroed sizes
        if self.p_info.p_filesize == b"\x00\x00\x00\x00" or self.p_info.p_blocksize == b"\x00\x00\x00\x00":
            fixed = True
            if self.p_info.p_filesize == b"\x00\x00\x00\x00":
                print("[!] Zeroed p_info.p_filesize")
            if self.p_info.p_blocksize == b"\x00\x00\x00\x00":
                print("[!] Zeroed p_info.p_blocksize")

            self.fix_p_info_sizes()

        # Size mismatch
        if self.p_info.p_filesize != self.p_info.p_blocksize:
            fixed = True
            print("[!] p_info.p_filesize and p_info.p_blocksize mismatch")
            self.fix_p_info_sizes()

        if not fixed:
            print("  [i] No p_info fixes required")

        return fixed

        # TODO: Same values but non-sense size
        # This could happen with UPXv4, but this kind of files shouldn't reach this point

    def fix_p_info_sizes(self):
        """ Method to fix the p_info.p_filesize and p_info.p_blocksize values """

        # p_filesize
        self.patch(self.pack_hdr.u_file_size, self.p_info_off + 4)
        # p_blocksize
        self.patch(self.pack_hdr.u_file_size, self.p_info_off + 8)

        int_size = struct.unpack("<i", self.pack_hdr.u_file_size)[0]
        print(f"  [i] Fixed p_info sizes with value 0x{int_size:x} from PackHeader")

    def fix_overlay(self):
        """ Method to crop the file to remove overlay bytes  """

        fixed = False

        overlay_size = self.get_overlay_size()
        if overlay_size > 0:
            new_size = self.buff.size() - overlay_size
            print(f"[i] Removing {overlay_size} bytes of overlay")

            # self.buff.resize may fail on BSD and Mac
            self.tmp_fd.truncate(new_size)

            fixed = True

        return fixed

    def close(self):
        """ Method to close memory buffers and file descriptors """
        # Close mmap
        if self.buff is not None:
            self.buff.flush()
            self.buff.close()

        # Close file descriptors
        if self.in_fd is not None:
            self.in_fd.close()

        if self.tmp_fd is not None:
            self.tmp_fd.close()

        # Remove temporary file and dir
        self.tmp_folder.cleanup()


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="Script to check and fix UPX files modifications")
    parser.add_argument('-i', dest='input', required=True, help="Path to supposed UPX file to be fixed")
    parser.add_argument('-o', dest='output', required=True, help="Path to write the fixed version of the file")
    parser.add_argument('-a', '--assume-upx', action='store_true', help=f"Assume file is UPX. Use it when \
        {parser.prog} doesn't detect the input as UPX and you think it is wrong.")
    args = parser.parse_args()

    urt = None

    try:
        urt = UpxRecoveryTool(args.input, args.output, args.assume_upx)
        urt.fix()

    except UnsupportedFileError as why:
        print(f"[-] Unsupported file '{args.input}': {why}")

    except NonUpxError:
        print(f"[-] {args.input} doesn't seem to be a UPX-packed file")

    except CorruptedFileError as why:
        print(f"[-] The input file could be corrupted. Error while {why}")

    finally:
        if urt is not None:
            urt.close()
