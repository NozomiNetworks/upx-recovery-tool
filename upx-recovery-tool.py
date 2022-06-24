#! /usr/bin/python3

import os
import re
import mmap
import magic
import shutil
import struct
import argparse
from elftools.elf.elffile import ELFFile


class l_info_s:
    l_checksum: bytes # checksum
    l_magic: bytes # UPX! magic[55 50 58 21]
    l_lsize: bytes # loader size
    l_version: bytes # version info
    l_format: bytes # UPX format

    def __init__(self, buff):
        self.l_checksum = buff[0:4]
        self.l_magic = buff[4:8]
        self.l_lsize = buff[8:10]
        self.l_version = buff[10:11]
        self.l_version = buff[11:12]


class p_info_s:
    p_progid: bytes
    p_filesize: bytes # Size of unpacked file
    p_blocksize: bytes # Size of unpacked file

    def __init__(self, buff):
        self.p_progid = buff[0:4]
        self.p_filesize = buff[4:8]
        self.p_blocksize = buff[8:12]
        

class UnsupportedFileError(Exception):
    pass


class NonUpxError(Exception):
    pass


class CorruptedFileError(Exception):
    pass


class UpxRecoveryTool:

    upx_sigs = {
        "Intel 80386": [
            br"^\x50\xe8.{2}\x00\x00\xeb.\x5a\x58\x59\x97\x60\x8a\x54\x24\x20\xe9.{2}\x00\x00\x60\x8b\x74\x24\x24\x8b\x7c\x24\x2c\x83\xcd",
        ],
        "x86-64": [
            # ucl
            br"^\x50\x52\xe8.{4}\x55\x53\x51\x52\x48\x01\xfe\x56\x48\x89\xfe\x48\x89\xd7\x31\xdb\x31\xc9\x48\x83\xcd\xff\xe8",
            # lzma
            br"^\x50\x52\xe8.{4}\x55\x53\x51\x52\x48\x01\xfe\x56\x41\x80\xf8\x0e\x0f.{5}\x55\x48\x89\xe5\x44\x8b\x09",
        ],
        "MIPS": [
            # upx_mips_be
            br"^\x04\x11.{2}\x27\xfe\x00\x00\x27\xbd\xff\xfc\xaf\xbf\x00\x00\x00\xa4\x28\x20\xac\xe6\x00\x00\x3c\x0d\x80\x00\x01\xa0\x48\x21\x24\x0b\x00\x01\x04\x11",
            br"^\x04\x11.{2}\x27\xf7\x00\x00\x90\x99\x00\x00\x24\x01\xfa\x00\x90\x98\x00\x01\x33\x22\x00\x07\x00\x19\xc8\xc2\x03\x21\x08\x04",
            # upx_mips_le
            br"^.{2}\x11\x04\x00\x00\xfe\x27\xfc\xff\xbd\x27\x00\x00\xbf\xaf\x20\x28\xa4\x00\x00\x00\xe6\xac\x00\x80\x0d\x3c\x21\x48\xa0\x01\x01\x00\x0b\x24.{2}\x11\x04",
            br"^.{2}\x11\x04\x00\x00\xf7\x27\x00\x00\x99\x90\x00\xfa\x01\x24\x01\x00\x98\x90\x07\x00\x22\x33\xc2\xc8\x19\x00\x04\x08\x21\x03",
        ],
        "ARM": [
            br"^\x1c\xc0\x4f\xe2.{2}\x9c\xe8\x02\x00\xa0\xe1\x0c\xb0\x8b\xe0\x0c\xa0\x8a\xe0\x00\x30\x9b\xe5\x01\x90\x4c\xe0\x01\x20\xa0\xe1",
            br"^\x18\xd0\x4d\xe2.{2}\x00\xeb\x00\xc0\xdd\xe5\x0e\x00\x5c\xe3.\x02\x00\x1a\x0c\x48\x2d\xe9\x00\xb0\xd0\xe5\x06\xcc\xa0\xe3",
            br"^\x18\xd0\x4d\xe2.{2}\x00\xeb\x00\x10\x81\xe0\x3e\x40\x2d\xe9\x00\x50\xe0\xe3\x02\x41\xa0\xe3.{2}\x00\xea\x1a\x00\xbd\xe8",
        ],
        "PowerPC or cisco 4500": [
            # ucl
            br"^\x48\x00.{2}\x7c\x00\x29\xec\x7d\xa8\x02\xa6\x28\x07\x00\x02\x40\x82\x00\xe4\x90\xa6\x00\x00",
            # lzma
            br"^\x48\x00.{2}\x28\x07\x00\x0e\x40\x82\x0a\x4c\x94\x21\xff\xe8\x7c\x08\x02\xa6\x7c\xc9\x33\x78\x81\x06\x00\x00\x7c\xa7\x2b\x78",
        ],
    }

    def __init__(self, in_file, out_file):
        """ Initialization method. Receives the file to be read and the output path to write the fixed UPX """
        
        self.in_fd = None
        self.out_fd = None
        self.buff = None
        self.in_file = in_file
        self.out_file = out_file

        # Check file type is ELF and arch is supported
        self.check_file_type()

        # File is ELF, so it can be parsed
        self.in_fd = open(self.in_file, "rb")
        self.elf = ELFFile(self.in_fd)

        # Get file size for boudaries checks
        self.file_size = os.fstat(self.in_fd.fileno()).st_size
        
        # Check if is UPX
        if not self.is_upx():
            self.close()
            raise NonUpxError

        # Get UPX version. p_info fix doesn't work with UPX 4
        self.detect_version()

    def check_file_type(self):
        """ Method to check if the class will be able to analyze this type of file """

        if not os.path.isfile(self.in_file):
            self.close()
            raise UnsupportedFileError("Is not a file")

        # Check magic filetype
        magic_str = magic.from_file(self.in_file)
        
        if magic_str.startswith("ELF "):
            self.exe_type = "ELF"
            magic_arch = magic_str.split(',')[1].strip()

            if magic_arch in self.upx_sigs.keys():
                self.arch = magic_arch
                return

        self.close()
        raise UnsupportedFileError(f"Unsupported file type '{magic_str}'")

    def is_upx(self):
        """ Method that looks for ASM signatures to identify an UPX executable """

        # Instead of looking for the pattern in all the executable bytes, look for the
        # UPX sigs in the EP. The code is not so beauty, but it'll be more efficient.
        ep_bytes = self.get_ep_bytes(50)

        for sig in self.upx_sigs[self.arch]:
            if re.match(sig, ep_bytes, re.DOTALL):
                return True

        return False

    def detect_version(self):
        """ Method to know the UPX version used to pack the executable """
        # TODO: The current detection method is very naive and can be easily tricked

        # Load file in memory to look for string with version
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
        self.l_info_off = eh.e_phoff + eh.e_phnum * eh.e_phentsize

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
        """ Method to get the first 'num_bytes' of the executable's Entry Point. Used to detect UPX signatures """
        
        ep_bytes = None
        ep = self.elf.header['e_entry']

        # Loop segments looking where the EP is
        for seg in self.elf.iter_segments():
            sh = seg.header
            if ep > sh.p_vaddr and ep < sh.p_vaddr + sh.p_memsz:
                start_off = ep - sh.p_vaddr

                if start_off + num_bytes > self.file_size:
                    raise CorruptedFileError("Walking throug program headers")

                ep_bytes = seg.data()[start_off: start_off + num_bytes]

        return ep_bytes

    def fix(self):
        """ Method to fix all the (supported) modifications to UPX """

        try:
            shutil.copy(self.in_file, self.out_file)

            self.out_fd = open(self.out_file, "r+b")
            self.buff = mmap.mmap(self.out_fd.fileno(), 0)

            self.load_structs()

            self.fix_l_info()

            if self.version != 4:
                self.fix_p_info()

        finally:
            self.close()

    def fix_l_info(self):
        """ Method to check and fix modifications of l_info structure """

        # Check and fix l_magic (UPX!) modification 
        if self.l_info.l_magic != b"UPX!":
            print(f'[!] l_info.l_magic mismatch: "{self.l_info.l_magic}" found instead')

            # Replace all modified l_magic bytes
            magic_offset = self.buff.find(self.l_info.l_magic)

            while magic_offset != -1:
                self.patch(b"UPX!", magic_offset)
                print(f"  [i] UPX! magic bytes patched @ 0x{magic_offset:x}")
                magic_offset = self.buff.find(self.l_info.l_magic, magic_offset + 4)

        # Worst case: Different l_magic used along the file
        # It is also possible check magic at the end of the file
        #last_magic_offset = len(self.buff)-36
        #mod_upx_magic = self.buff[last_magic_offset:last_magic_offset+4]

    def fix_p_info(self):
        """ Method to check and fix modifications of p_info structure """

        # “p_info” is the size of the unpacked file. “p_info” and “p_filesize” contain the same value.
        # p_filesize is @ last UPX! sig offset + 24

        # Zeroed sizes
        if self.p_info.p_filesize == b"\x00\x00\x00\x00" or self.p_info.p_blocksize == b"\x00\x00\x00\x00":

            if self.p_info.p_filesize == b"\x00\x00\x00\x00":
                print("[!] Zeroed p_info.p_filesize")
            if self.p_info.p_blocksize == b"\x00\x00\x00\x00":
                print("[!] Zeroed p_info.p_blocksize")
            
            self.fix_p_info_sizes()

        # Size mismatch
        if self.p_info.p_filesize != self.p_info.p_blocksize:
            print("[!] p_info.p_filesize and p_info.p_blocksize mismatch")
            self.fix_p_info_sizes()

        # TODO: Same values but non-sense size
        # This could happen with UPXv4, but this kind of files shouldn't reach this point

    def fix_p_info_sizes(self):
        """ Method to fix the p_info.p_filesize and p_info.p_blocksize values """

        # At this point, UPX! magic values are already fixed
        # p_filesize is @ last UPX! sig last byte + 24

        # Look for last UPX! magic value
        last_offset = self.buff.rfind(b"UPX!")
        size_offset = last_offset + 24
        real_size = self.buff[size_offset: size_offset + 4]

        # p_filesize
        self.patch(real_size, self.p_info_off + 4)
        # p_blocksize
        self.patch(real_size, self.p_info_off + 8)

        int_size = struct.unpack("<i", real_size)[0]
        print(f"  [i] Fixed p_info sizes with value 0x{int_size:x}")

    def close(self):
        """ Method to close memory buffers and file descriptors """
        # Close mmap
        if self.buff is not None:
            self.buff.flush()
            self.buff.close()

        # Close file descriptors
        if self.in_fd is not None:
            self.in_fd.close()

        if self.out_fd is not None:
            self.out_fd.close()


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="Script to check and fix UPX files modifications")
    parser.add_argument('-i', dest='input', required=True, help="Path to supposed UPX file to be fixed")
    parser.add_argument('-o', dest='output', required=True, help="Path to write the fixed version of the file")
    args = parser.parse_args()

    try:
        urt = UpxRecoveryTool(args.input, args.output)
        urt.fix()
    
    except UnsupportedFileError as why:
        print(f"[-] Unsupported file '{args.input}': {why}")

    except NonUpxError:
        print(f"[-] {args.input} doesn't seem to be an UPX file")
