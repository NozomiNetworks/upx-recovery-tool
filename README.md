# upx-recovery-tool

upx-recovery-tool is a script that aims to repair the most common modifications done by malware creators to ELF UPX-compressed 
files done to prevent their automatic unpacking with a standard UPX tool.

## Implemented UPX fixes / Features

This tool detects and repairs the following common modifications:
- `l_magic` field of the `l_info` structure (`UPX!` magic value)
- `p_filesize` and `p_blocksize` fields of the `p_info` structure
- Overlay bytes

### Dependencies

The script requires the following libraries listed on `requirements.txt`:

- [`lief`](https://lief-project.github.io)
- [`python-magic`](https://pypi.org/project/python-magic/)
- [`yara-python`](https://github.com/VirusTotal/yara-python)
