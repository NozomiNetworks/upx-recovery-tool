# upx-recovery-tool

upx-recovery-tool is a script that aims to repair the most common modifications done by malware creators to ELF UPX
compressed files to prevent their automatic extraction with UPX.

## Implemented UPX fixes / Features

This tool detects and repairs these common modifications to:
- `UPX!` magic value
- `p_info` structure values

### Dependencies

The script requires the next libraries:

- [`elftools`](https://github.com/eliben/pyelftools)
