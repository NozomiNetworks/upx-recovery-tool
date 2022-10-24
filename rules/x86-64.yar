import "elf"

rule upx_entry_point {

	meta:
		author = "Nozomi Networks Labs"
		description = "Rule to detect if an ELF file is packed with UPX based on its entry point."
		
	strings:
		$ep_x64_0 = {50 52 e8 [4] 55 53 51 52 48 01 fe 56 48 89 fe 48 89 d7 31 db 31 c9 48 83 cd ff e8}
		$ep_x64_1 = {50 52 e8 [4] 55 53 51 52 48 01 fe 56 41 80 f8 0e 0f [5] 55 48 89 e5 44 8b 09}

	condition:
		uint32(0)==0x464c457f // ELF header
        and for any of ($ep_*):($ at elf.entry_point)
}

rule upx_init_code_not_ep {

	meta:
		author = "Nozomi Networks Labs"
		description = "Rule to detect if an ELF file contains UPX code that should be at the entry point but its located anywhere else."
		
	strings:
		$ep_x64_0 = {50 52 e8 [4] 55 53 51 52 48 01 fe 56 48 89 fe 48 89 d7 31 db 31 c9 48 83 cd ff e8}
		$ep_x64_1 = {50 52 e8 [4] 55 53 51 52 48 01 fe 56 41 80 f8 0e 0f [5] 55 48 89 e5 44 8b 09}

	condition:
		uint32(0)==0x464c457f // ELF header
        and any of ($ep_*)
        and for 0 of ($ep_*):($ at elf.entry_point)
}
