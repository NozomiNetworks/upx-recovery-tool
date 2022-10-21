import "elf"

rule upx_entry_point {

	meta:
		author = "Nozomi Networks Lab"
		description = "Rule to detect if an ELF file is packed with UPX based on its entry point."
		
	strings:
		$ep_ppc_0 = {48 00 ?? ?? 7c 00 29 ec 7d a8 02 a6 28 07 00 02 40 82 00 e4 90 a6 00 00 }
		$ep_ppc_1 = {48 00 ?? ?? 28 07 00 0e 40 82 0a 4c 94 21 ff e8 7c 08 02 a6 7c c9 33 78 81 06 00 00 7c a7 2b 78}

	condition:
		uint32(0)==0x464c457f // ELF header
        and for any of ($ep_*):($ at elf.entry_point)
}

rule upx_init_code_not_ep {

	meta:
		author = "Nozomi Networks Lab"
		description = "Rule to detect if an ELF file contains UPX code that should be at the entry point but its located anywhere else."
		
	strings:
		$ep_ppc_0 = {48 00 ?? ?? 7c 00 29 ec 7d a8 02 a6 28 07 00 02 40 82 00 e4 90 a6 00 00 }
		$ep_ppc_1 = {48 00 ?? ?? 28 07 00 0e 40 82 0a 4c 94 21 ff e8 7c 08 02 a6 7c c9 33 78 81 06 00 00 7c a7 2b 78}

	condition:
		uint32(0)==0x464c457f // ELF header
        and any of ($ep_*)
        and for 0 of ($ep_*):($ at elf.entry_point)
}
