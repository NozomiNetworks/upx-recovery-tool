import "elf"

rule upx_entry_point {

	meta:
		author = "Nozomi Networks Labs"
		description = "Rule to detect if an ELF file is packed with UPX based on its entry point."
		
	strings:
		$ep_x86 = {50 E8 [4] EB 0E 5A 58 59 97 60 8A 54 24 20 E9 [4] 60}

	condition:
		uint32(0)==0x464c457f // ELF header
        and for any of ($ep_*):($ at elf.entry_point)
}

rule upx_init_code_not_ep {

	meta:
		author = "Nozomi Networks Labs"
		description = "Rule to detect if an ELF file contains UPX code that should be at the entry point but its located anywhere else."
		
	strings:
		$ep_x86 = {50 E8 [4] EB 0E 5A 58 59 97 60 8A 54 24 20 E9 [4] 60}

	condition:
		uint32(0)==0x464c457f // ELF header
        and any of ($ep_*)
        and for 0 of ($ep_*):($ at elf.entry_point)
}

