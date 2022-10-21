import "elf"

rule upx_entry_point {

	meta:
		author = "Nozomi Networks Lab"
		description = "Rule to detect if an ELF file is packed with UPX based on its entry point."
		
	strings:
		$ep_mips_be_1 = {04 11 [2] 27 fe 00 00 27 bd ff fc af bf 00 00 00 a4 28 20 ac e6 00 00 3c 0d 80 00 01 a0 48 21 24 0b 00 01 04 11}
		$ep_mips_be_2 = {04 11 [2] 27 f7 00 00 90 99 00 00 24 01 fa 00 90 98 00 01 33 22 00 07 00 19 c8 c2 03 21 08 04}
		$ep_mips_le_1 = {?? ?? 11 04 00 00 fe 27 fc ff bd 27 00 00 bf af 20 28 a4 00 00 00 e6 ac 00 80 0d 3c 21 48 a0 01 01 00 0b 24 [2] 11 04}
		$ep_mips_le_2 = {?? ?? 11 04 00 00 f7 27 00 00 99 90 00 fa 01 24 01 00 98 90 07 00 22 33 c2 c8 19 00 04 08 21 03}

	condition:
		uint32(0)==0x464c457f // ELF header
        and for any of ($ep_*):($ at elf.entry_point)
}

rule upx_init_code_not_ep {

	meta:
		author = "Nozomi Networks Lab"
		description = "Rule to detect if an ELF file contains UPX code that should be at the entry point but its located anywhere else."
		
	strings:
		$ep_mips_be_1 = {04 11 [2] 27 fe 00 00 27 bd ff fc af bf 00 00 00 a4 28 20 ac e6 00 00 3c 0d 80 00 01 a0 48 21 24 0b 00 01 04 11}
		$ep_mips_be_2 = {04 11 [2] 27 f7 00 00 90 99 00 00 24 01 fa 00 90 98 00 01 33 22 00 07 00 19 c8 c2 03 21 08 04}
		$ep_mips_le_1 = {?? ?? 11 04 00 00 fe 27 fc ff bd 27 00 00 bf af 20 28 a4 00 00 00 e6 ac 00 80 0d 3c 21 48 a0 01 01 00 0b 24 [2] 11 04}
		$ep_mips_le_2 = {?? ?? 11 04 00 00 f7 27 00 00 99 90 00 fa 01 24 01 00 98 90 07 00 22 33 c2 c8 19 00 04 08 21 03}

	condition:
		uint32(0)==0x464c457f // ELF header
        and any of ($ep_*)
        and for 0 of ($ep_*):($ at elf.entry_point)
}
