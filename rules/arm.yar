import "elf"

rule upx_entry_point {

	meta:
		author = "Nozomi Networks Lab"
		description = "Rule to detect if an ELF file is packed with UPX based on its entry point."
		
	strings:
		$ep_arm_0 = {1c c0 4f e2 06 4c 9c e8 02 00 a0 e1 0c b0 8b e0 0c a0 8a e0 00 30 9b e5 01 90 4c e0 01 20 a0 e1}
		$ep_arm_1 = {18 d0 4d e2 ?? 02 00 eb 00 c0 dd e5 0e 00 5c e3 ?? 02 00 1a 0c 48 2d e9 00 b0 d0 e5 06 cc a0 e3}
		$ep_arm_2 = {00 18 d0 4d e2 9c 00 00 eb 00 10 81 e0 3e 40 2d e9 00 50 e0 e3 02 41 a0 e3 19 00 00 ea 1a 00 bd}

	condition:
		uint32(0)==0x464c457f // ELF header
        and for any of ($ep_*):($ at elf.entry_point)
}

rule upx_init_code_not_ep {

	meta:
		author = "Nozomi Networks Lab"
		description = "Rule to detect if an ELF file contains UPX code that should be at the entry point but its located anywhere else."
		
	strings:
		$ep_arm_0 = {1c c0 4f e2 06 4c 9c e8 02 00 a0 e1 0c b0 8b e0 0c a0 8a e0 00 30 9b e5 01 90 4c e0 01 20 a0 e1}
		$ep_arm_1 = {18 d0 4d e2 ?? 02 00 eb 00 c0 dd e5 0e 00 5c e3 ?? 02 00 1a 0c 48 2d e9 00 b0 d0 e5 06 cc a0 e3}
		$ep_arm_2 = {00 18 d0 4d e2 9c 00 00 eb 00 10 81 e0 3e 40 2d e9 00 50 e0 e3 02 41 a0 e3 19 00 00 ea 1a 00 bd}


	condition:
		uint32(0)==0x464c457f // ELF header
        and any of ($ep_*)
        and for 0 of ($ep_*):($ at elf.entry_point)
}
