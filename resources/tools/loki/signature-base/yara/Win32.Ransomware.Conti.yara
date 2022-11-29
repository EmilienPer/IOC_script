rule Win32_Ransomware_Conti : tc_detection malicious
{
    meta:

        author              = "ReversingLabs"

        source              = "ReversingLabs"
        status              = "RELEASED"
        sharing             = "TLP:WHITE"
        category            = "MALWARE"
        malware             = "CONTI"
        description         = "Yara rule that detects Conti ransomware."

        tc_detection_type   = "Ransomware"
        tc_detection_name   = "Conti"
        tc_detection_factor = 5

    strings:

        $find_files = {
            55 8B EC 83 E4 ?? 81 EC ?? ?? ?? ?? 53 56 57 8B D9 53 FF 15 ?? ?? ?? ?? 89 44 24 ?? 
            8D 0C 45 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B F8 89 7C 24 ?? 85 FF 0F 84 ?? ?? ?? ?? 8B 44 
            24 ?? B9 ?? ?? ?? ?? 53 BE ?? ?? ?? ?? 57 66 83 7C 43 ?? ?? 0F 45 F1 FF 15 ?? ?? ?? 
            ?? 56 57 FF 15 ?? ?? ?? ?? 8B CB E8 ?? ?? ?? ?? 8D 44 24 ?? 50 57 FF 15 ?? ?? ?? ?? 
            8B F8 83 FF ?? 0F 84 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 44 24 ?? 50 FF 15 ?? ?? ?? ?? 85 
            C0 0F 84 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 44 24 ?? 50 FF 15 ?? ?? ?? ?? 85 C0 0F 84 ?? 
            ?? ?? ?? F6 44 24 ?? ?? 74 ?? 8D 4C 24 ?? E8 ?? ?? ?? ?? 85 C0 74 ?? 8D 54 24 ?? 8B 
            CB E8 ?? ?? ?? ?? 8B F0 85 F6 74 ?? 8B CE E8 ?? ?? ?? ?? 8B CE E8 ?? ?? ?? ?? EB ?? 
            8D 4C 24 ?? E8 ?? ?? ?? ?? 85 C0 74 ?? 8D 54 24 ?? 8B CB E8 ?? ?? ?? ?? 8B F0 85 F6 
            74 ?? 68 ?? ?? ?? ?? 6A ?? FF 15 ?? ?? ?? ?? 85 C0 74 ?? 6A ?? 5A 8B C8 C6 01 ?? 41 
            83 EA ?? 75 ?? 83 48 ?? ?? 50 89 70 ?? A1 ?? ?? ?? ?? 52 6A ?? FF 70 ?? FF 15 ?? ?? 
            ?? ?? 8D 44 24 ?? 50 57 FF 15 ?? ?? ?? ?? 85 C0 0F 85 ?? ?? ?? ?? 8B 4C 24 ?? E8 ?? 
            ?? ?? ?? 83 FF ?? 74 ?? 57 FF 15 ?? ?? ?? ?? 5F 5E 5B 8B E5 5D C3 
        }
        
        $encrypt_files_p1 = {
            55 8B EC 81 EC ?? ?? ?? ?? 53 56 57 BB ?? ?? ?? ?? 8B F9 53 57 FF 15 ?? ?? ?? ?? 85 
            C0 0F 85 ?? ?? ?? ?? BE ?? ?? ?? ?? 56 57 FF 15 ?? ?? ?? ?? 85 C0 0F 85 ?? ?? ?? ?? 
            A1 ?? ?? ?? ?? 83 F8 ?? 75 ?? 89 75 ?? 33 F6 C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? 
            ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? 89 5D ?? FF 74 B5 ?? 57 FF 15 ?? ?? ?? 
            ?? 85 C0 75 ?? 46 83 FE ?? 7C ?? 33 C0 40 EB ?? 85 C0 75 ?? 8B 35 ?? ?? ?? ?? BB ?? 
            ?? ?? ?? B9 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? C6 00 ?? 40 83 E9 ?? 75 ?? 53 56 FF 15 ?? 
            ?? ?? ?? 85 C0 74 ?? 2B C6 D1 F8 74 ?? 85 C0 78 ?? 40 50 56 8D 85 ?? ?? ?? ?? 50 FF 
            15 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 50 57 FF 15 ?? ?? ?? ?? 85 C0 75 ?? 53 56 FF 15 ?? 
            ?? ?? ?? 8B F0 85 F6 74 ?? 83 C6 ?? EB ?? 33 C0 5F 5E 5B C9 C3 
        }

        $encrypt_files_p2 = {
            55 8B EC 83 EC ?? 53 56 57 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 33 DB 53 FF 15 ?? ?? 
            ?? ?? 8B F8 85 FF 75 ?? 53 FF 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A ?? 5E 56 68 ?? ?? ?? 
            ?? 53 8D 45 ?? 50 FF 15 ?? ?? ?? ?? 85 C0 75 ?? 68 ?? ?? ?? ?? 56 68 ?? ?? ?? ?? 53 
            8D 45 ?? 50 FF 15 ?? ?? ?? ?? 85 C0 75 ?? 68 ?? ?? ?? ?? 56 68 ?? ?? ?? ?? 53 8D 45 
            ?? 50 FF 15 ?? ?? ?? ?? 85 C0 75 ?? 68 ?? ?? ?? ?? 56 68 ?? ?? ?? ?? 53 8D 45 ?? 50 
            FF 15 ?? ?? ?? ?? 85 C0 75 ?? 6A ?? FF 15 ?? ?? ?? ?? 8D 45 ?? 50 53 53 68 ?? ?? ?? 
            ?? 68 ?? ?? ?? ?? FF 75 ?? FF 15 ?? ?? ?? ?? 85 C0 75 ?? 6A ?? FF 15 ?? ?? ?? ?? 6A 
            ?? 8D 45 ?? 50 8D 45 ?? 50 8D 45 ?? 50 8B 45 ?? FF 70 ?? FF 15 ?? ?? ?? ?? 85 C0 75 
            ?? 6A ?? FF 15 ?? ?? ?? ?? 81 7D ?? ?? ?? ?? ?? 0F 84 ?? ?? ?? ?? FF 75 ?? 8B 4D ?? 
            8B D7 FF 75 ?? E8 ?? ?? ?? ?? 59 59 85 C0 74 ?? 8B 45 ?? FF 70 ?? FF 15 ?? ?? ?? ?? 
            8B 45 ?? B9 ?? ?? ?? ?? 83 48 ?? ?? 8B 45 ?? 8B 58 ?? E8 ?? ?? ?? ?? 8B F0 85 F6 74 
            ?? 53 56 FF 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? 56 FF 15 ?? ?? ?? ?? 56 53 FF 15 ?? ?? ?? 
            ?? 8B CE E8 ?? ?? ?? ?? 8B 4D ?? E8 ?? ?? ?? ?? 8B 4D ?? 8B 49 ?? E8 ?? ?? ?? ?? FF 
            75 ?? FF 15 ?? ?? ?? ?? E9 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A ?? 57 FF 15 ?? ?? ?? ?? FF 
            75 ?? FF 15 ?? ?? ?? ?? 6A ?? FF 15 ?? ?? ?? ?? 5F 5E 33 C0 5B C9 C2
        }
        
    condition:
        uint16(0) == 0x5A4D and
        (
            $find_files
        ) and
        (
            all of ($encrypt_files_p*)
        )
}