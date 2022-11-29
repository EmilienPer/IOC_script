rule Win32_Ransomware_Zeppelin : tc_detection malicious
{
    meta:

        author              = "ReversingLabs"

        source              = "ReversingLabs"
        status              = "RELEASED"
        sharing             = "TLP:WHITE"
        category            = "MALWARE"
        malware             = "ZEPPELIN"
        description         = "Yara rule that detects Zeppelin ransomware."

        tc_detection_type   = "Ransomware"
        tc_detection_name   = "Zeppelin"
        tc_detection_factor = 5

    strings:

        $search_files_p1 = {                        
            55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 8D 55 ?? 8B 45 ?? E8 ?? ?? ?? ?? 8D 85 ?? ?? ?? 
            ?? B9 ?? ?? ?? ?? 8B 55 ?? E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? BA ?? 
            ?? ?? ?? E8 ?? ?? ?? ?? 85 C0 0F 85 ?? ?? ?? ?? 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 
            89 20 8D 45 ?? 8B 8D ?? ?? ?? ?? 8B 55 ?? E8 ?? ?? ?? ?? 8D 45 ?? 50 8B 45 ?? E8 ?? 
            ?? ?? ?? 8B D8 8B 45 ?? E8 ?? ?? ?? ?? 2B D8 43 53 8B 45 ?? E8 ?? ?? ?? ?? 8B D0 42 
            8B 45 ?? 59 E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? FF 30 FF 75 ?? 68 ?? ?? ?? ?? 8B 85 ?? 
            ?? ?? ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 8B 00 E8 ?? ?? ?? ?? 83 F8 
            ?? 7C ?? E8 ?? ?? ?? ?? E9 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? E8 ?? ?? ?? ?? 85 C0 0F 84 
            ?? ?? ?? ?? 33 C0 5A 59 59 64 89 10 68 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? E8 ?? ?? ?? ?? 
            C3 
        }

        $search_files_p2 = {                        
            8D 85 ?? ?? ?? ?? B9 ?? ?? ?? ?? 8B 55 ?? E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 8D 8D ?? 
            ?? ?? ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 85 C0 0F 85 ?? ?? ?? ?? 33 C0 55 68 ?? ?? ?? 
            ?? 64 FF 30 64 89 20 F6 85 ?? ?? ?? ?? ?? 74 ?? 8B 85 ?? ?? ?? ?? BA ?? ?? ?? ?? E8 
            ?? ?? ?? ?? 74 ?? 8B 85 ?? ?? ?? ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 74 ?? 8B 45 ?? 50 
            8D 85 ?? ?? ?? ?? 8B 8D ?? ?? ?? ?? 8B 55 ?? E8 ?? ?? ?? ?? 8B 95 ?? ?? ?? ?? 8B 8D 
            ?? ?? ?? ?? 8B 45 ?? E8 ?? ?? ?? ?? 59 8D 85 ?? ?? ?? ?? E8 ?? ?? ?? ?? 85 C0 74 ?? 
            33 C0 5A 59 59 64 89 10 68 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? E8 ?? ?? ?? ?? C3 E9 ?? ?? 
            ?? ?? EB ?? 33 C0 5A 59 59 64 89 10 68 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? BA ?? ?? ?? ?? 
            E8 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 ?? BA ?? ?? 
            ?? ?? E8 ?? ?? ?? ?? C3 E9 ?? ?? ?? ?? EB ?? 5B 8B E5 5D C3 
        }

        $kill_processes = {                        
            55 8B EC 33 C9 51 51 51 51 51 51 51 51 53 56 57 84 D2 74 ?? 83 C4 ?? E8 ?? ?? ?? ?? 
            88 55 ?? 89 45 ?? 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 33 D2 55 68 ?? ?? ?? ?? 
            64 FF 32 64 89 22 8D 55 ?? A1 ?? ?? ?? ?? 8B 00 E8 ?? ?? ?? ?? B2 ?? A1 ?? ?? ?? ?? 
            E8 ?? ?? ?? ?? 8B D8 8B 45 ?? 89 58 ?? 8B C3 B2 ?? E8 ?? ?? ?? ?? 8B 45 ?? 8B 40 ?? 
            C6 40 ?? ?? 8D 45 ?? E8 ?? ?? ?? ?? 8B 45 ?? 85 C0 74 ?? 83 E8 ?? 8B 00 8B F0 85 F6 
            7E ?? BB ?? ?? ?? ?? 8D 45 ?? 8B 55 ?? 0F B6 54 1A ?? E8 ?? ?? ?? ?? 8B 45 ?? 50 8D 
            55 ?? B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 55 ?? 58 E8 ?? ?? ?? ?? 75 ?? 8D 55 ?? 8B 45 
            ?? E8 ?? ?? ?? ?? 8B 55 ?? 8B 45 ?? 8B 40 ?? 8B 08 FF 51 ?? 8D 45 ?? E8 ?? ?? ?? ?? 
            EB ?? 8D 45 ?? 8B 55 ?? 0F B6 54 1A ?? E8 ?? ?? ?? ?? 8B 55 ?? 8D 45 ?? E8 ?? ?? ?? 
            ?? 43 4E 75 ?? 33 C0 5A 59 59 64 89 10 EB ?? E9 ?? ?? ?? ?? E8 ?? ?? ?? ?? B1 ?? 33 
            D2 8B 45 ?? E8 ?? ?? ?? ?? 33 C0 5A 59 59 64 89 10 68 ?? ?? ?? ?? 8D 45 ?? BA ?? ?? 
            ?? ?? E8 ?? ?? ?? ?? 8D 45 ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? C3 E9 ?? ?? ?? ?? EB ?? 
            8B 45 ?? 80 7D ?? ?? 74 ?? E8 ?? ?? ?? ?? 64 8F 05 ?? ?? ?? ?? 83 C4 ?? 8B 45 ?? 5F 
            5E 5B 8B E5 5D C3 
        }

        $enum_shares = {                        
            55 8B EC B9 ?? ?? ?? ?? 6A ?? 6A ?? 49 75 ?? 51 53 56 57 89 45 ?? 8B 45 ?? E8 ?? ?? 
            ?? ?? 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 
            89 20 B2 ?? A1 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 45 ?? 8D 55 ?? B8 ?? ?? ?? ?? E8 ?? ?? 
            ?? ?? 8B 55 ?? 8B 45 ?? E8 ?? ?? ?? ?? 8B 55 ?? 8B 45 ?? E8 ?? ?? ?? ?? 8D 4D ?? 33 
            D2 8B 45 ?? E8 ?? ?? ?? ?? 8B 45 ?? E8 ?? ?? ?? ?? B2 ?? A1 ?? ?? ?? ?? E8 ?? ?? ?? 
            ?? 89 45 ?? B2 ?? 8B 45 ?? E8 ?? ?? ?? ?? B2 ?? 8B 45 ?? E8 ?? ?? ?? ?? 8B 55 ?? 8B 
            45 ?? E8 ?? ?? ?? ?? B2 ?? A1 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 45 ?? 8D 55 ?? B8 ?? ?? 
            ?? ?? E8 ?? ?? ?? ?? 8B 55 ?? 8B 45 ?? E8 ?? ?? ?? ?? 8B 45 ?? 8B 10 FF 52 ?? 48 85 
            C0 0F 8C ?? ?? ?? ?? 40 89 45 ?? C7 45 ?? ?? ?? ?? ?? 8D 4D ?? 8B 55 ?? 8B 45 ?? 8B 
            18 FF 53 ?? 8B 55 ?? 8B 45 ?? E8 ?? ?? ?? ?? 84 C0 74 ?? 33 C0 55 68 ?? ?? ?? ?? 64 
            FF 30 64 89 20 FF 75 ?? 68 ?? ?? ?? ?? 8D 4D ?? 33 D2 8B 45 ?? E8 ?? ?? ?? ?? 8B 45 
            ?? 8D 55 ?? E8 ?? ?? ?? ?? FF 75 ?? 8D 45 ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 55 ?? 
            8D 45 ?? E8 ?? ?? ?? ?? 8B 55 ?? A1 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 5A 59 59 64 89 
            10 EB ?? E9 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 45 ?? E8 ?? ?? ?? ?? 84 C0 75 ?? FF 45 ?? 
            FF 4D ?? 0F 85 ?? ?? ?? ?? 8B 45 ?? E8 ?? ?? ?? ?? 8B 45 ?? E8 ?? ?? ?? ?? 33 C0 5A 
            59 59 64 89 10 EB ?? E9 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 5A 59 59 64 89 10 68 ?? ?? 
            ?? ?? 8D 45 ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 ?? E8 ?? ?? ?? ?? 8D 45 ?? BA ?? 
            ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? C3 E9 ?? ?? ?? ?? EB 
            ?? 5F 5E 5B 8B E5 5D C3 
        }

        $encrypt_files = {                        
            55 8B EC 83 C4 ?? 53 56 33 DB 89 5D ?? 84 D2 74 ?? 83 C4 ?? E8 ?? ?? ?? ?? 8B D9 88 
            55 ?? 8B F0 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 33 D2 8B C6 E8 ?? ?? ?? ?? E8 
            ?? ?? ?? ?? 88 5E ?? 88 5E ?? 56 6A ?? 8D 46 ?? 50 B9 ?? ?? ?? ?? 33 D2 33 C0 E8 ?? 
            ?? ?? ?? 8B D8 89 5E ?? 85 DB 75 ?? E8 ?? ?? ?? ?? 8D 55 ?? E8 ?? ?? ?? ?? 8B 45 ?? 
            89 45 ?? C6 45 ?? ?? 8D 45 ?? 50 6A ?? 8B 0D ?? ?? ?? ?? B2 ?? A1 ?? ?? ?? ?? E8 ?? 
            ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 5A 59 59 64 89 10 68 ?? ?? ?? ?? 8D 45 ?? E8 ?? ?? ?? 
            ?? C3 
        }

    condition:
        uint16(0) == 0x5A4D and 
        (
            $kill_processes
        ) and 
        (
            $enum_shares
        ) and 
        (
            all of ($search_files_p*)
        ) and 
        (
            $encrypt_files
        )
}