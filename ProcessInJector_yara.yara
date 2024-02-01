rule ProcessInjected {
    
    meta: 
        last_updated = "2024-01-31"
        author = "Fortune Sam Okon"
        description = "A sample Yara rule for PMAT course final"

    strings:
        // Fill out identifying strings and other criteria
        $string1 = "@C:\Users\Public\werflt.exe"
        $string2 = "CreateRemoteThread"
        $string3 = "@C:\Windows\SysWOW64\WerFault.exe"
        $PE_magic_byte = "MZ"
        $sus_hex_string = {8E}

    condition:
        // Fill out the conditions that must be met to identify the binary
        $PE_magic_byte at 0 and
        ($string1 and $string2 and $string3) or 
        $sus_hex_string
}
