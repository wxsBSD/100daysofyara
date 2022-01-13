Source: https://twitter.com/0xDroogy/status/1478113042667823105
Description: A collection of rules for a bunch of things.

```yara
import "pe"
import "hash"
import "math"
import "time"

rule rtfDocumentWithObject {
    meta:
        description = " Identify RTF files with embedded objects "
        author = "Droogy"
        DaysOfYARA = "7/100"
    
    strings:
        $s1 = "\\object" nocase ascii wide
    
    condition:
        uint32(0) == 0x74725c7b     /* {\rt */
        and $s1
}

rule embeddedDocfile {
    meta:
        description = " look for embedded microsoft docfile header "
        author = "Droogy"
        DaysOfYARA = "7/100"

    strings:
        $s1 = { D0 CF 11 E0 }

    condition:
        $s1 in (100..filesize)

}

rule Amadey_Trojan {
    meta:
        description = " Identify Amadey Trojan using a binary trait (courtesy of binlex) and a few strings"
        author = "Droogy"
        DaysOfYARA = "6/100"

    strings:
        $trait = {8b 8d ?? ff ff ff 42 8b c1 81 fa 00 10 ?? ?? 72 14}
        $s1 = "PPPPP" nocase wide ascii
        $s2 = "Y_^[" nocase wide ascii
        $s3 = "8\\u0" nocase wide ascii
    
    condition:
        uint16(0) == 0x5a4d and
        $trait and 2 of ($s*)
}

rule unreliableTimestamp {
    meta:
        description = " Parse .debug section in PE files and look for evidence that a PE file may have unreliable timestamps"
        author = "Droogy"
        DaysOfYARA = "5/100"

    condition:
        pe.is_pe
        and
        pe.data_directories[pe.IMAGE_DIRECTORY_ENTRY_DEBUG].virtual_address != 0
        and
        pe.timestamp > time.now()
}

rule backdooredChromeMiner {
    meta:
        description = " Look for strings indicative of a backdoored version of Chrome with a coin miners"
        author = "Droogy"
        DaysOfYARA = "4/100"

    strings:
        $s1 = "chrome.exe" ascii wide nocase
        $c1 = "xmrig" ascii wide nocase
        $c2 = "coinhive" ascii wide nocase
        $c3 = "hashvault.pro" ascii wide nocase

    condition:
        $s1 and 1 of ($c*)
}

rule packedTextSection {
    meta:
        description = " Look for high-entropy .text sections within PE files "
        author = "Droogy"
        DaysOfYARA = "3/100"

    condition:
        for any section in pe.sections: (
            section.name == ".text"    // .text section contains executable code likely to be packed
        )
        and
        for any section in pe.sections: (
            math.entropy(
                section.raw_data_offset, 
                section.raw_data_size
            ) >= 7    // entropy goes from 0-8, generally 6.5 and above is high
        )
}

rule isDotNet {
    meta:
        description = " Detect if file is .NET assembly "
        author = "Droogy"
        DaysOfYARA = "2/100"

    condition:
        pe.number_of_sections >= 3
        and
        pe.imports(/mscoree.dll/i, /_CorExeMain/ ) == 1
}

rule solitaire {
    meta:
        description = " Suspicious file pulled from malshare named Solitaire.exe - has no hits on VT"
        author = "Droogy"
        DaysOfYARA = "1/100"
    
    condition:
        uint16(0) == 0x5a4d
        and
        pe.number_of_sections == 7 
        and
        for any var_section in pe.sections: (
            var_section.name == "_RDATA"    // clue this is a cpp file compiled in VS
        )
}
```
