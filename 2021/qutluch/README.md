# Oversized overlay

Source: https://twitter.com/Qutluch/status/1477678918291398668
Description: Nice way to check if the overlay of a PE file is large relative to
the size of the file and has a high entropy.

```yara
import "pe"
import "math"

rule MAL_OVERYLAY_OVERSIZED_00
{
    meta:
        OneHundredDaysOfYARA    = "1"
        author                  = "Conor Quigley <schrodinger@konundrum.org>"
        description             = "PE files where overlay > 95% of the filesize."
        reference               = "https://aaqeel01.wordpress.com/2021/09/21/dissecting-binaries-from-unknown-threat-actor/"
        license                 = "BSD-2-Clause"
        created                 = "2022-01-01"
        version                 = "1.0"
        hash1                   = "ebb22358cc0ce4bc40c76e1c02df8d304fd0b27e9793c7cbcc02f23b4e3c1c89"

    condition:
        uint16(0) == 0x5A4D
        and (uint32(uint32(0x3C)) == 0x00004550)
        and pe.characteristics & pe.DLL
        and ((pe.overlay.size * 100) \ filesize)  > 95
        and math.entropy(pe.overlay.offset, filesize) >= 7
}
```

# Dumping PE section 512 byte sector hashes

Source: https://twitter.com/Qutluch/status/1477685333521317890
Description: A python script to dump certain information from PE sections in a
hash form.

TODO: Conor, would you be willing to put your script in this repo? Probably
don't want to put it directly in this file.

# .NET fun

Source: https://twitter.com/Qutluch/status/1478038426159046657
Description: Hunting for .NET typelib values. This is one way to do it if
you're not able to use the dotnet YARA module. ;)

```yara
import "pe"

rule pe_dotnet_typelib
{

    meta:
        OneHundredDaysOfYARA    = "3"
        author                  = "Conor Quigley <schrodinger@konundrum.org>"
        description             = "Hunting for .NET typelib GUIDs"
        reference               = "https://www.virusbulletin.com/virusbulletin/2015/06/using-net-guids-help-hunt-malware/"
        license                 = "BSD-2-Clause"
        created                 = "2022-01-03"
        version                 = "1.0"

    strings:
        $typelib_00 = "e4b18d56-1feb-4f65-a048-3689cb5727cc" ascii
        $typelib_01 = "38930c14-13a7-45bc-8c93-51c7e87d93bb" ascii

    condition:

        pe.data_directories[pe.IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].virtual_address != 0

        and
        uint32be(
            pe.rva_to_offset(
                uint32(
                    pe.rva_to_offset(pe.data_directories[pe.IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].virtual_address) + 8
                )
            ) // Start of Meta Data Header
        ) == 0x42534a42

        and for any of ($typelib*) :
        ( $ in
            (
                pe.rva_to_offset(
                    uint32(
                        pe.rva_to_offset(pe.data_directories[pe.IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].virtual_address) + 8
                    )
                )
                ..
                pe.rva_to_offset(
                    uint32(
                        pe.rva_to_offset(pe.data_directories[pe.IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].virtual_address) + 8
                    )
                    +
                    uint32(
                        pe.rva_to_offset(pe.data_directories[pe.IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].virtual_address) + 12
                    )
                )
            )
        )
}
```
