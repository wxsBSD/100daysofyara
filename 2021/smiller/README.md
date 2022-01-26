# Detecting PE files with OpenSSH private keys in them

Source: https://twitter.com/stvemillertime/status/1478033256763346949
Description: Detecting PE files with OpenSSH keys in them, which was inspired
by looking at TRITON malware.

```yara
rule adversary_methods_pe_with_openssh_key {
  meta:
    author="smiller"
    description="Looking for PE files with default OpenSSH private key strings"
  strings:
    $a1= "[-----BEGIN OPENSSH PRIVATE KEY-----"
    $a2= {0A2D2D2D2D2D454E44204F50454E5353482050524956415445204B45592D2D2D2D2D0A257373682D}
  condition:
    uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and all of them
}
```

Source: https://twitter.com/stvemillertime/status/1483914381788336128

```import "pe"
rule SwearEngine_Fuck: TTP { strings: $a = /([Ff]uck|FUCK)/ condition: pe.number_of_signatures == 0 and $a }
```


Source: https://twitter.com/stvemillertime/status/1486354826787176450

```import "pe"
import "console"
rule CreatePEPolyObject {
    strings:
        $a = "CreatePEPolyObject" xor
        $b = "CreatePEPolyObject" nocase ascii wide
        $c = "CreatePEPolyObject" base64 base64wide
    condition:
        any of them
}
rule Export_CreatePEPolyObject {
    condition:
        pe.exports("CreatePEPolyObject")
}
rule Export_CreatePEPolyObject_Loop {
    condition:
        for any func in pe.export_details:
            (
                func.name contains "CreatePEPolyObject"
            )
}
rule PE_Export_Func_Name {
    meta:
        note = "Must have console module via yara-4.2.0-rc1+"
    condition:
        uint16(0) == 0x5A4D and
        for any func in pe.export_details:
            (
                console.log("Export Name: ", func.name)
            )
}
//CEO-PC >> ~/yara-4.2.0-rc1 % yara -r test-export.yar ~/vx/ | sort | grep -e 'Export: ' | sort | uniq -c  
```