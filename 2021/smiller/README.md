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
