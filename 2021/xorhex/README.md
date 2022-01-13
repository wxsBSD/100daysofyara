# Sweet usage of the time.now() module

Source: https://twitter.com/xorhex/status/1477363401424842752
Description: Look for certificates that have expired already, for a constantly
evolving definition of expired. Sweet use of time.now()!
Blog: https://blog.xorhex.com/blog/onehundreddiscontiguousdaysofyara-day1/

```yara
import "pe"
import "time"

rule cert_expired {
    meta:
        author = "xorhex"
        description = "Find PE files whose code signing certificate is expired as of current date"
        HundredDaysOfYara = "Day 1"

    condition:
        for any s in (0..pe.number_of_signatures) : (
            pe.signatures[s].not_after < time.now()
        )
}
```

# PE files compiled after the signing certificate expired

Source: https://twitter.com/xorhex/status/1477696409877028864
Description: Find PE files compiled after the signing certificate has expired.
Blog: https://blog.xorhex.com/blog/onehundreddiscontiguousdaysofyara-day2/

```yara
import "pe"

rule pe_created_after_cert_expired {
    meta:
        author = "xorhex"
        description = "Find PE files that were compiled (assuming the timestamp was not modified) after their code signing certificate expired"
        HundredDaysOfYara = "Day 2"

    condition:
        for any s in pe.signatures: (
            pe.timestamp > s.not_after
        )
}
```

# MZ and PE fields wiped? No worries!

Source: https://twitter.com/xorhex/status/1478076841902628866
Description: Finding PE files with no MZ and PE field values based upon machine
type in the NT header.
Blog: https://blog.xorhex.com/blog/onehundreddiscontiguousdaysofyara-day3/

```yara
rule no_mz_sig__no_pe_sig__but_could_be_a_pe_file {

  meta:
    author = "xorhex"
    description = "Identifies PE files whose MZ sig and PE sig are wiped by inspecting the machine type value at the expected offset"
    warning = "Further tweaking maybe required to lessen the FP rate"
    HundredDaysOfYARA = "Day 3"

  condition:
      uint16be(0) != 0x4d5a
    and
      uint32(uint32(0x3C)) != 0x00004550
    and
      (
          uint16(uint32(0x3c) + 4 ) == 0x014c
        or
          uint16(uint32(0x3c) + 4) == 0x8664
      )
}
```
