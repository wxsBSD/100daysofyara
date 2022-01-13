Source: https://twitter.com/secman_pl/status/1478157595248627717
Description: PE inception!

```yara
rule hunt_PE_embedded {
  meta:
    
        OneHundredDaysOfYARA  = "1/100"
        author                = "Bartek Jerzman"
        description           = "Hunting for PE files embedded in other PE files"
        reference             = "https://yara.readthedocs.io/en/stable/writingrules.html#iterating-over-string-occurrences"
    vt_search          = "tag:contains-pe and type:peexe"
  strings:

        $mz =  { 4D 5A }
   
  condition:
          // match 2 occurances of PE header
        for 2 i in (1..#mz) : ( uint32(@mz[i] + uint32(@mz[i] + 0x3c)) == 0x00004550 and 
          // first occurance at offset 0
        @mz[1] == 0) 
}
```
